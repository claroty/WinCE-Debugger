import re
import sys
import angr
import time
import string
import asyncio
import logging
import binascii
from construct import Int32ul

from textual import work
from textual.app import *
from textual.widgets import *
from rich.text import Text
from rich.style import Style
from rich.jupyter import JupyterMixin
from rich.segment import Segment, Segments

from widgets.hex_view import *
from widgets.breakpoints import *
from widgets.disasm_view import *
from widgets.thread_context import *
from widgets.input_widgets import *

from utils import *
from debugger_protocol_manager import EDMProtocolManager, EXCEPTION_EVENT_TYPE, BREAKPOINT_EXCEPTION_EVENT_TYPE, CXX_EXCEPTION_EVENT_TYPE, NATIVE_EXCEPTION_EVENT_TYPE, THREAD_CREATE_EVENT_TYPE, PROCESS_CREATE_EVENT_TYPE, THREAD_EXIT_EVENT_TYPE, PROCESS_EXIT_EVENT_TYPE, LOAD_DLL_EVENT_TYPE, UNLOAD_DLL_EVENT_TYPE, DEBUG_STRING_EVENT_TYPE, RIP_EVENT_TYPE


logging.getLogger('angr').setLevel('ERROR')

# tarcing related
def contextualize_state(state, context_registers):
    state.regs.r0 = context_registers['R0']
    state.regs.r1 = context_registers['R1']
    state.regs.r2 = context_registers['R2']
    state.regs.r3 = context_registers['R3']
    state.regs.r4 = context_registers['R4']
    state.regs.r5 = context_registers['R5']
    state.regs.r6 = context_registers['R6']
    state.regs.r7 = context_registers['R7']
    state.regs.r8 = context_registers['R8']
    state.regs.r9 = context_registers['R9']
    state.regs.r10 = context_registers['R10']
    state.regs.r11 = context_registers['R11']
    state.regs.r12 = context_registers['R12']
    state.regs.sp = context_registers['Sp']
    state.regs.lr = context_registers['Lr']
    state.regs.pc = context_registers['Pc']
    state.regs.flags = context_registers['Cpsr']
    state.regs.fpscr = context_registers['Fpscr']


class DLLFuncsHook(angr.SimProcedure):
    def __init__(self, hook_callback, debugger_app):
        super().__init__()
        self.hook_callback = hook_callback
        self.debugger_app = debugger_app

    def run(self, argc, args):
        hook_callback(self.debugger_app, self.state)
        self.jump(self.state.regs.lr)


class DebuggerApp(App):
    code = reactive(b'')
    data = reactive(b'')
    curr_pc = reactive(0)
    code_base_addr = reactive(0)
    data_addr = reactive(0)
    threads = reactive({})
    breakpoints = reactive([])


    DEFAULT_CSS = '''
    Screen {
        align: center middle;
        layers: below above;
    }

    #grid {
        layout: grid;
        grid-size: 2;
        grid-rows: 75% 25%;
        grid-columns: 75% 25%;
        grid-gutter: 1;
        keyline: double;
    }

    #disasm-view {
        column-span: 1;
        row-span: 1;
    }

    DisasmLine:hover {
        padding-left: 4;
        background: green;
    }

    #thread-context {
        column-span: 1;
        row-span: 1;
    }

    RegisterWidget {
        layout: horizontal;
    }

    RegisterWidget > Label {
        height: 3;
        width: 15;
        content-align: center middle;
    }
    
    RegisterWidget > Input {
        height: 3;
        width: 20;
        content-align: center middle;
    }

    InputPop {
        layer: above;
        height: 3;
        width: 40;
        align: center middle;
    }
    InputPop > Input {
        height: 3;
        width: 40;
        content-align: center middle;
    }

    #tabs {
        row-span: 1;
        column-span: 2;
    }

    #hex-view {
    }

    BreakpointWidget {
        layout: horizontal;
        background: $boost;
        max-width: 50;
    }

    BreakpointWidget > Input {
        margin: 1;
        padding: 10;
        content-align: center middle;
    }

    BreakpointWidget > Button {
        margin: 1;
        content-align: center middle;
    }

    #log {
    }

    SelectProcess > ListView {
        width: 50;
        height: auto;
        margin: 2 2;
    }
    '''

    BINDINGS = [
        ('q', 'do_binding_quit', 'Quit application'),
        ('c', 'do_binding_continue_application', 'Continue application'),
        ('b', 'do_binding_modify_breakpoint', 'Modify applIcation breakpoint'),
        ('x', 'do_binding_hex_goto', 'Goto in applIcation memory in hex-view'),
        ('g', 'do_binding_code_goto', 'Change disasm location'),
        ('s', 'do_binding_single_step', 'Single step application'),
        ('t', 'do_binding_trace', 'Trace application')
    ]

    class DebuggerConnect(Message):
        pass

    class NativeDebugLaunch(Message):
        pass

    class BreakpointModify(Message):
        def __init__(self, result):
            self.result = result
            super().__init__()

    class HexGoto(Message):
        def __init__(self, result):
            self.result = result
            super().__init__()

    class CodeGoto(Message):
        def __init__(self, result):
            self.result = result
            super().__init__()

    class BreakpointEvent(Message):
        def __init__(self, tid, addr):
            self.tid = tid
            self.addr = addr
            super().__init__()

    class ProcessCreateEvent(Message):
        def __init__(self, tid):
            self.tid = tid
            super().__init__()

    class ThreadCreateEvent(Message):
        def __init__(self, tid):
            self.tid = tid
            super().__init__()

    class ThreadExitEvent(Message):
        def __init__(self, tid):
            self.tid = tid
            super().__init__()

    def __init__(self, ip, port, target=None, executable=None):
        super().__init__()
        self.ip = ip
        self.port = port
        self.target = target
        self.tracing = False
        self.bbl_trace = []
        self.stepping_breakpoints = []
        self.edm_protocol_manager = EDMProtocolManager(ip, port)
        self.angr_proj = None
        self.cs = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        if executable:
            self.angr_proj = angr.Project(executable, auto_load_libs=False, use_sim_procedures=True, simos='Generic')

    def gen_curr_state(self, thread_context):
        app_state = self.angr_proj.factory.blank_state()
        app_state.regs.r0 = thread_context['R0']
        app_state.regs.r1 = thread_context['R1']
        app_state.regs.r2 = thread_context['R2']
        app_state.regs.r3 = thread_context['R3']
        app_state.regs.r4 = thread_context['R4']
        app_state.regs.r5 = thread_context['R5']
        app_state.regs.r6 = thread_context['R6']
        app_state.regs.r7 = thread_context['R7']
        app_state.regs.r8 = thread_context['R8']
        app_state.regs.r9 = thread_context['R9']
        app_state.regs.r10 = thread_context['R10']
        app_state.regs.r11 = thread_context['R11']
        app_state.regs.r12 = thread_context['R12']
        app_state.regs.sp = thread_context['Sp']
        app_state.regs.lr = thread_context['Lr']
        app_state.regs.pc = thread_context['Pc']
        app_state.regs.flags = thread_context['Cpsr']
        app_state.regs.fpscr = thread_context['Fpscr']
        return app_state

    def predict_next_insn(self, thread_context):
        curr_state = self.gen_curr_state(thread_context)
        prediction_simgr = self.angr_proj.factory.simgr(curr_state)
        prediction_simgr.step(num_inst=1)
        if prediction_simgr.active:
            next_insn_addr = prediction_simgr.active[0].solver.eval(prediction_simgr.active[0].regs.pc)
            return next_insn_addr
        elif prediction_simgr.unconstrained:
            return prediction_simgr.unconstrained[0].regs.pc.args[0]
        else:
            return None

    def app_log(self, text):
        self.query_one('#log').write(f'[[cyan]Debug[/cyan]]: {text}')

    @work
    async def events_loop(self):
        while self.debugging:
            await asyncio.sleep(1.0)
            self.query_one('#log').write(f'[[cyan]Debug[/cyan]]: Get events')
            response = await self.edm_protocol_manager.protocol_GetEvents(self.pid)
            for event in response.events:
                if event.event_type == BREAKPOINT_EXCEPTION_EVENT_TYPE:
                    self.post_message(self.BreakpointEvent(event.tid, event.event_info.address))
                elif event.event_type == CXX_EXCEPTION_EVENT_TYPE:
                    await self.edm_protocol_manager.protocol_ContinueAllThreads(self.pid)
                elif event.event_type == NATIVE_EXCEPTION_EVENT_TYPE:
                    await self.edm_protocol_manager.protocol_ContinueAllThreads(self.pid)
                elif event.event_type == THREAD_CREATE_EVENT_TYPE:
                    self.post_message(self.ThreadCreateEvent(event.tid))
                elif event.event_type == PROCESS_CREATE_EVENT_TYPE:
                    self.post_message(self.ProcessCreateEvent(event.tid))
                elif event.event_type == THREAD_EXIT_EVENT_TYPE:
                    self.post_message(self.ThreadExitEvent(event.tid))
                elif event.event_type == PROCESS_EXIT_EVENT_TYPE:
                    self.action_do_binding_quit()
                elif event.event_type == LOAD_DLL_EVENT_TYPE:
                    await self.edm_protocol_manager.protocol_ContinueAllThreads(self.pid)
                elif event.event_type == UNLOAD_DLL_EVENT_TYPE:
                    await self.edm_protocol_manager.protocol_ContinueAllThreads(self.pid)
                elif event.event_type == DEBUG_STRING_EVENT_TYPE:
                    await self.edm_protocol_manager.protocol_ContinueAllThreads(self.pid)
                elif event.event_type == RIP_EVENT_TYPE:
                    await self.edm_protocol_manager.protocol_ContinueAllThreads(self.pid)

    @work
    async def select_process(self):
        pass

    @work
    async def launch_debug_target(self, process_name):
        self.pid = await self.edm_protocol_manager.protocol_NativeDebugLaunch(process_name)
        self.post_message(self.NativeDebugLaunch())

    @work
    async def connect_debugger(self):
        self.app_log('Handshking')
        await self.edm_protocol_manager.protocol_TransportLoader_Handshake()
        self.app_log('Begin debug session')
        await self.edm_protocol_manager.protocol_BeginDebugSession()
        self.post_message(self.DebuggerConnect())

    @work
    async def breakpoint_event_handler(self, tid, addr):
        if self.stepping_breakpoints:
            prev_bp, curr_stepping_bp = self.stepping_breakpoints.pop()
            if prev_bp in self.breakpoints:
                await self.edm_protocol_manager.protocol_ModifyBreakPoint(self.pid, prev_bp, 0x1)
            if not curr_stepping_bp in self.breakpoints:
                await self.edm_protocol_manager.protocol_ModifyBreakPoint(self.pid, curr_stepping_bp, 0x2)
            await self.edm_protocol_manager.protocol_ContinueAllThreads(self.pid)
            return

        thread_context = await self.edm_protocol_manager.protocol_ThreadContextGet(self.pid, tid)
        self.break_tid = tid
        self.threads[tid] = thread_context
        self.query_one(f"#thread-{tid}-context").update_thread_context(thread_context)

        self.curr_pc = addr
        self.query_one("#thread-context").active = f"pane-{tid}"
        self.code_base_addr = addr-0x40
        self.code = await self.edm_protocol_manager.protocol_ProcessMemoryRead(self.pid, addr-0x40, self.query_one("#disasm-view").virtual_size.height*4)

        mem = bytearray(await self.edm_protocol_manager.protocol_ProcessMemoryRead(self.pid, thread_context['Sp'], 0x200))
        self.data = mem
        self.data_addr = thread_context['Sp']
        self.query_one('#hex-view').cursor = 0
        self.app_log(f"Breakpoint event on address {addr}")
        self.query_one("*").loading = False
        self.query_one("#disasm-view").disabled = False
        self.query_one("#disasm-view").loading = False
        self.query_one("#hex-view").disabled = False
        self.query_one("#hex-view").loading = False
        self.query_one("#thread-context").disabled = False
        self.query_one("#thread-context").loading = False

    @work
    async def process_create_event_handler(self, tid):
        self.app_log(f"Process create event with thread {hex(tid)}")
        thread_context = await self.edm_protocol_manager.protocol_ThreadContextGet(self.pid, tid)
        self.threads[tid] = thread_context

        self.query_one('#thread-context').add_pane(TabPane(f'Thread-{hex(tid)}', id=f'pane-{tid}'))
        await self.query_one(f'#pane-{tid}').mount(ThreadContextWidget(thread_id=tid, thread_context=thread_context, id=f'thread-{tid}-context'))

        self.breakpoints.append(self.angr_proj.loader.main_object.entry)
        self.mutate_reactive(DebuggerApp.breakpoints)
        await self.edm_protocol_manager.protocol_ModifyBreakPoint(self.pid, self.angr_proj.loader.main_object.entry, 0x1)
        await asyncio.sleep(0.5)
        await self.edm_protocol_manager.protocol_ContinueAllThreads(self.pid)

    @work
    async def thread_create_event_handler(self, tid):
        self.app_log(f"Thread create event with thread {hex(tid)}")
        thread_context = await self.edm_protocol_manager.protocol_ThreadContextGet(self.pid, tid)
        self.threads[tid] = thread_context

        self.query_one('#thread-context').add_pane(TabPane(f'Thread-{hex(tid)}', id=f'pane-{tid}'))
        await self.query_one(f'#pane-{tid}').mount(ThreadContextWidget(thread_id=tid, thread_context=thread_context, id=f'thread-{tid}-context'))
        await self.edm_protocol_manager.protocol_ContinueAllThreads(self.pid)

    @work
    async def thread_exit_event_handler(self, tid):
        self.app_log(f"Thread exit event with thread {hex(tid)}")
        self.threads.pop(tid)
        self.query_one("#thread-context").remove_pane(f"pane-{tid}")
        await self.edm_protocol_manager.protocol_ContinueAllThreads(self.pid)

    @work
    async def hex_view_commit_changes_handler(self, base, changes):
        self.app_log("Commiting memory changes")
        for offsets,data in changes:
            await self.edm_protocol_manager.protocol_ProcessMemoryWrite(self.pid, base+offsets[0], data)
            if self.code_base_addr <= base+offsets[0] < self.code_base_addr + len(self.code):
                byte_offset = offsets[0]
                self.code = b''.join([self.code[:byte_offset] + data + self.data[byte_offset+len(data):]])

    @work
    async def register_widget_register_changed_handler(self, tid, register, value):
        self.app_log(f"Changing register {register} to value {hex(value)}")
        self.threads[tid][register] = value
        await self.edm_protocol_manager.protocol_ThreadContextSet(self.threads[tid])

        if register == 'Pc':
            self.query_one("#thread-context").active = f"pane-{tid}"
            self.code = await self.edm_protocol_manager.protocol_ProcessMemoryRead(self.pid, value, 400)
            self.query_one("#disasm-view").app_pc = value
            self.query_one("#disasm-view").base_addr = value
        elif register == 'Sp':
            mem = bytearray(await self.edm_protocol_manager.protocol_ProcessMemoryRead(self.pid, value, 0x200))
            self.query_one('#hex-view').data = mem
            self.query_one('#hex-view').cursor = 0
            self.query_one('#hex-view').current_addr = value

    @work
    async def breakpoint_toggle_handler(self, addr):
        self.app_log(f"Toggle breakpoint address {addr}, {self.breakpoints}")
        if addr in self.breakpoints:
            self.breakpoints.remove(addr)
            self.mutate_reactive(DebuggerApp.breakpoints)
            await self.edm_protocol_manager.protocol_ModifyBreakPoint(self.pid, addr, 0x2)
        else:
            self.breakpoints.append(addr)
            self.mutate_reactive(DebuggerApp.breakpoints)
            await self.edm_protocol_manager.protocol_ModifyBreakPoint(self.pid, addr, 0x1)

    @work
    async def disasm_view_min_scroll_handler(self):
        self.app_log("Scroll upper boundary")
        self.code_base_addr -= 0x40
        self.code = bytearray(await self.edm_protocol_manager.protocol_ProcessMemoryRead(self.pid, self.code_base_addr, 0x40)) + self.code

    @work
    async def disasm_view_max_scroll_handler(self, msg):
        self.app_log("Scroll lower boundary")
        self.code_base_addr += 0x40
        self.code = self.code[0x40:] + bytearray(await self.edm_protocol_manager.protocol_ProcessMemoryRead(self.pid, self.code_base_addr+len(self.code), 0x40))

    @work
    async def continue_application_handler(self):
        self.app_log("Continuing application")
        self.query_one("#disasm-view").disabled = True
        self.query_one("#disasm-view").loading = True
        self.query_one("#hex-view").disabled = True
        self.query_one("#hex-view").loading = True
        self.query_one("#thread-context").disabled = True
        self.query_one("#thread-context").loading = True
    
        await self.edm_protocol_manager.protocol_ModifyBreakPoint(self.pid, self.curr_pc, 0x2)
        stepping_bp = self.predict_next_insn(self.threads[self.break_tid])
        
        if isinstance(stepping_bp, str):
            val_addr = int(stepping_bp.split('_')[1], 16)
            next_insn_addr = await self.edm_protocol_manager.protocol_ProcessMemoryRead(self.pid, val_addr, 4)
            stepping_bp = Int32ul.parse(next_insn_addr)

        await self.edm_protocol_manager.protocol_ModifyBreakPoint(self.pid, stepping_bp, 0x1)
        self.stepping_breakpoints.append((self.curr_pc, stepping_bp))
        await self.edm_protocol_manager.protocol_ContinueAllThreads(self.pid)
        
    def dll_hook(self, state):
        pass

    @work
    async def hex_goto_handler(self, addr):
        self.app_log("Goto in hex-view")
        self.data = bytearray(await self.edm_protocol_manager.protocol_ProcessMemoryRead(self.pid, addr, 0x200))
        self.data_addr = addr

    @work
    async def code_goto_handler(self, addr):
        self.app_log("Goto in disasm-view")
        self.code_base_addr = addr
        self.code = await self.edm_protocol_manager.protocol_ProcessMemoryRead(self.pid, addr, 0x200)

    def compose(self):
        with Container(id='grid'):
            yield DisasmView(id='disasm-view').data_bind(DebuggerApp.code).data_bind(DebuggerApp.breakpoints).data_bind(DebuggerApp.code_base_addr).data_bind(DebuggerApp.curr_pc)
            yield TabbedContent(id='thread-context')
            with TabbedContent(id='tabs'):
                with TabPane('HexView'):
                    yield HexView(id='hex-view').data_bind(DebuggerApp.data).data_bind(DebuggerApp.data_addr)
                with TabPane('Log'):
                    yield RichLog(id='log', markup=True)
                with TabPane('Breakpoints'):
                    yield BreakpointsView(id='breakpoints-view').data_bind(DebuggerApp.breakpoints)
        yield Footer()

    async def on_mount(self):
        self.app_log("Connecting debugger")
        self.query_one("*").loading = True
        self.connect_debugger()

    async def on_debugger_app_debugger_connect(self, msg):
        self.debugging = True
        self.query_one('*').loading = False
        if not self.target:
            self.app_log('Selecting debug process target')
            self.select_process()
        else:
            self.app_log('Launching debug target')
            self.launch_debug_target(self.target)

    async def on_debugger_app_breakpoint_event(self, msg):
        self.breakpoint_event_handler(msg.tid, msg.addr)

    async def on_debugger_app_process_create_event(self, msg):
        self.process_create_event_handler(msg.tid)
        
    async def on_debugger_app_thread_create_event(self, msg):
        self.thread_create_event_handler(msg.tid)
        
    async def on_debugger_app_thread_exit_event(self, msg):
        self.thread_exit_event_handler(msg.tid)
        
    async def on_debugger_app_process_select(self, msg):
        pass        

    async def on_debugger_app_debugger_attach(self, msg):
        pass

    async def on_debugger_app_native_debug_launch(self, msg):
        self.app_log("Starting event loop")
        self.events_loop()

    async def on_hex_view_commit_changes(self, msg):
        self.hex_view_commit_changes_handler(msg.data_addr, msg.changes)

    async def on_register_widget_register_changed(self, msg):
        self.register_widget_register_changed_handler(msg.tid, msg.register, msg.value)

    async def on_breakpoint_widget_remove_bp(self, msg):
        self.breakpoint_toggle_handler(msg.addr)

    async def on_disasm_view_toggle_breakpoint(self, msg):
        self.breakpoint_toggle_handler(msg.addr)

    async def on_disasm_view_min_scroll(self, msg):
        self.disasm_view_min_scroll_handler()

    async def on_disasm_view_max_scroll(self, msg):
        self.disasm_view_max_scroll_handler(msg)

    async def on_debugger_app_breakpoint_modify(self, msg):
        self.breakpoint_toggle_handler(msg.result)

    async def on_debugger_app_hex_goto(self, msg):
        self.hex_goto_handler(msg.result)

    async def on_debugger_app_code_goto(self, msg):
        self.code_goto_handler(msg.result)

    async def action_do_binding_modify_breakpoint(self):
        self.mount(InputPop(self.BreakpointModify))
        self.query_one("InputPop").focus()

    async def action_do_binding_continue_application(self):
        self.continue_application_handler()

    async def action_do_binding_hex_goto(self):
        self.mount(InputPop(self.HexGoto))
        self.query_one("InputPop").focus()

    async def action_do_binding_code_goto(self):
        self.mount(InputPop(self.CodeGoto))
        self.query_one("InputPop").focus()

    async def action_do_binding_single_step(self):
        pass

    async def action_do_binding_trace(self):
        pass

    async def on_tabbed_content_tab_activated(self, event):
        pass

    async def action_do_binding_quit(self):
        self.exit()

