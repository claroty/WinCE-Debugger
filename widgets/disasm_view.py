import binascii
from capstone import *
from textual import work
from textual.app import *
from textual.widgets import *
from textual.strip import Strip
from textual.containers import *
from textual.geometry import Size
from textual.message import Message
from textual.reactive import reactive
from textual.scroll_view import ScrollView
from rich.text import Text
from rich.style import Style
from rich.jupyter import JupyterMixin
from rich.segment import Segment, Segments


class DisasmView(ScrollView):
    # bound attrs
    curr_pc = reactive(0)
    code = reactive(b'')
    breakpoints = reactive([])
    code_base_addr = reactive(0)

    # internal
    disasm = reactive([])
    cursor = reactive(0)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.virtual_size = Size(self.virtual_size.width, self.virtual_size.height+0x40)

    class MinScroll(Message):
        pass

    class MaxScroll(Message):
        pass

    class ToggleBreakpoint(Message):
        def __init__(self, addr):
            super().__init__()
            self.addr = addr

    def generate_instruction_segments(self, offset, addr, insn_bytes, mnemonic, op_string):
        styles = [Style()]
        if addr in self.breakpoints:
            styles.append(Style(bgcolor='white'))
        if offset == self.cursor:
            styles.append(Style(bold=True, italic=True))

        if addr == self.curr_pc:
            styles.append(Style(color='black'))
        else:
            styles.append(Style(color='cyan'))
        segments = [Segment(f"{hex(addr).rjust(8, ' ')}: ", Style.chain(*styles))]
        # styles.pop()
        segments.append(Segment(binascii.hexlify(insn_bytes).decode(), Style.chain(*styles)))
        segments.append(Segment(f" {mnemonic} {op_string}", Style.chain(*styles)))
        return segments
        
    def render_line(self, y):
        scroll_x, scroll_y = self.scroll_offset
        y += scroll_y

        if y < len(self.disasm):
            return Strip(self.generate_instruction_segments(y, *self.disasm[y]))
        return Strip.blank(20, self.rich_style)

    def key_up(self):
        if self.cursor == 0:
            self.post_message(self.MinScroll())
            return
        self.cursor -= 1
            
    def key_down(self):
        if self.cursor == self.virtual_size.height - 1:
            self.post_message(self.MaxScroll())
            return
        self.cursor += 1

    def on_mouse_scroll_up(self, event):
        if self.scroll_offset.y <= 0:
            self.post_message(self.MinScroll())

    def on_mouse_scroll_down(self, event):
        if self.scroll_offset.y+self.size.height >= self.virtual_size.height:
            self.post_message(self.MaxScroll())

    def watch_code(self, val):
        cs = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        self.disasm = [(i.address, i.bytes, i.mnemonic, i.op_str) for i in cs.disasm(val, self.code_base_addr)]

    def on_mouse_move(self, event):
        mouse_pos = event.offset + self.scroll_offset
        self.cursor = mouse_pos.y

    def on_click(self, event):
        if event.button == 1 and not self.loading:
            bp_addr = self.code_base_addr + (event.offset.y*4) + (self.scroll_offset.y*4)
            self.post_message(self.ToggleBreakpoint(bp_addr))