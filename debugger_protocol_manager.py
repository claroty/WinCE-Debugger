import uuid
import socket
import asyncio
from zlib import crc32
from hashlib import md5
from construct import *


class NoSuchThreadError(Exception):
    pass


SERIALIZED_DATA = Struct(
    'sz' / Int32ul,
    'data' / Bytes(this.sz)
)


SERIALIZED64_DATA = Struct(
    'sz' / Int64ul,
    'data' / Bytes(this.sz)
)


RESPONSE_METADATA = Struct(
    'transaction_type' / Const(0x30, Int32ul),
    'prev_digest' / Bytes(0x10),
    Padding(0x4),
    Const(0x4, Int32ul),
    'sz' / Int32ub
)


RESPONSE = Struct(
    'transaction_type' / Const(0x30, Int32ul),
    'prev_digest' / Bytes(0x10),
    'elements_count' / Int32ul,
    'elements' / Array(this.elements_count, SERIALIZED_DATA)
)


RPC_NAME_DATA = Struct(
    'sz' / Int32ul,
    'name' / Bytes((this.sz+1)*2)
)

PROCESSES_INFO = GreedyRange(
    Struct(
        Padding(0x8),
        'pid' / Int32ul,
        Padding(0xc),
        'process_name' / PaddedString(0x230, 'utf_16_le'),
        'process_state' / PaddedString(0x70, 'utf_16_le')
    )
)


EXCEPTION_EVENT_TYPE = 0x101
EXCEPTION_EVENT_STRUCT = Struct()

BREAKPOINT_EXCEPTION_EVENT_TYPE = 0x110
BREAKPOINT_EXCEPTION_EVENT_STRUCT = Struct(
    Padding(0xc),
    'address' / Int32ul
)


CXX_EXCEPTION_EVENT_TYPE = 0x2
CXX_EXCEPTION_EVENT_STRUCT = Struct()


NATIVE_EXCEPTION_EVENT_TYPE = 0x1
NATIVE_EXCEPTION_EVENT_STRUCT = Struct()

THREAD_CREATE_EVENT_TYPE = 0x102
THREAD_CREATE_EVENT_STRUCT = Struct()

PROCESS_CREATE_EVENT_TYPE = 0x103
PROCESS_CREATE_EVENT_STRUCT = Struct()

THREAD_EXIT_EVENT_TYPE = 0x104
THREAD_EXIT_EVENT_STRUCT = Struct()

PROCESS_EXIT_EVENT_TYPE = 0x105
PROCESS_EXIT_EVENT_STRUCT = Struct()

LOAD_DLL_EVENT_TYPE = 0x106
LOAD_DLL_EVENT_STRUCT = Struct()

UNLOAD_DLL_EVENT_TYPE = 0x107
UNLOAD_DLL_EVENT_STRUCT = Struct()

DEBUG_STRING_EVENT_TYPE = 0x108
DEBUG_STRING_EVENT_STRUCT = Struct()

RIP_EVENT_TYPE = 0x10c
RIP_EVENT_STRUCT = Struct()



EVENTS_STRUCT = Struct(
    Padding(0x4),
    'events_count' / Int32ul,
    'events' / Array(
        this.events_count,
        'event' / Struct(
            'event_info_sz' / Int32ul,
            'event_idx' / Int32ul,
            'pid' / Int32ul,
            'tid' / Int32ul,
            Padding(0x8),
            'event_type' / Int32ul,
            'event_info' / Switch(this.event_type, {
                EXCEPTION_EVENT_TYPE: EXCEPTION_EVENT_STRUCT,
                BREAKPOINT_EXCEPTION_EVENT_TYPE: BREAKPOINT_EXCEPTION_EVENT_STRUCT,
                CXX_EXCEPTION_EVENT_TYPE: CXX_EXCEPTION_EVENT_STRUCT,
                NATIVE_EXCEPTION_EVENT_TYPE: NATIVE_EXCEPTION_EVENT_STRUCT,
                THREAD_CREATE_EVENT_TYPE: THREAD_CREATE_EVENT_STRUCT,
                PROCESS_CREATE_EVENT_TYPE: PROCESS_CREATE_EVENT_STRUCT,
                THREAD_EXIT_EVENT_TYPE: THREAD_EXIT_EVENT_STRUCT,
                PROCESS_EXIT_EVENT_TYPE: PROCESS_EXIT_EVENT_STRUCT,
                LOAD_DLL_EVENT_TYPE: LOAD_DLL_EVENT_STRUCT,
                UNLOAD_DLL_EVENT_TYPE: UNLOAD_DLL_EVENT_STRUCT,
                DEBUG_STRING_EVENT_TYPE: DEBUG_STRING_EVENT_STRUCT,
                RIP_EVENT_TYPE: RIP_EVENT_STRUCT
            })
        )
    )
)


THREAD_CONTEXT = Struct(
    Padding(0x8),
    'ContextFlags' / Int32ul,
    'R0' / Int32ul,
    'R1' / Int32ul,
    'R2' / Int32ul,
    'R3' / Int32ul,
    'R4' / Int32ul,
    'R5' / Int32ul,
    'R6' / Int32ul,
    'R7' / Int32ul,
    'R8' / Int32ul,
    'R9' / Int32ul,
    'R10' / Int32ul,
    'R11' / Int32ul,
    'R12' / Int32ul,
    'Sp' / Int32ul,
    'Lr' / Int32ul,
    'Pc' / Int32ul,
    'Cpsr' / Int32ul,
    'Fpscr' / Int32ul,
    Padding(0xf4-(21*4))
)


MEMORY = Struct(
    Padding(0x4),
    'mem_sz' / Int32ul,
    'mem' / Bytes(this.mem_sz)
)


BP_INFO = Struct(
    'bp_addr' / Int32ul,
    Const(0x0, Int32ul),
    Const(0x1, Int32ul),
    Const(0xffffffff, Int32ul),
    Padding(0x10),
    Const(0x4, Int64ul)
)


def deserialize(serialized_data):
    return SERIALIZED_DATA.parse().get('data', None)


def serialize(data):
    return SERIALIZED_DATA.build({'sz': len(data), 'data': data})


def serialize64(data):
    return SERIALIZED64_DATA.build({'sz': len(data), 'data': data})


def build_rpc_name_data(name):
    return RPC_NAME_DATA.build({'sz': len(name), 'name': ''.join([name,'\x00']).encode('utf-16le')})


class EDMProtocolManager():
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.lock = asyncio.Lock()
        self.prev_digest = None

    async def build_transaction(self, header, data, data_digest, need_crc=True):
        if need_crc:
            crc = Int32ul.build(crc32(serialize(data_digest) + data))
        else:
            crc = b''

        if self.prev_digest:
            return Int32ul.build(0x20) + self.prev_digest + serialize(data_digest) + Int32ul.build(len(header)+4) + header + data + crc
        return serialize(data_digest) + Int32ul.build(len(header)+4) + header + data + crc
 
    async def invoke_rpc(self, rpc, *args, need_crc=True):
        items = [build_rpc_name_data(rpc)]
        items.extend(args)
        data = b''.join(items)
        md5_hash = md5()
        md5_hash.update(data)
        data_digest = md5_hash.digest()
        header = data_digest + Int32ul.build(0x0) + Int32ul.build((len(rpc)+1)*2 + Int32ul.parse(args[0]) + 0x24) + Int32ub.build((len(rpc)+1)*2 + Int32ul.parse(args[0]) + 0x24) + self.debug_session_guid
        transaction = await self.build_transaction(header, data, data_digest, need_crc)
        self.writer.write(transaction)
        await self.writer.drain()

        response_metadata_raw = b''
        while len(response_metadata_raw) < RESPONSE_METADATA.sizeof():
            response_metadata_raw += await self.reader.read(RESPONSE_METADATA.sizeof())

        response_metadata = RESPONSE_METADATA.parse(response_metadata_raw)

        buf = b''
        while len(buf) < 0x1c+response_metadata.sz:
            buf += await self.reader.read(0x1c+response_metadata.sz)

        response = RESPONSE.parse(buf)
        self.prev_digest = response.prev_digest
        return response.elements

    async def protocol_TransportLoader_Handshake(self):
        await self.lock.acquire()
        self.reader, self.writer = await asyncio.open_connection(self.ip, self.port)
        self.writer.write(b'\x01')
        await self.writer.drain()
        await self.reader.read(1)

        self.writer.write(b'\x01\x00\x00\x00')
        await self.writer.drain()
        self.keepalive_reader, self.keepalive_writer = await asyncio.open_connection(self.ip, self.port)
        self.keepalive_writer.write(b'\x01')
        await self.keepalive_writer.drain()
        await self.keepalive_reader.read(1)

        self.writer.write('TransportLoader Handshake\x00'.encode('utf-16le'))
        await self.writer.drain()
        response = await self.reader.read(52)
        self.lock.release()

    async def protocol_BeginDebugSession(self):
        await self.lock.acquire()
        self.debug_session_guid = uuid.uuid1().bytes
        response = await self.invoke_rpc('BeginDebugSession', serialize64(self.debug_session_guid))
        self.lock.release()

    async def protocol_EndDebugSession(self):
        await self.lock.acquire()
        response = await self.invoke_rpc('EndDebugSession', serialize64(self.debug_session_guid))
        self.lock.release()

    async def protocol_GetArchitectureInfo(self):
        await self.lock.acquire()
        response = await self.invoke_rpc('GetArchitectureInfo', Int64ul.build(0x0))
        self.lock.release()

    async def protocol_BeginEnumProcesses(self):
        await self.lock.acquire()
        self.enum_processes_guid = uuid.uuid1().bytes
        response = await self.invoke_rpc('BeginEnumProcesses', Int64ul.build(0x10), self.enum_processes_guid)
        self.lock.release()
        return response

    async def protocol_EndEnumProcesses(self):
        await self.lock.acquire()
        response = await self.invoke_rpc('EndEnumProcesses', Int64ul.build(0x10), self.enum_processes_guid)
        self.lock.release()
        return response

    async def protocol_GetCount(self):
        await self.lock.acquire()
        response = await self.invoke_rpc('GetCount', Int64ul.build(0x10), self.enum_processes_guid)
        self.lock.release()
        return Int32ul.parse(response.pop().data[4:])

    async def protocol_GetProcesses(self, processes_count):
        await self.lock.acquire()
        response = await self.invoke_rpc('GetProcesses', Int64ul.build(0x14), self.enum_processes_guid, Int32ul.build(processes_count))
        self.lock.release()
        return PROCESSES_INFO.parse(response.pop().data)

    async def protocol_AttachDebugger(self, process_name, pid):
        await self.lock.acquire()
        process_name_bytes = ''.join([process_name, '\x00']).encode('utf-16le')
        response = await self.invoke_rpc('AttachDebugger', Int64ul.build(0x18+len(process_name_bytes)), Int32ul.build(pid), Int32ul.build(len(process_name_bytes)), process_name_bytes, self.debug_session_guid)
        self.lock.release()
        return response

    async def protocol_NativeDebugLaunch(self, process_name):
        await self.lock.acquire()
        process_name_bytes = ''.join([process_name, '\x00']).encode('utf-16le')
        response = await self.invoke_rpc('NativeDebugLaunch', Int64ul.build(0x24+len(process_name_bytes)+0x2), Int32ul.build(len(process_name_bytes)), process_name_bytes, Int32ul.build(0x2), Int16ul.build(0x0) , Int32ul.build(0x0), Int32ul.build(0x0), Int32ul.build(0x2), self.debug_session_guid)
        self.lock.release()
        return Int32ul.parse(response.pop().data[-4:])

    async def protocol_StopDebugging(self):
        pass

    async def protocol_DebugEventContinue(self):
        pass

    async def protocol_GetEvents(self, pid, events_count=0x0):
        await self.lock.acquire()
        response = await self.invoke_rpc('GetEvents', Int64ul.build(0x4), Int32ul.build(pid), Int32ul.build(events_count), need_crc=False)
        self.lock.release()
        return EVENTS_STRUCT.parse(response.pop().data)


    async def protocol_ProcessMemoryRead(self, pid, addr, sz):
        await self.lock.acquire()
        response = await self.invoke_rpc('ProcessMemoryRead', Int64ul.build(0x10), Int32ul.build(pid), Int64ul.build(addr), Int32ul.build(sz))
        self.lock.release()
        return MEMORY.parse(response.pop().data).mem

    async def protocol_ProcessMemoryWrite(self, pid, addr, data):
        await self.lock.acquire()
        response = await self.invoke_rpc('ProcessMemoryWrite', Int64ul.build(0x10+len(data)), Int32ul.build(pid), Int64ul.build(addr), Int32ul.build(len(data)), data)
        self.lock.release()
        return response

    async def protocol_ThreadContextGet(self, pid, tid):
        await self.lock.acquire()
        response = await self.invoke_rpc('ThreadContextGet', Int64ul.build(0xc), Int32ul.build(pid), Int32ul.build(tid), Int32ul.build(0xf4))
        self.lock.release()
        if len(response[0].data) == 4:
            if Int32ul.parse(response.pop().data) == 0x89731207:
                raise NoSuchThreadError('')
        thread_context = THREAD_CONTEXT.parse(response.pop().data)
        thread_context.pop('_io')
        return thread_context

    async def protocol_ThreadContextSet(self, pid, tid, thread_context):
        await self.lock.acquire()
        response = await self.invoke_rpc('ThreadContextSet', Int64ul.build(0x100), Int32ul.build(pid), Int32ul.build(tid), Int32ul.build(0xf4), THREAD_CONTEXT.build(thread_context))
        self.lock.release()
        return response

    async def protocol_ContinueAllThreads(self, pid):
        await self.lock.acquire()
        response = await self.invoke_rpc('ContinueAllThreads', Int64ul.build(0x4), Int32ul.build(pid))
        self.lock.release()
        return response

    async def protocol_BreakAll(self):
        pass

    async def protocol_ThreadSuspend(self):
        pass

    async def protocol_ThreadResume(self):
        pass

    async def protocol_ProcessCreate(self):
        pass

    async def protocol_ProcessTerminate(self):
        pass

    async def protocol_ModifyBreakPoint(self, pid, addr, mod_type):
        await self.lock.acquire()
        breakpoint_info = BP_INFO.build({'bp_addr': addr})
        response = await self.invoke_rpc('ModifyBreakPoint', Int64ul.build(0x30), Int32ul.build(pid), breakpoint_info, Int32ul.build(mod_type), Int32ub.build(0x4200), need_crc=False)
        self.lock.release()
        return response

    async def protocol_SetExceptions(self):
        pass

    async def protocol_RemoveSetExceptions(self):
        pass

    async def protocol_Launch(self):
        pass

    async def protocol_GetEndPointInformation(self):
        pass

    async def protocol_GetServiceState(self):
        pass

    async def protocol_EnumServiceProviders(self):
        pass

    async def protocol_GetPDataBlock(self):
        pass

    async def protocol_SetBreakpointsAndContinue(self):
        pass

    async def get_processes(self):
        await self.protocol_BeginEnumProcesses()
        count = await self.protocol_GetCount()
        processes = await self.protocol_GetProcesses(count)
        await self.protocol_EndEnumProcesses()
        return processes

