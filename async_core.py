import asyncio
from construct import *

from utils import *


REGISTERS = ['R0', 'R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7', 'R8', 'R9', 'R10', 'R11', 'R12', 'SP', 'LR', 'PC', 'PSR']
GUID = Sequence(Int32ul, Int16ul, Int16ul, Int16ub, Bytes(6))

SENDFILE_INITIAL_PKT_STRUCT = Struct(
    'magic' / Const(b'\xffVSD'),
    'cmd' / Const(0x2, Int32ul),
    Padding(0x10),
    'size' / Int32ul,
    'class' / Const(0x0, Int32ul),
    Padding(0x4),
    'low_date_time' / Const(0x0, Int32ul),
    'file_attrs' / Const(0x2, Int32ul),
    'flags_bitmask' / Const(0x0, Int32ul),
    Padding(0xc),
    'content_size' / Int32ul
)


SENDFILE_CONTENT_PKT_STRUCT = Struct(
    'magic' / Const(b'\xffVSD'),
    'cmd' / Const(0x2, Int32ul),
    Padding(0x10),
    'size' / Int32ul,
    'class' / Const(0x1, Int32ul),
    Padding(0x4),
    'low_date_time' / Const(0x0, Int32ul),
    'file_attrs' / Const(0x2, Int32ul),
    'flags_bitmask' / Const(0x0, Int32ul),
    Padding(0xc),
    'content_size' / Int32ul
)


SENDFILE_FINAL_PKT_STRUCT = Struct(
    'magic' / Const(b'\xffVSD'),
    'cmd' / Const(0x2, Int32ul),
    Padding(0x10),
    'size' / Const(0x24, Int32ul),
    'class' / Const(0x2, Int32ul),
    Padding(0x4),
    'low_date_time' / Const(0x0, Int32ul),
    'file_attrs' / Const(0x2, Int32ul),
    'flags_bitmask' / Const(0x0, Int32ul),
    Padding(0xc),
    'content_size' / Const(0x0, Int32ul)
)


START_PACKAGE_PKT_STRUCT = Struct(
    'magic' / Const(b'\xffVSD'),
    'cmd' / Const(0x19, Int32ul),
    'guid' / GUID,
    'body_size' / Int32ul,
    'service_id_size' / Int32ul,
    'exe_path_size' / Int32ul,
    'dll_path_size' / Int32ul,
    'service_id' / Bytes(this.service_id_size),
    'exe_path' / Bytes(this.exe_path_size),
    'dll_path' / Bytes(this.dll_path_size)
)

SHUTDOWN_PACKAGE_PKT_STRUCT = Struct(
    'magic' / Const(b'\xffVSD'),
    'cmd' / Const(0x18, Int32ul),
    'guid' / GUID,
    'body_size' / Int32ul,
    'service_id_size' / Int32ul,
    'service_id' / Bytes(this.service_id_size),
)

TERMINATE_PROCESS_PKT_STRUCT = Struct(
    'magic' / Const(b'\xffVSD'),
    'cmd' / Const(0xa, Int32ul),
    'guid' / GUID,
    'body_size' / Int32ul,
    'pid' / Int32ul
)

GET_SERVICE_STREAM_ID_PKT_STRUCT = Struct(
    'magic' / Const(b'\xffVSD'),
    'cmd' / Const(0x15, Int32ul),
    'guid' / GUID,
    'body_size' / Int32ul,
    'content_size' / Int32ul,
    'content' / Bytes(this.content_size)
)


RESP_GET_SERVICE_STREAM_ID_PKT_STRUCT = Struct(
    'magic' / Const(b'\xffVSD'),
    'cmd' / Const(0x15, Int32ul),
    Padding(0x10),
    'body_size' / Int32ul,
    'content_size' / Int32ul,
    'content' / Bytes(this.content_size)
)


UNIQ_SERVICE_ID = 'AEF7671F-A8D6-4E27-8B83-6C3E44425B6E\x00'
REMOTE_EDM_EXE_PATH = '%CSIDL_WINDOWS%\\edm.exe\x00'
REMOTE_EDM_DLL_PATH = '%CSIDL_WINDOWS%\\edbgtl.dll\x00'

class VSD2005Session(object):
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.lock = asyncio.Lock()

    async def vsd2005_handshake(self):
        self.reader, self.writer = await asyncio.open_connection(self.ip, self.port)
        self.writer.write(b'\x01')
        await self.writer.drain()
        await self.reader.read(0x1)
        self.writer.write(Int32ul.build(0x1))
        await self.writer.drain()

        keepalive_reader, keepalive_writer = await asyncio.open_connection(self.ip, self.port)
        keepalive_writer.write(b'\x01')
        await keepalive_writer.drain()
        await keepalive_reader.read(0x1)

        await self.reader.read(0x1)
        self.writer.write(b'\x01')
        await self.writer.drain()
        
    async def vsd2005_send_file(self, local_path, remote_path_raw):
        remote_path = (remote_path_raw + '\x00').encode('utf-16le')
        self.writer.write(SENDFILE_INITIAL_PKT_STRUCT.build({
            'size': 0x24 + len(remote_path),
            'content_size': len(remote_path)
        }) + remote_path)
        await self.writer.drain()
        await self.reader.read(1460)

        with open(local_path, 'rb') as f:
            buff = f.read(0xff8)

            while buff:
                self.writer.write(SENDFILE_CONTENT_PKT_STRUCT.build({
                    'size': 0x24 + len(buff),
                    'content_size': len(buff)
                }) + buff)
                await self.writer.drain()
                buff = f.read(0xff8)

        self.writer.write(SENDFILE_FINAL_PKT_STRUCT.build(None))
        await self.writer.drain()
        await self.reader.read(1460)

    async def vsd2005_send_hot_patched_exe(self, exe, remote_path):
        oep, cave_break = patch_executable(exe)
        await self.vsd2005_send_file(exe+'_mod', remote_path)
        return oep, cave_break

    async def vsd2005_start_service(self, raw_service_id, raw_exe, raw_dll):
        service_id = (raw_service_id + '\x00').encode('utf-16le')
        exe = (raw_exe + '\x00').encode('utf-16le')
        dll = (raw_dll + '\x00').encode('utf-16le')

        self.writer.write(START_PACKAGE_PKT_STRUCT.build({
                'guid': get_rand_guid(),
                'body_size': 0xc + len(service_id) + len(exe) + len(dll),
                'service_id_size': len(service_id),
                'exe_path_size': len(exe),
                'dll_path_size': len(dll),
                'service_id': service_id,
                'exe_path': exe,
                'dll_path': dll
            }))
        await self.writer.drain()
        response = await self.reader.read(1460)
        return response

    async def vsd2005_stop_service(self, raw_service_id):
        service_id = (raw_service_id + '\x00').encode('utf-16le')

        self.writer.write(SHUTDOWN_PACKAGE_PKT_STRUCT.build({
                'guid': get_rand_guid(),
                'body_size': 4 + len(service_id),
                'service_id_size': len(service_id),
                'service_id': service_id,
            }))
        await self.writer.drain()
        response = await self.reader.read(1460)
        return response

    async def vsd2005_terminate_process(self, pid):
        self.writer.write(TERMINATE_PROCESS_PKT_STRUCT.build({
                'guid': get_rand_guid(),
                'body_size': 4,
                'pid': pid
            }))
        await self.writer.drain()
        response = await self.reader.read(1460)
        return response

    async def vsd2005_get_service_stream_id(self, raw_service_id):
        service_id = raw_service_id + '\x00'
        self.writer.write((GET_SERVICE_STREAM_ID_PKT_STRUCT.build({
            'guid': get_rand_guid(),
            'body_size': len(service_id.encode('utf-16le')) + 4,
            'content_size': len(service_id.encode('utf-16le')),
            'content': service_id.encode('utf-16le')
        })))
        response = await self.reader.read(1460)
        return response

    async def vsd2005_session(self):
        await self.vsd2005_handshake()
        await self.vsd2005_send_file('edm.exe', '%CSIDL_WINDOWS%\\edm.exe')
