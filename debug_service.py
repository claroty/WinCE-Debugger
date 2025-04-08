import os
import re
import struct
import hashlib
import asyncio
import argparse
import nest_asyncio
nest_asyncio.apply()

from async_core import VSD2005Session


async def session(ip, port, target):
    vsd2005_session = VSD2005Session(ip, port)
    await vsd2005_session.vsd2005_session()
    # await vsd2005_session.vsd2005_send_hot_patched_exe(target, '%CSIDL_WINDOWS%\\target.exe\x00')
    await vsd2005_session.vsd2005_send_file(target, '%CSIDL_WINDOWS%\\target.exe\x00')

    while True:
        UNIQ_EDM_SERVICE_ID = 'AEF7671F-A8D6-4E27-8B83-6C3E44425B6E\x00'
        REMOTE_EDM_EXE_PATH = '%CSIDL_WINDOWS%\\edm.exe\x00'
        REMOTE_EDM_DLL_PATH = '%CSIDL_WINDOWS%\\edbgtl.dll\x00'
        await vsd2005_session.vsd2005_start_service(UNIQ_EDM_SERVICE_ID, REMOTE_EDM_EXE_PATH, REMOTE_EDM_DLL_PATH)
        response = await vsd2005_session.vsd2005_get_service_stream_id(UNIQ_EDM_SERVICE_ID)       
        print(int(response.decode('utf-16le').split('=')[-1].rstrip('\x00'), 10))

        # UNIQ_TARGET_SERVICE_ID = 'AEF7671F-A8D6-4E27-8B83-6C3E44425B6A\x00'
        # REMOTE_TARGET_EXE_PATH = '%CSIDL_WINDOWS%\\target.exe\x00'
        # await vsd2005_session.vsd2005_start_service(UNIQ_TARGET_SERVICE_ID, REMOTE_TARGET_EXE_PATH, '')

        cmd = input()
        if cmd == 'q':
            break     
        # else:
        #     await vsd2005_session.vsd2005_stop_service(UNIQ_TARGET_SERVICE_ID)
            
            
def main():
    argparser = argparse.ArgumentParser()
    argparser.add_argument('--ip', default='192.168.56.101')
    argparser.add_argument('--port', default=9999)
    argparser.add_argument('--target', default='T82_WINCE.exe')
    args = argparser.parse_args()

    loop = asyncio.get_event_loop()
    loop.run_until_complete(session(args.ip, args.port, args.target))


if __name__ == "__main__":
    main()
