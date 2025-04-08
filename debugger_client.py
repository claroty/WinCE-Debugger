import argparse

from app import *


def parse_args():
    args_parser = argparse.ArgumentParser()
    args_parser.add_argument('--ip', '-i', help='Debugger server IP', default='192.168.56.101')
    args_parser.add_argument('--port', '-p', help='Debugger server port', default='6510')
    args_parser.add_argument('--target', '-t', help='Debugger remote target application', default=None)
    args_parser.add_argument('--executable', '-e', help='Debugger target executable', default=None)
    return args_parser.parse_args()

def main():
    args = parse_args()
    app = DebuggerApp(args.ip, args.port, args.target, args.executable)
    try:
        app.run()
    except KeboardInterrupt:
        app.exit()
        exit(0)

if __name__ == '__main__':
    main()