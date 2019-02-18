"""
<Program Name>
  test_populate_char_buffer

<Purpose>

Tests that ensure the C extension populate_char_buffer function correctly
copies data into a child process.

"""

from __future__ import print_function
import ctypes
import os
import time
import syscallreplay.syscallreplay as sr
import signal
import unittest
import mock

TEST_STRING = 'This is a \"test string\"'

class TestPopulateCharBuffer(unittest.TestCase):
  def test_readlink_happy_case(self):
    """ Ensure test data is correctly copied into a child process via ptrace

    """

    # Allocate a buffer big enough for the test string.  This will exist
    # post-fork so we can populate it with the string and read it back.
    libc = ctypes.CDLL('libc.so.6')
    alloc_f = libc.malloc
    alloc_f.restype = ctypes.c_void_p
    alloc_f.argtypes = [ctypes.c_uint]
    addr = alloc_f(ctypes.c_uint(len(TEST_STRING) + 1))

    pid = os.fork()

    if pid == 0:
        sr.traceme()
        while True:
            pass
    else:
        sr.attach(pid)
        sr.waitpid(pid)
        sr.populate_char_buffer(pid, addr, TEST_STRING)
        string_read_back = sr.copy_string(pid, addr)
        sr.detach(pid)
        os.kill(pid, signal.SIGKILL)
        self.assertEqual(TEST_STRING, string_read_back)
