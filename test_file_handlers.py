
"""
<Program Name>
  syscallreplay

<Purpose>
  Provide functions necessary for examining posix-omni-parser provided system
  call objects and writing them into the memory of a process using some
  interface.  Right now this interface is uses ptrace and is provided by the
  syscallreplay CPython extension.

"""


import unittest
import mock
import bunch

import syscallreplay.file_handlers


class TestReadlinkEntryHandler(unittest.TestCase):


  @mock.patch('syscallreplay.file_handlers.noop_current_syscall')
  @mock.patch('syscallreplay.file_handlers.cleanup_quotes', return_value='test_filename.txt')
  @mock.patch('syscallreplay.file_handlers.cint')
  @mock.patch('syscallreplay.file_handlers.apply_return_conditions')
  @mock.patch('logging.debug')
  def test_readlink_happy_case(self, mock_log, mock_apply, mock_cint, mock_cleanup, mock_noop):
    """ Test that the readlink entry handler works under usual conditions

    """

    mock_cint.EBX = 5
    mock_cint.ECX = 6
    mock_cint.ORIG_EAX = 1
    def _peek_register(pid, reg):
      # fake filename buffer
      if reg == mock_cint.EBX:
        return 6666
      # fake output buffer
      if reg == mock_cint.ECX:
        return 7777
    mock_cint.peek_register = mock.Mock(side_effect=_peek_register)
    mock_populate_char_buffer = mock.Mock()
    mock_cint.copy_string = mock.Mock(return_value='test_filename.txt')

    syscall_id = 85
    syscall_object = bunch.Bunch()
    syscall_object.args = [None, None, None]
    arg0_obj = bunch.Bunch()
    arg0_obj.value = '\"test_filename.txt\"'
    syscall_object.args[0] = arg0_obj
    arg1_obj = bunch.Bunch()
    arg1_obj.value = '\"test_filename.txt\"'
    syscall_object.args[1] = arg1_obj
    syscall_object.ret = (0,)
    pid = 555
    #  We don't want to hard code in the debug message here in case it
    #  changes
    syscallreplay.file_handlers.readlink_entry_handler(syscall_id, syscall_object, pid)
    mock_log.assert_called()
    mock_noop.assert_called_with(pid)

    peek_register_calls = [mock.call(pid, mock_cint.EBX), mock.call(pid, mock_cint.ECX)]
    mock_cint.peek_register.assert_has_calls(peek_register_calls)
    mock_cleanup.assert_called_with('"test_filename.txt"')
    mock_cint.populate_char_buffer.assert_called_with(pid, 7777, 'test_filename.txt')
    mock_apply.assert_called_with(pid, syscall_object)
