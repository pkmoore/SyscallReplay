# pylint: disable=no-self-use
"""Tests for generic system call handlers
"""


import unittest
import mock
from bunch import Bunch
from syscallreplay.generic_handlers import syscall_return_success_handler
from syscallreplay.generic_handlers import check_return_value_entry_handler
from syscallreplay.generic_handlers import check_return_value_exit_handler


class TestSyscallReturnSuccessHandler(unittest.TestCase):
    """Tests for syscall_return_success_handler
    """

    @mock.patch('syscallreplay.generic_handlers.noop_current_syscall')
    @mock.patch('syscallreplay.generic_handlers.apply_return_conditions')
    @mock.patch('logging.debug')
    def test_happy_case(self, mock_log, mock_apply, mock_noop):
        """Ensure noop_current_syscall and apply_return_conditions
        Ensure syscall_return_success_handler noops the current system call and
        appropriately applies return conditions

        Notes: generic_handlers uses a relative import to pull
        noop_current_syscall and apply_return_conditions directly into its
        namespace.  This is why we are mocking
        syscallreplay.generic_handlers.<whatever> rather than
        syscallreplay.util.<whatever>
        """

        syscall_id = 4
        syscall_object = Bunch()
        pid = 555
        syscall_return_success_handler(syscall_id, syscall_object, pid)
        #  We don't want to hard code in the debug message here in case it
        #  changes
        mock_log.assert_called()
        mock_noop.assert_called_with(pid)
        mock_apply.assert_called_with(pid, syscall_object)


class TestCheckReturnValueEntryHandler(unittest.TestCase):
    """Tests for check_return_value_entry_handler
    """

    @mock.patch('logging.debug')
    def test_ensure_logging_done(self, mock_log):
        """Ensure logging happens
        This handler pretty much just reports that it was called for logging
        purposes.  All we test for is that this logging was done.
        """

        syscall_id = 4
        syscall_object = Bunch()
        syscall_object.name = 'write'
        pid = 555
        check_return_value_entry_handler(syscall_id, syscall_object, pid)
        mock_log.assert_called()


class TestCheckReturnValueExitHandler(unittest.TestCase):
    """Tests for check_return_value_exit_handler
    """

    @mock.patch('syscallreplay.generic_handlers.cleanup_return_value',
                return_value=4)
    @mock.patch('syscallreplay.generic_handlers.cint')
    @mock.patch('logging.debug')
    def test_return_values_match(self,
                                 mock_log,
                                 mock_cint,
                                 mock_clean):
        """Ensure equal return values pass don't raise
        """

        mock_cint.EAX = 4
        mock_cint.peek_register = mock.Mock(return_value=4)

        syscall_id = 4
        syscall_object = Bunch()
        syscall_object.ret = (1, None)
        pid = 555
        check_return_value_exit_handler(syscall_id, syscall_object, pid)
        mock_clean.assert_called_with(syscall_object.ret[0])
        mock_cint.peek_register.assert_called_with(pid, mock_cint.EAX)
        mock_log.assert_called()
