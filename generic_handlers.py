"""Generic handlers
"""

import logging

from errno_dict import ERRNO_CODES

from util import (ReplayDeltaError,
                  logging,
                  cint,
                  noop_current_syscall,
                  cleanup_return_value,
                  apply_return_conditions,)


def syscall_return_success_handler(syscall_id, syscall_object, pid):
    """Generic handler that does two things:
    1. Noop out the current system call
    2. Sets the return value from the current syscall_object
    Checks:
    Nothing

    Sets:
    return value: The return value specified in syscall_object
        (added as replay file descriptor)
    errno

    """

    logging.debug('Using default "return success" handler')
    noop_current_syscall(pid)
    apply_return_conditions(pid, syscall_object)


def check_return_value_entry_handler(syscall_id, syscall_object, pid):
    """Generic handler that works in concert with
    check_return_value_exit_handler to check whether the return value from
    allowing a system call to pass through matches the system call recorded
    for the same system call in syscall_object.
    Checks:
    Nothing

    Sets:
    Nothing

    """
    logging.debug('check_return_value entry handler')
    logging.debug('Letting system call {}: {} pass through'
                  .format(syscall_id, syscall_object.name))


def check_return_value_exit_handler(syscall_id, syscall_object, pid):
    """Generic handler that works with
    check_return_value_entry_handler to check whether the return value from
    allowing a system call to pass through matches the system call recorded
    for the same system call in syscall_object.  This is where the actual
    checking happens
    Checks:
    The return value from syscall execution

    Sets:
    Nothing

    """
    logging.debug('check_return_value exit handler')
    ret_from_execution = cint.peek_register(pid, cint.EAX)
    ret_from_trace = cleanup_return_value(syscall_object.ret[0])
    logging.debug('Return value from execution %x', ret_from_execution)
    logging.debug('Return value from trace %x', ret_from_trace)
    # HACK HACK HACK
    if syscall_object.ret[1] is not None:
        logging.debug('We have an errno code')
        logging.debug('Errno code: %s', syscall_object.ret[1])
        errno_retval = -1 * ERRNO_CODES[syscall_object.ret[1]]
        logging.debug('Errno ret_val: %d', errno_retval)
        if errno_retval == ret_from_execution:
            return
    if ret_from_execution < 0:
        ret_from_execution &= 0xffffffff
    if ret_from_execution != ret_from_trace:
        raise ReplayDeltaError('Return value from execution ({}, {:02x}) differs '
                        'from return value from trace ({}, {:02x})'
                        .format(ret_from_execution,
                                ret_from_execution,
                                ret_from_trace,
                                ret_from_trace))
