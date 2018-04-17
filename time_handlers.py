import logging
from util import *


def timer_create_entry_handler(syscall_id, syscall_object, pid):
    logging.debug("Entering the timer_create entry handler")
    if syscall_object.ret[0] == -1:
        raise NotImplementedError('Unsuccessful calls not implemented')
    else:
        # only SIGEV_NONE is supported as other sigevents can't be replicated as of now
        sigev_type = syscall_object.args[3].value.strip()
        logging.debug("Sigevent type: " + str(sigev_type))

        if sigev_type != 'SIGEV_NONE':
            raise NotImplementedError("Sigevent type %s is not supported" % (sigev_type))

        addr = cint.peek_register(pid, cint.EDX)
        logging.debug('timerid address: %x', addr)

        timerid = int(syscall_object.args[-1].value.strip('{}'))
        logging.debug(str(timerid))

        cint.populate_timer_t_structure(pid, addr, timerid);

        noop_current_syscall(pid)
        apply_return_conditions(pid, syscall_object)


def timer_extract_and_populate_itimerspec(syscall_object, pid, addr, start_index):
    logging.debug('Itimerspec Address: %x', addr)
    logging.debug('Extracting itimerspec')

    i = start_index
    interval_seconds = int(syscall_object.args[i].value.split("{")[2].strip())
    interval_nanoseconds = int(syscall_object.args[i+1].value.strip('{}'))        
    logging.debug('Interval Seconds: %d', interval_seconds)
    logging.debug('Interval Nanoseconds: %d', interval_nanoseconds)

    value_seconds = int(syscall_object.args[i+2].value.split("{")[1].strip())
    value_nanoseconds = int(syscall_object.args[i+3].value.strip('{}'))
    logging.debug('Value Seconds: %d', value_seconds)
    logging.debug('Value Nanoseconds: %d', value_nanoseconds)

    logging.debug('Populating itimerspec structure')
    cint.populate_itimerspec_structure(pid, addr,
                                       interval_seconds, interval_nanoseconds,
                                       value_seconds, value_nanoseconds)


def timer_settime_entry_handler(syscall_id, syscall_object, pid):

    logging.debug("Entering the timer_settime entry handler")
    if syscall_object.ret[0] == -1:
        raise NotImplementedError('Unsuccessful calls not implemented')
    else:
        logging.debug(str(syscall_object.args[-1]))
        OLD_value_present = syscall_object.args[-1].value != 'NULL'
        if old_value_present:
            logging.debug("Old value present, have to copy it into memory")

            addr = cint.peek_register(pid, cint.ESI)
            logging.debug('old_value address: %x', addr)

            itimerspec_starting_index = 6;
            timer_extract_and_populate_itimerspec(syscall_object, pid, addr, itimerspec_starting_index)

        noop_current_syscall(pid)
        apply_return_conditions(pid, syscall_object)


def timer_gettime_entry_handler(syscall_id, syscall_object, pid):
    logging.debug("Entering the timer_gettime entry handler")
    if syscall_object.ret[0] == -1:
        raise NotImplementedError('Unsuccessful calls not implemented')
    else:
        logging.debug('Got successful timer_gettime call')
        logging.debug('Replaying this system call')

        # these should be the same probably?
        timer_id_from_trace = int(syscall_object.args[0].value[0].strip('0x'))
        timer_id_from_execution = int(cint.peek_register(pid, cint.EBX))

        if timer_id_from_trace != timer_id_from_execution:
            raise ReplayDeltaError("Timer id ({}) from execution "
                                    "differs from trace ({})"
                                   .format(timer_id_from_execution, timer_id_from_trace))

        addr = cint.peek_register(pid, cint.ECX)
        itimerspec_starting_index = 1;
        timer_extract_and_populate_itimerspec(syscall_object, pid, addr, itimerspec_starting_index)
        noop_current_syscall(pid)
        apply_return_conditions(pid, syscall_object)


def timer_delete_entry_handler(syscall_id, syscall_object, pid):
    logging.debug("Entering the timer_delete entry handler")

    noop_current_syscall(pid)
    apply_return_conditions(pid, syscall_object)


def time_entry_handler(syscall_id, syscall_object, pid):
    """Replay Always
    Checks:
    Nothing
    Sets:
    return value: The time or -1 (error)
    0: The the value of the integer pointed to by 0, if not NULL
    errno

    Not Implemented:
    """
    logging.debug('Entering time entry handler')
    if syscall_object.ret[0] == -1:
        raise NotImplementedError('Unsuccessful calls not implemented')
    else:
        addr = cint.peek_register(pid, cint.EBX)
        noop_current_syscall(pid)
        logging.debug('Got successful time call')
        t = int(syscall_object.ret[0])
        logging.debug('time: %d', t)
        logging.debug('addr: %d', addr)
        if syscall_object.args[0].value != 'NULL' or addr != 0:
            logging.debug('Populating the time_t')
            cint.populate_unsigned_int(pid, addr, t)
        apply_return_conditions(pid, syscall_object)


def time_forger(pid):
    """Forge a time() call based on injected state
    Nothing
    Sets:
    return value: The time or -1 (error)
    0: The the value of the integer pointed to by 0, if not NULL
    errno

    Not Implemented:
    """

    logging.debug('Forging time call')
    t = cint.injected_state['time_call_results'][-1]
    times = cint.injected_state['time_call_results']
    new_t = t + _get_avg_time_result_delta(times)
    cint.injected_state['time_call_results'].append(new_t)
    syscall_object = lambda: None
    syscall_object.name = 'time'
    syscall_object.ret = []
    syscall_object.ret.append(t)
    addr = cint.peek_register(pid, cint.EBX)
    if addr != 0:
        cint.populate_unsigned_int(pid, addr, t)
    noop_current_syscall(pid)
    apply_return_conditions(pid, syscall_object)
    # Back up one system call we passed it when we decided to forge this
    # call
    cint.syscall_index -= 1


def gettimeofday_forger(pid):
    logging.debug('Forging gettimeofday call')
    timezone_addr = cint.peek_register(pid, cint.ECX)
    if timezone_addr != 0:
        raise NotImplementedError('Cannot forge gettimeofday() with a timezone')
    time_addr = cint.peek_register(pid, cint.EBX)
    seconds_times = [x['seconds']
                    for x in cint.injected_state['gettimeofdays']]
    microseconds_times = [x['microseconds']
                         for x in cint.injected_state['gettimeofdays']]
    seconds_delta = _get_avg_time_result_delta(seconds_times)
    microseconds_delta = _get_avg_time_result_delta(microseconds_times)
    last_seconds = cint.injected_state['gettimeofdays'][-1]['seconds']
    last_microseconds = cint.injected_state['gettimeofdays'][-1]['microseconds']
    seconds = last_seconds + seconds_delta
    microseconds = last_microseconds + microseconds_delta
    cint.injected_state['gettimeofdays'].append({'seconds': seconds,
                                                 'microseconds': microseconds})
    logging.debug('Using seconds: %d microseconds: %d', seconds, microseconds)
    syscall_object = lambda: None
    syscall_object.name = 'gettimeofday'
    syscall_object.ret = []
    syscall_object.ret.append(0)
    noop_current_syscall(pid)
    cint.populate_timeval_structure(pid, time_addr, seconds, microseconds)
    apply_return_conditions(pid, syscall_object)
    # Back up one system call we passed it when we decided to forge this
    # call
    cint.syscall_index -= 1


def _get_avg_time_result_delta(times):
    deltas = []
    for i, v in enumerate(times):
        if i == 0:
            continue
        deltas.append(times[i] - times[i-1])
    if len(deltas) == 0:
        # We don't have enough to do averages so start with 10
        return 1000
    return reduce(lambda x, y: x + y, deltas) / len(deltas)


def gettimeofday_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering gettimeofday entry handler')
    if syscall_object.ret[0] == -1:
        raise NotImplementedError('Unsuccessful calls not implemented')
    else:
        noop_current_syscall(pid)
        if syscall_object.args[2].value != 'NULL':
            raise NotImplementedError('time zones not implemented')
        addr = cint.peek_register(pid, cint.EBX)
        seconds = int(syscall_object.args[0].value.strip('{}'))
        microseconds = int(syscall_object.args[1].value.strip('{}'))
        logging.debug('Address: %x', addr)
        logging.debug('Seconds: %d', seconds)
        logging.debug('Microseconds: %d', microseconds)
        logging.debug('Populating timeval structure')
        cint.populate_timeval_structure(pid, addr, seconds, microseconds)
        apply_return_conditions(pid, syscall_object)




def clock_gettime_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering clock_gettime entry handler')
    if syscall_object.ret[0] == -1:
        raise NotImplementedError('Unsuccessful calls not implemented')
    else:
        logging.debug('Got successful clock_gettime call')
        logging.debug('Replaying this system call')
        noop_current_syscall(pid)
        clock_type_from_trace = syscall_object.args[0].value
        clock_type_from_execution = cint.peek_register(pid,
                                                              cint.EBX)
        # The first arg from execution must be CLOCK_MONOTONIC
        # The first arg from the trace must be CLOCK_MONOTONIC
        if clock_type_from_trace == 'CLOCK_MONOTONIC':
            if clock_type_from_execution != cint.CLOCK_MONOTONIC:
                raise ReplayDeltaError('Clock type ({}) from execution '
                                       'differs from trace'
                                       .format(clock_type_from_execution))
        if clock_type_from_trace == 'CLOCK_PROCESS_CPUTIME_ID':
            if clock_type_from_execution != cint.CLOCK_PROCESS_CPUTIME_ID:
                raise ReplayDeltaError('Clock type ({}) from execution '
                                       'differs from trace'
                                       .format(clock_type_from_execution))
        seconds = int(syscall_object.args[1].value.strip('{}'))
        nanoseconds = int(syscall_object.args[2].value.strip('{}'))
        addr = cint.peek_register(pid, cint.ECX)
        logging.debug('Seconds: %d', seconds)
        logging.debug('Nanoseconds: %d', nanoseconds)
        logging.debug('Address: %x', addr)
        logging.debug('Populating timespec strucutre')
        cint.populate_timespec_structure(pid, addr,
                                                seconds, nanoseconds)
        apply_return_conditions(pid, syscall_object)


def times_entry_handler(syscall_id, syscall_object, pid):
    """Always replay.
    Checks: nothing

    Sets: contents of the structure passed as a parameter
    errno

    Returns: clock_t time value or -1 (error)
    """

    logging.debug('Entering times entry handler')
    noop_current_syscall(pid)
    if syscall_object.args[0].value != 'NULL':
        logging.debug('Got times() call with out structure supplied')
        addr = cint.peek_register(pid, cint.EBX)
        utime = int(syscall_object.args[0].value.split('=')[1])
        logging.debug('utime: %d', utime)
        stime = int(syscall_object.args[1].value.split('=')[1])
        logging.debug('stime: %d', stime)
        cutime = int(syscall_object.args[2].value.split('=')[1])
        logging.debug('cutime: %d', cutime)
        cstime = int(syscall_object.args[3].value.split('=')[1].rstrip('}'))
        logging.debug('cstime: %d', cstime)
        cint.populate_tms_structure(pid, addr, utime, stime, cutime, cstime)
    apply_return_conditions(pid, syscall_object)


def utimensat_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering utimensat entry handler')
    validate_integer_argument(pid, syscall_object, 0, 0)
    if should_replay_based_on_fd(int(syscall_object.args[0].value)):
        noop_current_syscall(pid)
        logging.debug('Replaying this system call')
        timespec0_addr = cint.peek_register(pid, cint.EDX)
        timespec1_addr = timespec0_addr + 4
        logging.debug('Timespec 0 addr: %d', timespec0_addr)
        logging.debug('Timespec 1 addr: %d', timespec1_addr)
        timespec0_seconds = syscall_object.args[2].value
        timespec0_seconds = int(timespec0_seconds.strip('{}'))
        timespec0_nseconds = syscall_object.args[3].value[0]
        timespec0_nseconds = int(timespec0_nseconds.rstrip('}'))
        logging.debug('Timespec0 seconds: %d nseconds: %d',
                      timespec0_seconds,
                      timespec0_nseconds)
        timespec1_seconds = syscall_object.args[4].value
        timespec1_seconds = int(timespec1_seconds.strip('{}'))
        timespec1_nseconds = syscall_object.args[5].value
        timespec1_nseconds = int(timespec1_nseconds.rstrip('}'))
        logging.debug('Timespec1 seconds: %d nseconds: %d',
                      timespec1_seconds,
                      timespec1_nseconds)
        cint.populate_timespec_structure(pid,
                                                timespec0_addr,
                                                timespec0_seconds,
                                                timespec0_nseconds)
        cint.populate_timespec_structure(pid,
                                                timespec1_addr,
                                                timespec1_seconds,
                                                timespec1_nseconds)
        apply_return_conditions(pid, syscall_object)
    else:
        swap_trace_fd_to_execution_fd(pid, 0, syscall_object)
        logging.debug('Not replaying this system call')



def time_entry_debug_printer(pid, orig_eax, syscall_object):
    param = cint.peek_register(pid, cint.EBX)
    if param == 0:
        logging.debug('Time called with a NULL time_t')
    else:
        logging.debug('time_t addr: %d', param)
