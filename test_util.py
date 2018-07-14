"""
<Program Name>
  test_util

<Purpose>
  Provide tests for the functions collected in util.py

"""


import unittest
import mock
import bunch

import syscallreplay.util


class TestProcessIsAlive(unittest.TestCase):

    @mock.patch('os.kill')
    def test_process_does_not_exist(self, mock_kill):
        """Ensure returns False when process does not exist
        <Purpose>
          Ensure this function returns False when os.kill() indicates that the
          specified process does not exist by raising an OSError.

        """

        mock_kill.side_effect = OSError('Process does not exist')

        pid = 555
        signal_number = 0
        self.assertEqual(syscallreplay.util.process_is_alive(pid), False)
        mock_kill.assert_called_with(pid, signal_number)


    @mock.patch('os.kill')
    def test_process_exists(self, mock_kill):
        """Ensure returns True when process does not exist
        <Purpose>
          Ensure this function returns True when os.kill() indicates that the
          specified process is alive (i.e. kill(0) succeeds).

        """

        pid = 555
        signal_number = 0
        self.assertEqual(syscallreplay.util.process_is_alive(pid), True)
        mock_kill.assert_called_with(pid, signal_number)





class TestStringTimeToInt(unittest.TestCase):

    @mock.patch('logging.debug')
    def test_zero_strtime(self, mock_log):
        """Ensure '0' strtime returns 0
        <Purpose>
            Ensure that a string time of 0 passed in returns the int 0

        """
        strtime = '0'
        self.assertEqual(syscallreplay.util.string_time_to_int(strtime), 0)
        mock_log.assert_called()


    @mock.patch('logging.debug')
    @mock.patch('__builtin__.int')
    @mock.patch('time.mktime')
    @mock.patch('time.strptime')
    def test_nonzero_strtime(self, mock_strptime, mock_mktime, mock_int, mock_log):
        strtime = '2001/01/01-01:01:01'
        strptime_format = '%Y/%m/%d-%H:%M:%S'
        strptime_return_value = mock.Mock(tm_year=2001,
                                          tm_mon=1,
                                          tm_mday=1,
                                          tm_hour=1,
                                          tm_min=1,
                                          tm_sec=1,
                                          tm_wday=0,
                                          tm_yday=1,
                                          tm_isdst=1)
        mktime_return_value = 97833961.0
        int_return_value = 97833961

        mock_strptime.return_value = strptime_return_value
        mock_mktime.return_value = mktime_return_value
        mock_int.return_value = int_return_value

        self.assertEqual(syscallreplay.util.string_time_to_int(strtime), int_return_value)

        mock_log.assert_called()
        mock_strptime.assert_called_with(strtime, strptime_format)
        mock_mktime.assert_called_with(strptime_return_value)
        mock_int.assert_called_with(mktime_return_value)
