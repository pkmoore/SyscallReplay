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
