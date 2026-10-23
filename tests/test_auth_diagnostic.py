from t7manager import protocol
from t7manager.cli import i18n
from t7manager.cli import output
from t7manager.operations import unlock as unlock_ops
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import dataclasses

from test_single_native import INFO

class Tests(unittest.TestCase):
    def test_values_are_not_disclosed(self):
        secret=b'private-password'
        response=protocol.Response(4100,0,0,'method',1,(secret,987654321,('control',240)))
        result=protocol.auth_failure_diagnostic(response,2048)
        encoded=json.dumps(result)
        self.assertNotIn(secret.decode(),encoded)
        self.assertNotIn('987654321',encoded)
        self.assertNotIn('240',encoded)
        self.assertEqual(result['token_shapes'],[{'kind':'bytes','length':16},{'kind':'integer'},{'kind':'control'}])
        self.assertEqual(result['recovery_exclusion_reasons'],['unsupported_return_tokens'])

    def test_supported_shape_has_no_exclusions(self):
        result=protocol.auth_failure_diagnostic(protocol.Response(4100,0,0,'method',1,()),2048)
        self.assertEqual(result['recovery_exclusion_reasons'],[])

    def test_sync_session_comparisons_do_not_accept_rejection(self):
        values=(('control',248),bytes.fromhex('00000000000000ff'),bytes.fromhex('000000000000ff03'),('control',240),1,0,('control',241),('control',249))
        response=protocol.Response(4100,0,0,'method',1,values)
        result=protocol.auth_failure_diagnostic(response,2048)
        self.assertEqual(result['recovery_exclusion_reasons'],[])
        self.assertTrue(protocol.supported_auth_rejection(response,2048))
        checks=result['sync_session_checks']
        self.assertTrue(checks['control_tokens_match'])
        self.assertTrue(checks['sync_session_uid_match'])
        self.assertTrue(checks['host_session_matches_request'])
        self.assertTrue(checks['device_session_zero'])
        self.assertFalse(checks['device_session_positive_uint32'])
        for index,bad,key in [(0,('control',241),'control_tokens_match'),(1,b'PASSWORD','invoking_uid_match'),(2,b'PASSWORD','sync_session_uid_match'),(4,True,'session_values_uint32'),(5,2**32,'session_values_uint32')]:
            altered=list(values);altered[index]=bad
            r=dataclasses.replace(response,values=tuple(altered))
            self.assertFalse(protocol.sync_session_checks(r)[key])
            self.assertFalse(protocol.supported_auth_rejection(r,2048))
        for count in range(8):
            self.assertFalse(protocol.sync_session_checks(dataclasses.replace(response,values=values[:count]))['eight_tokens'])
