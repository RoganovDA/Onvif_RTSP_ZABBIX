import unittest

from onvif_utils import _classify_category


class ClassifyCategoryTests(unittest.TestCase):
    def test_security_token_fault_is_unauthorized(self):
        message = "The security token could not be authenticated or authorized"
        self.assertEqual(
            _classify_category(None, message, exc=None),
            "unauthorized",
        )

    def test_fault_code_failed_authentication_is_unauthorized(self):
        class DummyFault:
            def __init__(self):
                self.code = "wsse:FailedAuthentication"

        dummy = DummyFault()
        self.assertEqual(
            _classify_category(None, "", exc=dummy),
            "unauthorized",
        )


if __name__ == "__main__":
    unittest.main()
