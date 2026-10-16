"""Offline regression tests for the session-token security contract."""

import unittest
from unittest.mock import patch

from lib import settings


class SessionTokenSecurityTests(unittest.TestCase):
    def setUp(self):
        # Synthetic, distinct keys: never read a developer's env.json.
        self.config = {
            "user_config": {
                "user_secret": "test-only-user-key",
                "admin_secret": "test-only-admin-key",
                "session_secrets": {"user_max_age": 60, "admin_max_age": 10},
            }
        }
        self.load_env = patch.object(settings, "load_env", return_value=self.config)
        self.load_env.start()
        self.addCleanup(self.load_env.stop)
        # Control the signing clock, but use real signing and verification.
        self.clock = patch("itsdangerous.timed.time.time", return_value=1_700_000_000)
        self.now = self.clock.start()
        self.addCleanup(self.clock.stop)
        self.identity = "researcher@example.invalid"

    def test_valid_tokens_round_trip_for_each_role(self):
        for is_admin in (False, True):
            with self.subTest(is_admin=is_admin):
                token = settings.create_user_token(self.identity, is_admin=is_admin)
                self.assertEqual(settings.verify_token(token, is_admin=is_admin), self.identity)

    def test_tokens_cannot_cross_roles(self):
        for is_admin in (False, True):
            with self.subTest(is_admin=is_admin):
                token = settings.create_user_token(self.identity, is_admin=is_admin)
                self.assertIsNone(settings.verify_token(token, is_admin=not is_admin))

    def test_role_specific_expiry_boundaries(self):
        issued_at = self.now.return_value
        for is_admin, max_age in ((False, 60), (True, 10)):
            with self.subTest(is_admin=is_admin):
                self.now.return_value = issued_at
                token = settings.create_user_token(self.identity, is_admin=is_admin)
                self.now.return_value = issued_at + max_age
                self.assertEqual(settings.verify_token(token, is_admin=is_admin), self.identity)
                self.now.return_value += 1
                self.assertIsNone(settings.verify_token(token, is_admin=is_admin))

    def test_future_dated_tokens_are_rejected(self):
        for is_admin in (False, True):
            with self.subTest(is_admin=is_admin):
                issued_at = self.now.return_value
                token = settings.create_user_token(self.identity, is_admin=is_admin)
                self.now.return_value = issued_at - 1
                self.assertIsNone(settings.verify_token(token, is_admin=is_admin))
                self.now.return_value = issued_at

    def test_modified_payload_is_rejected(self):
        for is_admin in (False, True):
            with self.subTest(is_admin=is_admin):
                token = settings.create_user_token(self.identity, is_admin=is_admin)
                other = settings.create_user_token("someone-else@example.invalid", is_admin=is_admin)
                other_payload = other.rsplit(".", 2)[0]
                _, timestamp, signature = token.rsplit(".", 2)
                modified = ".".join((other_payload, timestamp, signature))
                self.assertIsNone(settings.verify_token(modified, is_admin=is_admin))

    def test_modified_signature_is_rejected(self):
        for is_admin in (False, True):
            with self.subTest(is_admin=is_admin):
                token = settings.create_user_token(self.identity, is_admin=is_admin)
                payload, timestamp, signature = token.rsplit(".", 2)
                replacement = "A" if signature[0] != "A" else "B"
                modified = ".".join((payload, timestamp, replacement + signature[1:]))
                self.assertIsNone(settings.verify_token(modified, is_admin=is_admin))

    def test_unsigned_payload_is_rejected(self):
        for is_admin in (False, True):
            with self.subTest(is_admin=is_admin):
                token = settings.create_user_token(self.identity, is_admin=is_admin)
                payload = token.rsplit(".", 2)[0]
                self.assertIsNone(settings.verify_token(payload, is_admin=is_admin))

    def test_tokens_signed_with_other_keys_are_rejected(self):
        for is_admin in (False, True):
            with self.subTest(is_admin=is_admin):
                token = settings.create_user_token(self.identity, is_admin=is_admin)
                changed_config = {
                    "user_config": {
                        **self.config["user_config"],
                        "user_secret": "different-test-only-user-key",
                        "admin_secret": "different-test-only-admin-key",
                    }
                }
                with patch.object(settings, "load_env", return_value=changed_config):
                    self.assertIsNone(settings.verify_token(token, is_admin=is_admin))

    def test_malformed_inputs_fail_closed(self):
        for is_admin in (False, True):
            for value in (None, "", "not-a-token", "a.b.c", 123, [], {}):
                with self.subTest(is_admin=is_admin, value=value):
                    self.assertIsNone(settings.verify_token(value, is_admin=is_admin))


if __name__ == "__main__":
    unittest.main()
