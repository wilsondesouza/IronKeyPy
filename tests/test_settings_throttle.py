"""Testes de preferências e de proteção contra força bruta local."""

import os
import tempfile
import time
import unittest

from services.login_throttle import LoginThrottle
from services.settings import Settings


class SettingsTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "settings.json")

    def test_roundtrip(self):
        settings = Settings.load(self.path)
        settings.auto_lock_seconds = 120
        settings.appearance_mode = "light"
        settings.save(self.path)

        self.assertEqual(Settings.load(self.path).auto_lock_seconds, 120)
        self.assertEqual(Settings.load(self.path).appearance_mode, "light")

    def test_corrupt_file_falls_back_to_defaults(self):
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("{ não é json")
        self.assertEqual(Settings.load(self.path).auto_lock_seconds, 300)

    def test_unsafe_values_are_clamped(self):
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write('{"auto_lock_seconds": 999999, "max_unlock_attempts": 1,'
                     ' "appearance_mode": "hacker", "default_length": 2}')
        settings = Settings.load(self.path)
        self.assertLessEqual(settings.auto_lock_seconds, 24 * 3600)
        self.assertGreaterEqual(settings.max_unlock_attempts, 3)
        self.assertEqual(settings.appearance_mode, "dark")
        self.assertGreaterEqual(settings.default_length, 8)

    def test_unknown_keys_ignored(self):
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write('{"__class__": "evil", "auto_lock_seconds": 60}')
        self.assertEqual(Settings.load(self.path).auto_lock_seconds, 60)


class ThrottleTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "state.json")

    def test_lockout_after_max_attempts(self):
        throttle = LoginThrottle(max_attempts=3, path=self.path)
        self.assertTrue(throttle.status().allowed)

        self.assertTrue(throttle.register_failure().allowed)
        self.assertTrue(throttle.register_failure().allowed)
        blocked = throttle.register_failure()
        self.assertFalse(blocked.allowed)
        self.assertGreater(blocked.wait_seconds, 0)
        self.assertIn("Aguarde", blocked.message)

    def test_backoff_is_exponential(self):
        throttle = LoginThrottle(max_attempts=3, path=self.path)
        delays = []
        for _ in range(3):
            for _ in range(2):
                throttle.register_failure()
            delays.append(throttle.register_failure().wait_seconds)
            throttle._state["locked_until"] = 0     # libera para o próximo ciclo
        self.assertLess(delays[0], delays[1])
        self.assertLess(delays[1], delays[2])

    def test_state_persists_between_sessions(self):
        LoginThrottle(max_attempts=3, path=self.path).register_failure()
        self.assertEqual(LoginThrottle(max_attempts=3, path=self.path).status().remaining_attempts, 2)

    def test_success_resets(self):
        throttle = LoginThrottle(max_attempts=3, path=self.path)
        throttle.register_failure()
        throttle.register_success()
        self.assertEqual(throttle.status().remaining_attempts, 3)
        self.assertIsNotNone(throttle.last_success())

    def test_lock_expires(self):
        throttle = LoginThrottle(max_attempts=3, path=self.path)
        for _ in range(3):
            throttle.register_failure()
        throttle._state["locked_until"] = time.time() - 1
        self.assertTrue(throttle.status().allowed)


if __name__ == "__main__":
    unittest.main()
