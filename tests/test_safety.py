from __future__ import annotations

import unittest

from continuum.core.safety import (
    redact_text_secrets,
    redact_value_secrets,
    scan_text_for_entropy_secrets,
    scan_text_for_secrets,
    scan_value_for_secrets,
)


class EpicContinuumSafetyTest(unittest.TestCase):
    def test_known_secret_patterns_are_detected_and_redacted(self) -> None:
        samples = {
            "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----",
            "openai_key": "sk-" + "A" * 24,
            "github_token": "ghp_" + "A" * 36,
            "gitlab_token": "glpat-" + "A" * 24,
            "huggingface_token": "hf_" + "A" * 24,
            "slack_token": "xoxb-" + "A" * 24,
            "stripe_key": "sk_live_" + "A" * 24,
            "google_api_key": "AIza" + "A" * 35,
            "bearer_token": "Bearer " + "A" * 24,
            "aws_access_key": "AKIA" + "A" * 16,
            "secret_assignment": "OPENAI_API_KEY=" + "A" * 20,
        }
        for expected_type, sample in samples.items():
            with self.subTest(expected_type=expected_type):
                findings = scan_text_for_secrets(sample)
                self.assertTrue(any(finding["type"] == expected_type for finding in findings), findings)
                self.assertNotIn(sample, redact_text_secrets(sample))

    def test_short_sensitive_assignment_marks_bruteforceable_hash_risk(self) -> None:
        findings = scan_text_for_secrets("client_secret: short")

        self.assertEqual(findings[0]["type"], "sensitive_key_assignment")
        self.assertIn("secret_hash", findings[0])
        self.assertEqual(findings[0]["secret_hash_risk"], "low_entropy_secret_value")

    def test_redacted_placeholders_do_not_create_findings(self) -> None:
        text = "OPENAI_API_KEY=[REDACTED]\nclient_secret: [REDACTED]\n"

        self.assertEqual(scan_text_for_secrets(text), [])

    def test_nested_sensitive_values_are_redacted_and_scanned(self) -> None:
        payload = {"safe": {"token_budget": 900}, "auth": {"api_key": "supersecretvalue123"}}

        findings = scan_value_for_secrets(payload, scope="unit")
        redacted = redact_value_secrets(payload)

        self.assertTrue(any(finding["type"] == "sensitive_metadata_key" for finding in findings), findings)
        self.assertEqual(redacted["auth"]["api_key"], "[REDACTED]")
        self.assertEqual(redacted["safe"]["token_budget"], 900)

    def test_entropy_scanner_detects_only_high_entropy_long_tokens(self) -> None:
        token = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0"

        findings = scan_text_for_entropy_secrets(f"opaque={token}\nplain={'a' * 48}\n")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["type"], "high_entropy_token")
        self.assertIn("secret_hash", findings[0])
        self.assertGreater(findings[0]["entropy"], 4.0)


if __name__ == "__main__":
    unittest.main()
