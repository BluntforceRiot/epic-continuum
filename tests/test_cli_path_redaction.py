from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from continuum.cli import main as cli_main
from continuum.cli import redact_cli_error_message
from continuum.core.store import init_db


class CliPathRedactionTest(unittest.TestCase):
    def test_standalone_slashes_and_operators_are_not_redacted(self) -> None:
        for message in (
            "expected / or \\ separator",
            "ratio must be numerator / denominator",
            "ratio numerator / denominator",
            "division assignment uses /= here",
            "glob operator /* is unsupported",
            'formula "numerator / denominator / result"',
        ):
            with self.subTest(message=message):
                self.assertEqual(redact_cli_error_message(message), message)

    def test_credible_posix_path_controls_remain_redacted(self) -> None:
        cases = (
            ("failed /private/secret.txt", "failed <redacted-path:secret.txt>"),
            ("failed /x/secret.txt", "failed <redacted-path:secret.txt>"),
            ("failed /0/secret.txt", "failed <redacted-path:secret.txt>"),
            (
                "failed '/private folder/secret.txt'; retry",
                "failed '<redacted-path:secret.txt>'; retry",
            ),
            ('failed "/+private/secret.txt"', 'failed "<redacted-path:secret.txt>"'),
            (
                'failed "/ Private Folder/secret.txt"',
                'failed "<redacted-path:secret.txt>"',
            ),
            ("failed ///private/secret.txt", "failed <redacted-path:secret.txt>"),
            ("path:/home/Jane Doe/Private Data", "path:<redacted-path>"),
            ("failed file:///Private Folder/secret.txt", "failed file:<redacted-path>"),
            ("failed file:///%20Private/secret.txt", "failed file:<redacted-path:secret.txt>"),
            ("failed file:////private/secret.txt", "failed file:<redacted-path:secret.txt>"),
            (
                'failed "file://// Private Folder/secret.txt"',
                'failed "<redacted-path>"',
            ),
        )
        for message, expected in cases:
            with self.subTest(message=message):
                self.assertEqual(redact_cli_error_message(message), expected)

        uri = "endpoint https://example.com/status unavailable"
        self.assertEqual(redact_cli_error_message(uri), uri)

    def test_spaced_directory_and_filename_matrix(self) -> None:
        quoted_cases = (
            (
                'failed "C:\\Private Folder\\Sensitive Final Name.txt"; retry later.',
                "Sensitive Final Name.txt",
            ),
            (
                "failed '/private folder/Sensitive Final Name.txt'; retry later.",
                "Sensitive Final Name.txt",
            ),
        )
        for message, leaf in quoted_cases:
            with self.subTest(message=message):
                redacted = redact_cli_error_message(message)
                self.assertIn(f"<redacted-path:{leaf}>", redacted)
                self.assertTrue(redacted.endswith("; retry later."), redacted)
                self.assertNotIn("Private Folder", redacted)
                self.assertNotIn("private folder", redacted)

        unquoted_cases = (
            "failed C:\\Private Folder\\Sensitive Final Name.txt; retry later.",
            "failed /private folder/Sensitive Final Name.txt; retry later.",
        )
        for message in unquoted_cases:
            with self.subTest(message=message):
                self.assertEqual(
                    redact_cli_error_message(message),
                    "failed <redacted-path>",
                )

    def test_quoted_absolute_paths_with_spaces_preserve_only_safe_leaf_and_prose(self) -> None:
        cases = (
            ('failed "C:\\Private Folder\\sensitive-name.txt"; retry later.', "sensitive-name.txt"),
            ("failed '/private folder/sensitive-name.txt'; retry later.", "sensitive-name.txt"),
            ('failed "\\\\server\\Private Folder\\sensitive-name.txt"; retry later.', "sensitive-name.txt"),
            ('failed "\\\\?\\C:\\Private Folder\\sensitive-name.txt"; retry later.', "sensitive-name.txt"),
            ('failed "\\\\?\\UNC\\server\\Private Folder\\sensitive-name.txt"; retry later.', "sensitive-name.txt"),
        )
        for message, leaf in cases:
            with self.subTest(message=message):
                redacted = redact_cli_error_message(message)
                self.assertIn(f"<redacted-path:{leaf}>", redacted)
                self.assertTrue(redacted.endswith("; retry later."), redacted)
                self.assertNotIn("Private Folder", redacted)
                self.assertNotIn("server", redacted)

    def test_unquoted_space_is_ambiguous_and_consumes_only_that_line(self) -> None:
        cases = (
            "failed C:\\Private Folder\\sensitive-name.txt; retry later.",
            "failed /private folder/sensitive-name.txt; retry later.",
            "failed \\\\server\\Private Folder\\sensitive-name.txt; retry later.",
            "failed \\\\?\\C:\\Private Folder\\sensitive-name.txt; retry later.",
        )
        for message in cases:
            with self.subTest(message=message):
                redacted = redact_cli_error_message(message + "\nsecond line remains")
                self.assertEqual(redacted, "failed <redacted-path>\nsecond line remains")
                self.assertNotIn("sensitive-name", redacted)
                self.assertNotIn("retry later", redacted)

    def test_unambiguous_unquoted_path_keeps_sanitized_leaf_and_punctuation(self) -> None:
        redacted = redact_cli_error_message(
            "failed C:\\private\\sensitive-name.txt)."
        )
        self.assertEqual(redacted, "failed <redacted-path:sensitive-name.txt>).")

    def test_urls_and_relative_text_are_not_misclassified_as_absolute_paths(self) -> None:
        message = "URL https://example.com/path and relative Private Folder/file.txt"
        self.assertEqual(redact_cli_error_message(message), message)

    def test_authority_uris_preserve_ipv6_but_diagnostic_labels_do_not(self) -> None:
        for uri in (
            "https://example.com/v1/status",
            "https://[::1]/v1/status",
            "https://[fe80::1%25eth0]/v1/status",
            "https://[fe80::1%25eth%2D0]/v1/status",
            "https://[v1.fe80::abcd]/v1/status",
            "https://[v1.a'b]/status",
            "https://example.com/O'Reilly/private",
            "'https://[v1.a'b]/status'",
        ):
            with self.subTest(uri=uri):
                message = f"endpoint {uri} unavailable"
                self.assertEqual(redact_cli_error_message(message), message)

        diagnostic_cases = (
            ("path:/home/Jane Doe/Private Data", "path:<redacted-path>"),
            ("root:/srv/Private Folder/item", "root:<redacted-path>"),
        )
        for message, expected in diagnostic_cases:
            with self.subTest(message=message):
                self.assertEqual(redact_cli_error_message(message), expected)

    def test_escaped_quote_in_spaced_final_component_is_conservative(self) -> None:
        message = (
            r'failed "C:\Private Folder\Final \"Quoted Name\".txt"; retry later.'
        )
        redacted = redact_cli_error_message(message)
        self.assertEqual(redacted, 'failed "<redacted-path>"; retry later.')
        self.assertNotIn("Private Folder", redacted)
        self.assertNotIn("Quoted Name", redacted)

    def test_windows_rooted_and_nt_namespace_paths_are_redacted(self) -> None:
        cases = (
            (r"failed \Users\Jane Doe\Private Data", "failed <redacted-path>"),
            (r"failed \Program Files (x86)\Secret Data", "failed <redacted-path>"),
            (r"failed \$Recycle.Bin\Private Data", "failed <redacted-path>"),
            (r"failed \用户\秘密", "failed <redacted-path:秘密>"),
            (r"failed \Device\HarddiskVolume3\Users\Jane Doe\Private Data", "failed <redacted-path>"),
            (r"failed \SystemRoot\Temp Folder\Private Data", "failed <redacted-path>"),
            (r"failed \??\UNC\server\share\Jane Doe\Private Data", "failed <redacted-path>"),
            (r"failed \DosDevices\C:\Users\Jane Doe\Private Data", "failed <redacted-path>"),
        )
        for message, expected in cases:
            with self.subTest(message=message):
                self.assertEqual(redact_cli_error_message(message), expected)

        quoted = r'failed "\Users\Jane Doe\Private Final Name.txt"; retry later.'
        redacted = redact_cli_error_message(quoted)
        self.assertEqual(
            redacted,
            'failed "<redacted-path:Private Final Name.txt>"; retry later.',
        )
        self.assertNotIn("Jane Doe", redacted)

    def test_ambiguous_backslash_diagnostics_are_not_treated_as_rooted_paths(self) -> None:
        for message in (
            r"invalid regex \d+",
            r"invalid regex \d\s",
            r"invalid escape \q",
            r"invalid escapes \q and \d",
            r"invalid regex \a\b",
            r"invalid regex \d+\s",
            r"invalid regex \w*\d",
            r"invalid regex \d+\+\d+",
            r"invalid regex \w+\-\w+",
        ):
            with self.subTest(message=message):
                self.assertEqual(redact_cli_error_message(message), message)

    def test_relative_components_are_not_promoted_to_absolute_paths(self) -> None:
        for message in (
            r"relative Folder (old)\Private\file.txt",
            r"relative 用户\秘密\file.txt",
            "relative Folder (old)/Private/file.txt",
        ):
            with self.subTest(message=message):
                self.assertEqual(redact_cli_error_message(message), message)

    def test_mixed_separator_windows_rooted_paths_are_redacted(self) -> None:
        for message in (r"failed \Users/Jane\Private", r"failed \Users/Jane/Private"):
            with self.subTest(message=message):
                self.assertIn("<redacted-path", redact_cli_error_message(message))

    def test_outer_single_quote_ignores_apostrophe_inside_uri(self) -> None:
        message = "endpoint 'https://[v1.a'b]/status' unavailable"
        self.assertEqual(redact_cli_error_message(message), message)

    def test_uri_span_stops_before_compact_local_path_field(self) -> None:
        cases = (
            (
                r"endpoint=https://example.com/status;path=C:\Private Folder\secret.txt",
                "endpoint=https://example.com/status;path=<redacted-path>",
            ),
            (
                "endpoint=https://example.com/status,path=/private/secret.txt",
                "endpoint=https://example.com/status,path=<redacted-path:secret.txt>",
            ),
            (
                "endpoint=https://example.com/status|root=C:/Private/secret.txt",
                "endpoint=https://example.com/status|root=<redacted-path:secret.txt>",
            ),
            (
                "endpoint='https://[v1.a'b]/status',path=C:/Private/secret.txt",
                "endpoint='https://[v1.a'b]/status',path=<redacted-path:secret.txt>",
            ),
            (
                "endpoint=https://example.com/status,file=/private/secret.txt",
                "endpoint=https://example.com/status,file=<redacted-path:secret.txt>",
            ),
            (
                "endpoint=https://example.com/status;cwd=/private/secret.txt",
                "endpoint=https://example.com/status;cwd=<redacted-path:secret.txt>",
            ),
            (
                "endpoint=https://example.com/status|source=C:/Private/secret.txt",
                "endpoint=https://example.com/status|source=<redacted-path:secret.txt>",
            ),
            (
                "endpoint=https://example.com/status,file='/private/secret.txt'",
                "endpoint=https://example.com/status,file='<redacted-path:secret.txt>'",
            ),
            (
                "endpoint=https://example.com/status,artifact=file:///%20Private/secret.txt",
                "endpoint=https://example.com/status,artifact=file:<redacted-path:secret.txt>",
            ),
            (
                "endpoint='https://[v1.a'b]/status',file=/private/secret.txt",
                "endpoint='https://[v1.a'b]/status',file=<redacted-path:secret.txt>",
            ),
            (
                "endpoint=https://example.com/status,file='/ Private Folder/secret.txt'",
                "endpoint=https://example.com/status,file='<redacted-path:secret.txt>'",
            ),
            (
                "endpoint=https://example.com/status;cwd='/+private/secret.txt'",
                "endpoint=https://example.com/status;cwd='<redacted-path:secret.txt>'",
            ),
            (
                "endpoint='https://[v1.a'b]:8443/status',path=\"/ Private Folder/secret.txt\"",
                "endpoint='https://[v1.a'b]:8443/status',path=\"<redacted-path:secret.txt>\"",
            ),
            (
                "endpoint=https://example.com/status,path=relative/file;"
                "cwd='/ Private Folder/secret.txt'",
                "endpoint=https://example.com/status,path=relative/file;"
                "cwd='<redacted-path:secret.txt>'",
            ),
            (
                "endpoint='https://example.com/status',path=relative/file;"
                "cwd='/ Private Folder/secret.txt'; retry",
                "endpoint='https://example.com/status',path=relative/file;"
                "cwd='<redacted-path:secret.txt>'; retry",
            ),
            (
                "endpoint='https://[v1.a'b]:8443/status',path=relative/file;"
                "cwd='/ Private Folder/secret.txt'; retry",
                "endpoint='https://[v1.a'b]:8443/status',path=relative/file;"
                "cwd='<redacted-path:secret.txt>'; retry",
            ),
            (
                "endpoint=https://example.com/status,path='relative/file';"
                "cwd='/ Private Folder/secret.txt'; retry",
                "endpoint=https://example.com/status,path='relative/file';"
                "cwd='<redacted-path:secret.txt>'; retry",
            ),
        )
        for message, expected in cases:
            with self.subTest(message=message):
                redacted = redact_cli_error_message(message)
                self.assertEqual(redacted, expected)
                self.assertNotIn("Private Folder", redacted)

        relative_only = (
            "endpoint='https://example.com/status',path=relative/file;"
            "mode='still/relative'; retry"
        )
        self.assertEqual(redact_cli_error_message(relative_only), relative_only)

    def test_cpp_relative_include_paths_are_not_redacted(self) -> None:
        for message in (r"relative C++\include\vector", "relative C++/include/vector"):
            with self.subTest(message=message):
                self.assertEqual(redact_cli_error_message(message), message)

    def test_file_uri_hides_local_path_suffix(self) -> None:
        redacted = redact_cli_error_message(
            "failed file:///Private Folder/sensitive-name.txt"
        )
        self.assertEqual(redacted, "failed file:<redacted-path>")
        self.assertNotIn("Private Folder", redacted)

    def test_top_level_main_error_output_uses_shared_path_redactor(self) -> None:
        stdout = io.StringIO()
        error = RuntimeError(
            'cannot open "C:\\Private Folder\\Sensitive Final Name.txt"; retry'
        )
        with patch("continuum.cli._main", side_effect=error), redirect_stdout(stdout):
            code = cli_main(["status"])
        payload = json.loads(stdout.getvalue())
        rendered = json.dumps(payload, ensure_ascii=True)
        self.assertEqual(code, 1)
        self.assertIn("<redacted-path:Sensitive Final Name.txt>", payload["error"])
        self.assertNotIn("Private Folder", rendered)

    def test_top_level_main_preserves_standalone_separator_diagnostic(self) -> None:
        stdout = io.StringIO()
        message = "expected / or \\ separator"
        with patch("continuum.cli._main", side_effect=RuntimeError(message)), redirect_stdout(stdout):
            code = cli_main(["status"])
        payload = json.loads(stdout.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(payload["error"], message)

    def test_top_level_main_redacts_generalized_posix_and_uri_field_cases(self) -> None:
        cases = (
            (
                'failed "/ Private Folder/secret.txt"',
                'failed "<redacted-path:secret.txt>"',
            ),
            (
                "endpoint=https://example.com/status;cwd=/private/secret.txt",
                "endpoint=https://example.com/status;cwd=<redacted-path:secret.txt>",
            ),
            (
                "endpoint=https://example.com/status,file='/ Private Folder/secret.txt'",
                "endpoint=https://example.com/status,file='<redacted-path:secret.txt>'",
            ),
            (
                'failed "file://// Private Folder/secret.txt"',
                'failed "<redacted-path>"',
            ),
            (
                "endpoint=https://example.com/status,path=relative/file;"
                "cwd='/ Private Folder/secret.txt'",
                "endpoint=https://example.com/status,path=relative/file;"
                "cwd='<redacted-path:secret.txt>'",
            ),
            (
                "endpoint='https://[v1.a'b]:8443/status',path=relative/file;"
                "cwd='/ Private Folder/secret.txt'; retry",
                "endpoint='https://[v1.a'b]:8443/status',path=relative/file;"
                "cwd='<redacted-path:secret.txt>'; retry",
            ),
        )
        for message, expected in cases:
            with self.subTest(message=message):
                stdout = io.StringIO()
                with patch("continuum.cli._main", side_effect=RuntimeError(message)), redirect_stdout(
                    stdout
                ):
                    code = cli_main(["status"])
                payload = json.loads(stdout.getvalue())
                self.assertEqual(code, 1)
                self.assertEqual(payload["error"], expected)

    def test_real_cli_exception_redacts_parent_directory_with_spaces(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "continuum"
            missing = base / "Private Folder" / "sensitive-name.txt"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = cli_main(
                    ["ingest-file", "--root", str(root), "--path", str(missing)]
                )
        payload = json.loads(stdout.getvalue())
        rendered = json.dumps(payload, ensure_ascii=True)
        self.assertEqual(code, 1)
        self.assertFalse(payload["ok"])
        self.assertIn("<redacted-path", payload["error"])
        self.assertNotIn("Private Folder", rendered)
        self.assertNotIn(str(missing), rendered)

    def test_hermes_install_backend_failure_returns_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            stdout = io.StringIO()
            backend_result = {
                "ok": False,
                "plugin_name": "continuum-memory",
                "plugin_target": "<redacted-path>",
                "dry_run": False,
                "command_failure_count": 1,
                "failed_commands": [["hermes", "plugins", "enable", "continuum-memory"]],
            }
            with patch(
                "continuum.cli.install_hermes_adapter",
                return_value=backend_result,
            ), redirect_stdout(stdout):
                code = cli_main(
                    [
                        "install-hermes-adapter",
                        "--root",
                        str(root),
                    ]
                )
            payload = json.loads(stdout.getvalue())
            receipt = json.loads(
                Path(payload["_operation"]["operation_receipt_uri"]).read_text(encoding="utf-8")
            )
        self.assertEqual(code, 1)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["failed_commands"], backend_result["failed_commands"])
        self.assertEqual(payload["_operation"]["status"], "failed")
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["cursor"]["phase"], "hermes_adapter_install_failed")
        self.assertEqual(receipt["result"]["failed_commands"], backend_result["failed_commands"])


if __name__ == "__main__":
    unittest.main()
