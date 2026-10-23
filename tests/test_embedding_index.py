from __future__ import annotations

import hashlib
import json
import math
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from continuum.core.config import default_config, write_config
from continuum.core.embedding_index import recall_indexed, refresh_embedding_index
from continuum.core.embeddings import EmbeddingError, embed_texts, embedding_identity
from continuum.core.recall import read_memory_source
from continuum.core.safety import scan_text_for_secrets, scan_value_for_secrets
from continuum.core.store import (
    append_scroll_event,
    connect,
    connect_existing,
    create_card,
    init_db,
    record_project_state,
)
from continuum.core.tool_outputs import record_indexed_tool_result


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def structured_credential_fixtures() -> list[str]:
    # Synthetic detector fixture; no real credential value is used or contacted.
    value = "heading\n" + "sk-" + "A" * 30
    encoded = json.dumps(value)
    return [
        json.dumps({"notes": value}),
        "\ufeff" + json.dumps({"notes": value}),
        json.dumps({"outer": [{"notes": value}]}),
        json.dumps(["ordinary", [value]]),
        encoded,
        '{"notes":' + encoded + ',"notes":"ordinary safe replacement"}',
        '{"outer":[{"notes":' + encoded + ',"notes":"ordinary safe replacement"}]}',
        '{"api\\u005fkey":"synthetic-safe-shaped-value"}',
    ]


class Provider:
    """Disposable protocol fixture only; no live endpoint or quality assertion."""

    def __init__(self) -> None:
        self.requests: list[dict] = []
        self.mode = "normal"
        self.fail_after: int | None = None
        self.dimensions = 3
        self.vector = None
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format, *args):
                pass

            def do_POST(self):
                self.close_connection = True
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                data = json.loads(body)
                owner.requests.append({"path": self.path, "headers": dict(self.headers), "body": data})
                if owner.mode == "redirect":
                    self.send_response(307)
                    self.send_header("Location", "http://192.0.2.1/v1/embeddings")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if owner.mode == "error" or (owner.fail_after is not None and len(owner.requests) > owner.fail_after):
                    payload = b'provider-private-error-body'
                    self.send_response(500)
                else:
                    rows = [{"index": index, "embedding": owner.vector(text) if owner.vector else
                             [float(index + number + 1) for number in range(owner.dimensions)]}
                            for index, text in enumerate(data["input"])]
                    output = {"model": data["model"], "data": rows}
                    if owner.mode == "reverse":
                        output["data"].reverse()
                    elif owner.mode == "wrong-model":
                        output["model"] = "different-model"
                    elif owner.mode == "duplicate":
                        output["data"] = [rows[0]] * len(rows)
                    elif owner.mode == "missing":
                        output["data"] = rows[:-1]
                    elif owner.mode == "nan":
                        rows[0]["embedding"] = [float("nan")]
                    elif owner.mode == "zero":
                        rows[0]["embedding"] = [0, 0]
                    elif owner.mode == "bool":
                        rows[0]["embedding"] = [True, 1]
                    elif owner.mode == "dimensions":
                        rows[-1]["embedding"] = [1, 2]
                    elif owner.mode == "oversize-dimensions":
                        rows[0]["embedding"] = [1] * 2049
                    payload = json.dumps(output, ensure_ascii=False).encode("utf-8")
                    if owner.mode == "duplicate-key":
                        payload = b'{"model":"fixture","model":"fixture","data":[]}'
                    if owner.mode == "malformed":
                        payload = b"not-json-private-body"
                    self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                try:
                    if owner.mode == "slow":
                        for character in payload:
                            self.wfile.write(bytes([character]))
                            self.wfile.flush()
                            time.sleep(0.02)
                    else:
                        self.wfile.write(payload)
                except (OSError, ValueError):
                    pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=lambda: self.server.serve_forever(poll_interval=0.01), daemon=True)
        self.thread.start()
        self.endpoint = f"http://127.0.0.1:{self.server.server_address[1]}/v1"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class EmbeddingProtocolTests(unittest.TestCase):
    def setUp(self):
        self.provider = Provider()
        self.addCleanup(self.provider.close)

    def embed(self, texts=None, **kwargs):
        return embed_texts(endpoint=self.provider.endpoint, model="fixture", texts=texts or ["quartz", "amber"], **kwargs)

    def test_real_protocol_exact_text_and_index_order(self):
        self.provider.mode = "reverse"
        values = self.embed(["Cafe\u0301 exact 😀", "second line\ntext"])
        self.assertEqual(len(values), 2)
        self.assertAlmostEqual(values[0][0], 1 / math.sqrt(14))
        request = self.provider.requests[0]
        self.assertEqual(request["path"], "/v1/embeddings")
        self.assertEqual(request["body"], {"model": "fixture", "input": ["Cafe\u0301 exact 😀", "second line\ntext"], "encoding_format": "float"})
        self.assertNotIn("Authorization", request["headers"])

    def test_no_proxy_environment_use(self):
        with patch.dict(os.environ, {"HTTP_PROXY": "http://192.0.2.1:1", "HTTPS_PROXY": "http://192.0.2.1:1", "ALL_PROXY": "http://192.0.2.1:1", "NO_PROXY": ""}):
            self.assertEqual(len(self.embed()), 2)

    def test_endpoint_validation_before_any_socket(self):
        invalid = ["", "http://localhost:123/v1", "http://192.0.2.1/v1", "http://127.0.0.1/v2",
                   "http://user@127.0.0.1/v1", "http://127.0.0.1/v1?x=1", "http://127.0.0.1/v1#x",
                   "http://[::1%25scope]/v1",
                   "http://[::ffff:127.0.0.1]/v1", "file:///v1", "http://127.0.0.1:0/v1", None]
        with patch.object(socket, "create_connection", side_effect=AssertionError("unexpected socket")):
            for endpoint in invalid:
                with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                    embed_texts(endpoint=endpoint, model="fixture", texts=["safe"])

    def test_canonical_identity_and_alias_validation(self):
        self.assertEqual(embedding_identity("http://127.0.0.1/v1/", "fixture"), ("http://127.0.0.1:80/v1", "fixture"))
        self.assertEqual(embedding_identity("http://[::1]/v1", "fixture")[0], "http://[::1]:80/v1")
        for model in ("", " padded ", "a" * 129, "../weights", "model.gguf", "\x01bad", "api_key=" + "synthetic-value-12345"):
            with self.subTest(model=model), self.assertRaises(ValueError):
                embedding_identity(self.provider.endpoint, model)

    def test_input_limits_and_credentials_never_reach_provider(self):
        cases = [[], [" "] , ["x"] * 17, ["x" * (64 * 1024 + 1)], ["x" * (64 * 1024)] * 5,
                 ["\ud800"], [True], ["api_key=" + "synthetic-value-12345"]]
        for texts in cases:
            with self.subTest(case=type(texts)), self.assertRaises(ValueError):
                embed_texts(endpoint=self.provider.endpoint, model="fixture", texts=texts)
        self.assertEqual(self.provider.requests, [])

    def test_structured_credentials_and_duplicate_keys_never_reach_provider(self):
        fixture = structured_credential_fixtures()[0]
        self.assertFalse(scan_text_for_secrets(fixture))
        self.assertTrue(scan_value_for_secrets(json.loads(fixture), scope="fixture"))
        for text in structured_credential_fixtures():
            with self.subTest(text_hash=digest(text)), self.assertRaisesRegex(ValueError, "credential policy"):
                self.embed([text])
        self.assertEqual(self.provider.requests, [])

    def test_safe_plaintext_and_structured_notes_are_unchanged(self):
        texts = ["Ordinary safe note: use the approved local helper.",
                 "This note is not JSON: {use the helper}",
                 json.dumps({"notes": "heading\nUse the approved local helper."}),
                 json.dumps({"outer": [{"notes": "safe follow-up"}, ["ordinary", "text"]]})]
        self.assertEqual(len(self.embed(texts)), len(texts))
        self.assertEqual(self.provider.requests[0]["body"]["input"], texts)

    def test_bad_provider_responses_are_sanitized(self):
        for mode in ("redirect", "error", "wrong-model", "duplicate", "missing", "nan", "zero", "bool", "dimensions", "oversize-dimensions", "duplicate-key", "malformed"):
            self.provider.mode = mode
            with self.subTest(mode=mode), self.assertRaises(EmbeddingError) as caught:
                self.embed()
            self.assertNotIn("private", str(caught.exception))
            self.assertNotIn("quartz", str(caught.exception))

    def test_total_deadline_interrupts_dripped_body(self):
        self.provider.mode = "slow"
        before = time.monotonic()
        with patch("continuum.core.embeddings.TOTAL_TIMEOUT_SECONDS", 0.1), self.assertRaises(EmbeddingError):
            self.embed()
        self.assertLess(time.monotonic() - before, 2)


class EmbeddingIndexTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="continuum-embedding-index-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "memory"
        config = default_config()
        config["capture"]["mode"] = "manual"
        config["local_inference"]["enabled"] = False
        write_config(self.root, config)
        init_db(self.root)
        self.provider = Provider()
        self.addCleanup(self.provider.close)
        self.model = "fixture"

    def refresh(self, **kwargs):
        return refresh_embedding_index(self.root, endpoint=self.provider.endpoint, model=self.model, **kwargs)

    def recall(self, query="semanticparaphrase", **kwargs):
        return recall_indexed(self.root, query=query, endpoint=self.provider.endpoint, model=self.model, **kwargs)

    def event(self, text, *, scope="global", project=None, session="fixture-session"):
        metadata = {"visibility_scope": scope, "continuum_disable_exact_memory": True}
        if project:
            metadata["project_id"] = project
        return append_scroll_event(self.root, session_id=session, event_type="message", role="user", content=text,
                                   metadata=metadata)["event_id"]

    def card(self, text, *, scope="global", project=None):
        with closing(connect(self.root)) as conn:
            source_id = create_card(conn, root=self.root, card_type="decision", title="Evidence", summary=text,
                                    source_refs=[], visibility_scope=scope, session_id="fixture-session", project_id=project)
            conn.commit()
        return source_id

    def cache(self):
        return sorted((self.root / "catalog" / "embedding-index").glob("*.json"))

    def logical_state(self):
        with closing(connect_existing(self.root)) as conn:
            return list(conn.iterdump())

    def test_incremental_reuse_exact_hash_change_and_no_source_writes(self):
        event = self.event("Azure transport evidence")
        before = self.logical_state()
        first = self.refresh()
        self.assertEqual(first["embedded_sources"], 1)
        self.assertEqual(first["indexed_sources"], 1)
        cache_before = self.cache()[0].read_bytes()
        second = self.refresh()
        self.assertEqual(second["reused_sources"], 1)
        self.assertEqual(second["provider_batches"], 0)
        self.assertEqual(len(self.provider.requests), 1)
        self.assertEqual(self.cache()[0].read_bytes(), cache_before)
        self.assertEqual(self.logical_state(), before)
        with closing(connect(self.root)) as conn:
            conn.execute("UPDATE scroll_events SET content=? WHERE id=?", ("Updated Azure evidence", event))
            conn.commit()
        third = self.refresh()
        self.assertEqual(third["embedded_sources"], 1)
        self.assertEqual(self.provider.requests[-1]["body"]["input"], ["Updated Azure evidence"])

    def test_index_has_only_identifiers_hashes_vectors_and_safe_metadata(self):
        event = self.event("UNIQUE_SOURCE_CONTENT_NEVER_PERSISTED_IN_DERIVED_CACHE")
        self.refresh()
        text = self.cache()[0].read_text(encoding="utf-8")
        self.assertNotIn("UNIQUE_SOURCE", text)
        self.assertNotIn(self.provider.endpoint, text)
        self.assertNotIn(self.model, text)
        data = json.loads(text)
        self.assertEqual(set(data), {"schema_version", "identity_sha256", "dimensions", "entries"})
        self.assertEqual(set(data["entries"][0]), {"kind", "id", "content_hash", "vector"})
        self.assertEqual(data["entries"][0]["id"], event)

    def test_scoped_current_sources_only_reach_provider(self):
        global_id = self.event("global-only")
        selected = self.event("project-allowed", scope="project", project="project-a")
        self.event("other-project-excluded", scope="project", project="project-b")
        self.event("private-excluded", scope="private", project="project-a")
        retired = self.card("retired-card", scope="project", project="project-a")
        with closing(connect(self.root)) as conn:
            conn.execute("UPDATE cards SET status='superseded' WHERE id=?", (retired,))
            conn.commit()
        result = self.refresh(project_id="project-a")
        self.assertEqual(result["indexed_sources"], 1)
        self.assertEqual(self.provider.requests[-1]["body"]["input"], ["project-allowed"])
        packet = self.recall(project_id="project-a")
        self.assertEqual({hit["id"] for hit in packet["results"]}, {selected})
        self.assertNotIn(global_id, json.dumps(packet))

    def test_cards_events_chunks_use_exact_canonical_read_content(self):
        self.card("chosen amber")
        self.event("durable event")
        record_indexed_tool_result(self.root, session_id="fixture-session", event_type="tool_result",
                                   text="large output evidence " * 200,
                                   metadata={"visibility_scope": "global", "tool_name": "fixture"}, max_reference_bytes=128)
        result = self.refresh()
        self.assertGreaterEqual(result["indexed_sources"], 3)
        entries = json.loads(self.cache()[0].read_text(encoding="utf-8"))["entries"]
        sent = [text for request in self.provider.requests for text in request["body"]["input"]]
        for entry in entries:
            read = read_memory_source(self.root, kind=entry["kind"], source_id=entry["id"], limit=8000)
            self.assertEqual(entry["content_hash"], read["content_hash"])
            self.assertIn(read["content"], sent)

    def test_credential_legacy_source_skipped_even_when_root_policy_off(self):
        source_id = self.event("legacy safe before direct fixture update")
        config = default_config()
        config["security"]["secret_scan_enabled"] = False
        write_config(self.root, config)
        with closing(connect(self.root)) as conn:
            conn.execute("UPDATE scroll_events SET content=? WHERE id=?", ("api_key=" + "synthetic-value-12345", source_id))
            conn.commit()
        result = self.refresh()
        self.assertEqual(result["skipped_credentials"], 1)
        self.assertEqual(result["indexed_sources"], 0)
        self.assertEqual(self.provider.requests, [])

    def test_query_credentials_never_reach_provider(self):
        self.event("ordinary source")
        self.refresh()
        requests = len(self.provider.requests)
        packet = self.recall("api_key=" + "synthetic-value-12345")
        self.assertEqual(packet["semantic_index"]["status"], "query_blocked")
        self.assertEqual(len(self.provider.requests), requests)

    def test_structured_legacy_source_guard_sends_zero_requests(self):
        source_id = self.event("ordinary fixture before legacy database mutation")
        for text in structured_credential_fixtures():
            with self.subTest(text_hash=digest(text)):
                with closing(connect(self.root)) as conn:
                    conn.execute("UPDATE scroll_events SET content=?,content_hash=? WHERE id=?", (text, digest(text), source_id))
                    conn.commit()
                result = self.refresh()
                self.assertEqual(result["embedded_sources"], 0)
                self.assertEqual(result["skipped_credentials"], 1)
                self.assertEqual(result["indexed_sources"], 0)
        self.assertEqual(self.provider.requests, [])

    def test_structured_query_guard_sends_zero_requests(self):
        self.event("ordinary safe source")
        self.refresh()
        self.provider.requests.clear()
        for text in structured_credential_fixtures():
            with self.subTest(text_hash=digest(text)):
                packet = self.recall(text)
                self.assertEqual(packet["semantic_index"]["status"], "query_blocked")
                self.assertFalse(packet["semantic_index"]["used"])
        self.assertEqual(self.provider.requests, [])

    def test_preexisting_structured_credential_cache_is_excluded_without_provider(self):
        source_id = self.event("ordinary fixture before legacy database mutation")
        self.refresh()
        path = self.cache()[0]
        cache = json.loads(path.read_text(encoding="utf-8"))
        text = structured_credential_fixtures()[0]
        with closing(connect(self.root)) as conn:
            conn.execute("UPDATE scroll_events SET content=?,content_hash=? WHERE id=?", (text, digest(text), source_id))
            conn.commit()
        cache["entries"][0]["content_hash"] = digest(text)
        path.write_text(json.dumps(cache), encoding="utf-8")
        before = path.read_bytes()
        self.provider.requests.clear()
        packet = self.recall()
        self.assertEqual(packet["semantic_index"]["status"], "no_eligible_sources")
        self.assertEqual(packet["semantic_index"]["credential_excluded"], 1)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.provider.requests, [])

    def test_card_structured_fields_are_screened_before_embedding_or_cached_recall(self):
        source_id = self.card("ordinary card before legacy database mutation")
        self.refresh()
        path = self.cache()[0]
        cache = json.loads(path.read_text(encoding="utf-8"))
        summary = json.dumps({"notes": "heading\n" + "sk-" + "A" * 30}, indent=2)
        with closing(connect(self.root)) as conn:
            conn.execute("UPDATE cards SET summary=? WHERE id=?", (summary, source_id))
            conn.commit()
        cache["entries"][0]["content_hash"] = digest("Evidence\n" + summary)
        path.write_text(json.dumps(cache), encoding="utf-8")
        self.provider.requests.clear()
        packet = self.recall()
        self.assertEqual(packet["semantic_index"]["credential_excluded"], 1)
        result = self.refresh()
        self.assertEqual(result["skipped_credentials"], 1)
        self.assertEqual(result["embedded_sources"], 0)
        self.assertEqual(self.provider.requests, [])

    def test_empty_index_never_calls_provider(self):
        result = self.refresh()
        self.assertEqual(result["indexed_sources"], 0)
        packet = self.recall()
        self.assertEqual(packet["semantic_index"]["status"], "empty")
        self.assertEqual(self.provider.requests, [])

    def test_refresh_numeric_arguments_reject_bool_fraction_and_out_of_bounds(self):
        for field, values in (("max_sources", [True, 0, 5001, 2.5]), ("batch_size", [True, 0, 17, 2.5])):
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    self.refresh(**{field: value})
        self.assertEqual(self.cache(), [])
        self.assertEqual(self.provider.requests, [])

    def test_query_no_write_and_missing_cache_makes_no_request(self):
        source_id = self.event("quartzsearch exact lexical")
        before = self.logical_state()
        with patch("continuum.core.embedding_index.secure_write_text", side_effect=AssertionError("query write")):
            missing = self.recall("quartzsearch")
        self.assertEqual(missing["semantic_index"]["status"], "missing")
        self.assertIn(source_id, {hit["id"] for hit in missing["results"]})
        self.assertEqual(self.provider.requests, [])
        self.assertEqual(self.cache(), [])
        self.refresh()
        cache_before = self.cache()[0].read_bytes()
        with patch("continuum.core.embedding_index.secure_write_text", side_effect=AssertionError("query write")):
            found = self.recall()
        self.assertTrue(found["semantic_index"]["used"])
        self.assertEqual(cache_before, self.cache()[0].read_bytes())
        self.assertEqual(self.logical_state(), before)

    def test_missing_root_query_does_not_initialize_or_call_provider(self):
        missing = self.root.parent / "absent-memory"
        packet = recall_indexed(missing, query="quartz", endpoint=self.provider.endpoint, model=self.model)
        self.assertFalse(packet["initialized"])
        self.assertFalse(missing.exists())
        with self.assertRaises(ValueError):
            refresh_embedding_index(missing, endpoint=self.provider.endpoint, model=self.model)
        self.assertFalse(missing.exists())
        self.assertEqual(self.provider.requests, [])

    def test_scope_model_and_endpoint_identity_misses_do_not_request(self):
        self.event("ordinary source")
        self.refresh()
        before = len(self.provider.requests)
        for kwargs in ({"project_id": "project-a"}, {"session_id": "session-other"}):
            self.assertEqual(self.recall(**kwargs)["semantic_index"]["status"], "missing")
        self.model = "different-alias"
        self.assertEqual(self.recall()["semantic_index"]["status"], "missing")
        packet = recall_indexed(self.root, query="quartz", endpoint="http://127.0.0.1:1/v1", model="fixture")
        self.assertEqual(packet["semantic_index"]["status"], "missing")
        self.assertEqual(len(self.provider.requests), before)

    def test_changed_retired_and_private_entries_excluded_before_request(self):
        changed = self.event("changed original")
        private = self.event("private later")
        card = self.card("retired later")
        self.refresh()
        before = len(self.provider.requests)
        with closing(connect(self.root)) as conn:
            conn.execute("UPDATE scroll_events SET content='changed now' WHERE id=?", (changed,))
            conn.execute("UPDATE scroll_events SET visibility_scope='private', metadata_json=? WHERE id=?",
                         (json.dumps({"visibility_scope": "private"}), private))
            conn.execute("UPDATE cards SET status='superseded' WHERE id=?", (card,))
            conn.commit()
        packet = self.recall()
        self.assertEqual(packet["semantic_index"]["status"], "no_eligible_sources")
        self.assertEqual(packet["semantic_index"]["stale_excluded"], 3)
        self.assertEqual(len(self.provider.requests), before)
        self.assertEqual(packet["retrieval"]["channels"]["semantic"], 0)
        refreshed = self.refresh()
        self.assertEqual(refreshed["removed_sources"], 2)

    def test_current_checkpoint_authority_is_rechecked(self):
        first = record_project_state(self.root, session_id="checkpoint-session", agent_id="fixture", project_id="project-a", objective="Earlier objective")
        self.refresh(project_id="project-a")
        second = record_project_state(self.root, session_id="checkpoint-session", agent_id="fixture", project_id="project-a", objective="New objective")
        packet = self.recall(project_id="project-a")
        self.assertFalse(packet["semantic_index"]["used"])
        result = self.refresh(project_id="project-a")
        self.assertGreater(result["removed_sources"], 0)
        serialized = self.cache()[0].read_text(encoding="utf-8")
        self.assertNotIn(first["card_id"], serialized)
        self.assertIn(second["card_id"], serialized)

    def test_invalid_index_falls_back_without_provider_or_repair(self):
        self.event("quartzsearch lexical")
        self.refresh()
        path = self.cache()[0]
        original = json.loads(path.read_text(encoding="utf-8"))
        mutations = [None, {**original, "identity_sha256": "0" * 64}, {**original, "schema_version": True},
                     {**original, "dimensions": 2000}, {**original, "entries": original["entries"] * 2}]
        for data in mutations:
            content = "not-json" if data is None else json.dumps(data)
            path.write_text(content, encoding="utf-8")
            before = len(self.provider.requests)
            packet = self.recall("quartzsearch")
            self.assertEqual(packet["semantic_index"]["status"], "invalid")
            self.assertEqual(len(self.provider.requests), before)
            self.assertEqual(path.read_text(encoding="utf-8"), content)
            self.assertGreater(packet["result_count"], 0)

    def test_offline_bad_provider_and_dimension_change_fall_back(self):
        self.event("quartzsearch lexical")
        self.refresh()
        self.provider.mode = "error"
        self.assertEqual(self.recall("quartzsearch")["semantic_index"]["status"], "unavailable")
        self.provider.mode = "normal"
        self.provider.dimensions = 2
        self.assertEqual(self.recall("quartzsearch")["semantic_index"]["status"], "unavailable")
        with patch("continuum.core.embeddings.http.client.HTTPConnection.connect", side_effect=OSError("private error")):
            packet = self.recall("quartzsearch")
        self.assertEqual(packet["semantic_index"]["status"], "unavailable")
        self.assertGreater(packet["result_count"], 0)
        self.assertNotIn("private error", json.dumps(packet))

    def test_failed_later_batch_never_partially_publishes(self):
        self.event("initial")
        self.refresh()
        path = self.cache()[0]
        before = path.read_bytes()
        self.event("pending one")
        self.event("pending two")
        self.provider.fail_after = len(self.provider.requests) + 1
        with self.assertRaises(EmbeddingError):
            self.refresh(batch_size=1)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(len(list(path.parent.iterdir())), 1)

    def test_new_dimensions_with_reused_entries_preserve_cache(self):
        self.event("initial")
        self.refresh()
        path = self.cache()[0]
        before = path.read_bytes()
        self.event("pending new")
        self.provider.dimensions = 2
        with self.assertRaises(EmbeddingError):
            self.refresh()
        self.assertEqual(path.read_bytes(), before)

    def test_counts_bytes_and_cache_limits_fail_without_publication(self):
        first = self.event("first")
        self.refresh()
        path = self.cache()[0]
        before = path.read_bytes()
        self.event("second")
        with self.assertRaises(ValueError):
            self.refresh(max_sources=1)
        with patch("continuum.core.embedding_index.MAX_SOURCE_BYTES", 1), self.assertRaises(ValueError):
            self.refresh()
        with patch("continuum.core.embedding_index.MAX_CACHE_BYTES", 10), self.assertRaises(ValueError):
            self.refresh()
        self.assertEqual(path.read_bytes(), before)
        self.assertIn(first, before.decode())

    def test_oversized_sources_skipped_not_truncated(self):
        source_id = self.event("safe short")
        with closing(connect(self.root)) as conn:
            conn.execute("UPDATE scroll_events SET content=? WHERE id=?", ("x" * (64 * 1024 + 1), source_id))
            conn.commit()
        result = self.refresh()
        self.assertEqual(result["skipped_oversize"], 1)
        self.assertEqual(result["indexed_sources"], 0)
        self.assertEqual(self.provider.requests, [])

    def test_byte_batching_honors_exact_utf8_budget(self):
        for index in range(5):
            self.event(str(index) + "x" * 60000)
        result = self.refresh()
        self.assertEqual(result["embedded_sources"], 5)
        self.assertEqual(result["provider_batches"], 2)
        self.assertEqual([len(request["body"]["input"]) for request in self.provider.requests], [4, 1])

    def test_minimum_packet_budget_includes_index_status_and_unicode_model(self):
        self.model = "😀" * 128
        self.event("budgetsource " + "東京😀 " * 30)
        self.refresh()
        packet = self.recall(token_budget=512)
        text = json.dumps(packet, ensure_ascii=True, separators=(",", ":"))
        self.assertLessEqual(len(text), 2048)
        self.assertEqual(packet["budget"]["estimated_tokens"], (len(text) + 3) // 4)
        self.assertNotIn(self.model, text)

    def test_date_filters_applied_before_semantic_candidate_limit(self):
        old = self.event("old record")
        current = self.event("current record")
        with closing(connect(self.root)) as conn:
            conn.execute("UPDATE scroll_events SET created_at='2020-01-01T00:00:00+00:00' WHERE id=?", (old,))
            conn.execute("UPDATE scroll_events SET created_at='2026-01-01T00:00:00+00:00' WHERE id=?", (current,))
            conn.commit()
        self.refresh()
        packet = self.recall(created_after="2025-01-01T00:00:00Z")
        self.assertEqual({hit["id"] for hit in packet["results"]}, {current})
        self.assertEqual(packet["semantic_index"]["validated_sources"], 1)

    def test_fresh_process_reuses_index_and_real_http(self):
        self.event("fresh process evidence")
        self.refresh()
        script = "import json,sys; from pathlib import Path; sys.path.insert(0,sys.argv[1]); from continuum.core.embedding_index import recall_indexed; print(json.dumps(recall_indexed(Path(sys.argv[2]),query='paraphrase',endpoint=sys.argv[3],model='fixture')))"
        completed = subprocess.run([sys.executable, "-I", "-B", "-c", script,
                                    str(Path(__file__).resolve().parents[1] / "src"), str(self.root), self.provider.endpoint],
                                   capture_output=True, text=True, timeout=30, check=True)
        packet = json.loads(completed.stdout)
        self.assertTrue(packet["semantic_index"]["used"])
        self.assertEqual(packet["semantic_index"]["validated_sources"], 1)
        self.assertEqual(len(self.provider.requests), 2)

    def bulk_events(self, count):
        with closing(connect(self.root)) as conn:
            conn.executemany("""INSERT INTO scroll_events
                (id,session_id,seq,event_type,role,content,content_hash,visibility_scope,metadata_json,created_at)
                VALUES (?,'bulk-session',?,'message','user',?,?,'global',?, '2026-01-01T00:00:00+00:00')""",
                [(f"bulk-{index:03}", index, f"source evidence {index}", digest(f"source evidence {index}"),
                  '{"visibility_scope":"global"}') for index in range(count)])
            conn.commit()

    def test_revalidation_happens_before_top_256_not_after(self):
        self.bulk_events(300)
        self.provider.vector = lambda text: [1.0, 0.0, 0.0]
        self.refresh()
        with closing(connect(self.root)) as conn:
            conn.execute("UPDATE scroll_events SET visibility_scope='private',metadata_json=? WHERE id != 'bulk-299'",
                         ('{"visibility_scope":"private"}',))
            conn.commit()
        packet = self.recall()
        self.assertEqual(packet["semantic_index"]["stale_excluded"], 299)
        self.assertEqual(packet["semantic_index"]["validated_sources"], 1)
        self.assertEqual([hit["id"] for hit in packet["results"]], ["bulk-299"])
        self.assertNotIn("bulk-000", json.dumps(packet))

    def test_large_vectors_respect_existing_semantic_serialized_ceiling(self):
        self.bulk_events(80)
        self.provider.dimensions = 2048
        self.refresh()
        packet = self.recall()
        self.assertTrue(packet["semantic_index"]["used"])
        self.assertTrue(packet["semantic_index"]["candidates_truncated"])
        self.assertGreater(packet["semantic_index"]["semantic_candidates"], 0)
        self.assertLess(packet["semantic_index"]["semantic_candidates"], 80)

    def test_cache_symlink_cannot_redirect_query_or_refresh(self):
        self.event("ordinary source")
        outside = self.root.parent / "outside"
        outside.mkdir()
        directory = self.root / "catalog" / "embedding-index"
        try:
            directory.symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest("symlink creation unavailable on this platform")
        self.assertEqual(self.recall()["semantic_index"]["status"], "invalid")
        with self.assertRaises(ValueError):
            self.refresh()
        self.assertEqual(list(outside.iterdir()), [])
        self.assertEqual(self.provider.requests, [])


if __name__ == "__main__":
    unittest.main()
