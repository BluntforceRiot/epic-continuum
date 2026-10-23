from __future__ import annotations

import copy
import hashlib
import json
import math
import sys
import unittest
from dataclasses import FrozenInstanceError
from decimal import Decimal
from unittest.mock import patch

from continuum.core import semantic_vectors
from continuum.core.semantic_vectors import (
    SemanticInput,
    VectorEvidence,
    cosine_similarity,
    parse_semantic_input,
)


QUERY = "Where did we put the turquoise heron?"
CONTENT_HASH = hashlib.sha256(b"Source content, not a model assertion.").hexdigest()


def payload(*, query: str = QUERY) -> dict:
    return {
        "model": "test/embedding-alias",
        "query_hash": hashlib.sha256(query.encode("utf-8")).hexdigest(),
        "query_vector": [3, 4],
        "items": [
            {
                "kind": "card",
                "id": "card_123",
                "content_hash": CONTENT_HASH,
                "vector": [4.0, 3.0],
            }
        ],
    }


class ExplosiveValue:
    """No user-controlled protocol should run during input validation."""

    def __str__(self):
        raise AssertionError("unexpected scalar coercion")

    def __repr__(self):
        raise AssertionError("unexpected value disclosure")

    def __float__(self):
        raise AssertionError("unexpected numeric coercion")

    def __iter__(self):
        raise AssertionError("unexpected iteration")

    def __len__(self):
        raise AssertionError("unexpected length lookup")


class ExplosiveList(list):
    def __iter__(self):
        raise AssertionError("unexpected list subclass iteration")

    def __len__(self):
        raise AssertionError("unexpected list subclass length lookup")


class ExplosiveDict(dict):
    def __iter__(self):
        raise AssertionError("unexpected dict subclass iteration")

    def __len__(self):
        raise AssertionError("unexpected dict subclass length lookup")

    def __getitem__(self, key):
        raise AssertionError("unexpected dict subclass lookup")


class SemanticInputTests(unittest.TestCase):
    def assert_invalid(self, value: object, *, query: str = QUERY) -> ValueError:
        with self.assertRaises(ValueError) as raised:
            parse_semantic_input(value, query=query)
        return raised.exception

    def test_none_disables_semantics(self) -> None:
        self.assertIsNone(parse_semantic_input(None, query=QUERY))

    def test_valid_json_returns_frozen_normalized_evidence(self) -> None:
        result = parse_semantic_input(json.loads(json.dumps(payload())), query=QUERY)
        self.assertEqual(
            result,
            SemanticInput(
                "test/embedding-alias",
                (0.6, 0.8),
                (VectorEvidence("card", "card_123", CONTENT_HASH, (0.8, 0.6)),),
            ),
        )
        self.assertTrue(all(type(value) is float for value in result.query_vector))
        self.assertEqual(hash(result), hash(copy.deepcopy(result)))
        with self.assertRaises(FrozenInstanceError):
            result.model = "different"
        with self.assertRaises(FrozenInstanceError):
            result.items[0].source_id = "different"

    def test_parser_does_not_mutate_or_retain_mutable_input(self) -> None:
        value = payload()
        before = copy.deepcopy(value)
        result = parse_semantic_input(value, query=QUERY)
        self.assertEqual(value, before)
        value["query_vector"][0] = 999
        value["items"][0]["vector"][0] = 999
        value["items"][0]["id"] = "different"
        value["items"].clear()
        self.assertEqual(result.query_vector, (0.6, 0.8))
        self.assertEqual(result.items[0].vector, (0.8, 0.6))
        self.assertEqual(result.items[0].source_id, "card_123")

    def test_all_supported_kinds_preserve_order_and_identity(self) -> None:
        value = payload()
        item = value["items"][0]
        value["items"] = [
            {**item, "kind": kind} for kind in ("scroll_event", "chunk", "card")
        ]
        result = parse_semantic_input(value, query=QUERY)
        self.assertEqual(
            [item.kind for item in result.items], ["scroll_event", "chunk", "card"]
        )
        self.assertEqual([item.source_id for item in result.items], ["card_123"] * 3)

    def test_empty_items_are_valid(self) -> None:
        value = payload()
        value["items"] = []
        self.assertEqual(parse_semantic_input(value, query=QUERY).items, ())

    def test_top_level_requires_exact_plain_json_object(self) -> None:
        for value in (
            True,
            1,
            "{}",
            b"{}",
            [],
            (),
            ExplosiveValue(),
            ExplosiveDict(payload()),
        ):
            self.assert_invalid(value)

    def test_top_level_rejects_unknown_missing_and_nonstring_fields(self) -> None:
        for field in payload():
            value = payload()
            del value[field]
            self.assert_invalid(value)
        for key in ("unknown", 7):
            value = payload()
            value[key] = ExplosiveValue()
            self.assert_invalid(value)
        value = payload()
        value[7] = value.pop("model")
        self.assert_invalid(value)

    def test_items_require_plain_bounded_json_array_before_iteration(self) -> None:
        for items in (
            None,
            True,
            {},
            (),
            "items",
            iter(()),
            ExplosiveValue(),
            ExplosiveList(),
        ):
            value = payload()
            value["items"] = items
            self.assert_invalid(value)
        value = payload()
        value["items"] = [ExplosiveValue()] * 257
        self.assert_invalid(value)

    def test_items_limit_is_inclusive(self) -> None:
        value = payload()
        item = value["items"][0]
        value["items"] = [{**item, "id": f"card_{index}"} for index in range(256)]
        self.assertEqual(len(parse_semantic_input(value, query=QUERY).items), 256)
        value["items"].append({**item, "id": "card_extra"})
        self.assert_invalid(value)

    def test_item_requires_exact_plain_json_object(self) -> None:
        for item in (None, True, [], (), "item", ExplosiveValue(), ExplosiveDict()):
            value = payload()
            value["items"] = [item]
            self.assert_invalid(value)
        for field in payload()["items"][0]:
            value = payload()
            del value["items"][0][field]
            self.assert_invalid(value)
        value = payload()
        value["items"][0]["unknown"] = ExplosiveValue()
        self.assert_invalid(value)
        value = payload()
        value["items"][0][7] = value["items"][0].pop("kind")
        self.assert_invalid(value)

    def test_kinds_are_exact_and_not_coerced(self) -> None:
        for kind in (
            "Card",
            "scroll",
            "library",
            "",
            "x" * 10000,
            None,
            True,
            [],
            ExplosiveValue(),
        ):
            value = payload()
            value["items"][0]["kind"] = kind
            self.assert_invalid(value)

    def test_duplicate_identity_is_rejected_even_with_other_content_hash(self) -> None:
        value = payload()
        value["items"].append({**value["items"][0], "content_hash": "0" * 64})
        self.assert_invalid(value)

    def test_model_uses_existing_alias_validator(self) -> None:
        value = payload()
        value["model"] = "  test-alias  "
        with patch.object(
            semantic_vectors,
            "validate_inference_model_identifier",
            wraps=semantic_vectors.validate_inference_model_identifier,
        ) as validator:
            result = parse_semantic_input(value, query=QUERY)
        validator.assert_called_once_with("  test-alias  ")
        self.assertEqual(result.model, "test-alias")

    def test_model_length_printability_and_type(self) -> None:
        for model in (
            "",
            " ",
            "x" * 129,
            "tab\there",
            "line\nbreak",
            "return\rbreak",
            "nul\0",
            "delete\x7f",
            "control\x85",
            "surrogate\ud800",
            None,
            True,
            123,
            [],
            ExplosiveValue(),
        ):
            value = payload()
            value["model"] = model
            self.assert_invalid(value)
        for model in ("x" * 128, "modèle-東京"):
            value = payload()
            value["model"] = model
            self.assertEqual(parse_semantic_input(value, query=QUERY).model, model)

    def test_model_paths_and_local_files_are_rejected(self) -> None:
        for model in (
            "/absolute/model",
            "C:\\private\\model",
            "../model",
            "./model",
            "..\\model",
            "file:///private/model",
            "vscode://model",
            "model.gguf",
            "model.safetensors",
            "alias/with space",
            "folder\\alias",
        ):
            value = payload()
            value["model"] = model
            self.assert_invalid(value)

    def test_source_identifier_is_portable_bounded_and_nonempty(self) -> None:
        for source_id in (
            "",
            "x" * 129,
            "../path",
            "/path",
            "a/b",
            "a\\b",
            "a b",
            "a\nb",
            "東京",
            "[markup]",
            "<tag>",
            "a?b",
            "a\0b",
            None,
            True,
            123,
            [],
            ExplosiveValue(),
        ):
            value = payload()
            value["items"][0]["id"] = source_id
            self.assert_invalid(value)
        for source_id in ("x", "x" * 128, "card_abc.123-DEF:4"):
            value = payload()
            value["items"][0]["id"] = source_id
            self.assertEqual(
                parse_semantic_input(value, query=QUERY).items[0].source_id, source_id
            )

    def test_hashes_require_lowercase_sha256_strings(self) -> None:
        for digest in (
            "",
            "0" * 63,
            "0" * 65,
            "A" * 64,
            "g" * 64,
            "0" * 63 + "\n",
            None,
            0,
            [],
            ExplosiveValue(),
        ):
            value = payload()
            value["query_hash"] = digest
            self.assert_invalid(value)
            value = payload()
            value["items"][0]["content_hash"] = digest
            self.assert_invalid(value)

    def test_query_hash_binds_exact_query_without_trimming_or_normalization(
        self,
    ) -> None:
        for query in ("", " café 東京\n", "café", "cafe\u0301"):
            self.assertIsNotNone(
                parse_semantic_input(payload(query=query), query=query)
            )
        for altered in (QUERY + " ", QUERY.lower(), "different query"):
            self.assert_invalid(payload(), query=altered)
        self.assert_invalid(payload(query="café"), query="cafe\u0301")

    def test_query_malformed_type_or_utf8_is_rejected_without_coercion(self) -> None:
        for query in (None, True, 1, b"query", ExplosiveValue(), "query\ud800"):
            self.assert_invalid(payload(), query=query)

    def test_vectors_require_plain_json_arrays(self) -> None:
        for vector in (
            None,
            True,
            1,
            "1,2",
            {"a": 1},
            (1, 2),
            iter((1, 2)),
            ExplosiveValue(),
            ExplosiveList([1, 2]),
        ):
            for item_vector in (False, True):
                value = payload()
                if item_vector:
                    value["items"][0]["vector"] = vector
                else:
                    value["query_vector"] = vector
                self.assert_invalid(value)

    def test_vectors_reject_empty_zero_and_oversized_arrays(self) -> None:
        for vector in ([], [0], [0.0, -0.0], [ExplosiveValue()] * 2049):
            for item_vector in (False, True):
                value = payload()
                if item_vector:
                    value["items"][0]["vector"] = vector
                else:
                    value["query_vector"] = vector
                self.assert_invalid(value)

    def test_vector_dimension_bound_is_inclusive(self) -> None:
        value = payload()
        value["query_vector"] = [1] * 2048
        value["items"][0]["vector"] = [2] * 2048
        result = parse_semantic_input(value, query=QUERY)
        self.assertEqual(len(result.query_vector), 2048)
        self.assertAlmostEqual(math.hypot(*result.query_vector), 1.0)
        self.assertAlmostEqual(
            cosine_similarity(result.query_vector, result.items[0].vector), 1.0
        )

    def test_vector_dimensions_must_match(self) -> None:
        value = payload()
        value["items"][0]["vector"] = [1, 2, 3]
        self.assert_invalid(value)

    def test_components_are_finite_json_numbers_not_booleans_or_coercions(self) -> None:
        for component in (
            True,
            False,
            "1",
            None,
            [],
            {},
            Decimal("1"),
            complex(1, 0),
            ExplosiveValue(),
            float("nan"),
            float("inf"),
            float("-inf"),
            1 << 10000,
        ):
            for item_vector in (False, True):
                value = payload()
                vector = (
                    value["items"][0]["vector"]
                    if item_vector
                    else value["query_vector"]
                )
                vector[0] = component
                self.assert_invalid(value)

    def test_builtin_scalar_subclasses_are_not_accepted(self) -> None:
        class StringSubclass(str):
            pass

        class IntSubclass(int):
            pass

        class FloatSubclass(float):
            pass

        for field in ("model", "query_hash"):
            value = payload()
            value[field] = StringSubclass(value[field])
            self.assert_invalid(value)
        for field in ("kind", "id", "content_hash"):
            value = payload()
            value["items"][0][field] = StringSubclass(value["items"][0][field])
            self.assert_invalid(value)
        for component in (IntSubclass(1), FloatSubclass(1.0)):
            value = payload()
            value["query_vector"][0] = component
            self.assert_invalid(value)
        self.assert_invalid(payload(), query=StringSubclass(QUERY))

    def test_normalization_is_stable_at_float_extremes(self) -> None:
        for vector in (
            [sys.float_info.max, sys.float_info.max],
            [1e-308, 1e-308],
            [5e-324, 5e-324],
            [-(1 << 1023), 1 << 1023],
        ):
            value = payload()
            value["query_vector"] = vector
            value["items"][0]["vector"] = vector
            result = parse_semantic_input(value, query=QUERY)
            self.assertAlmostEqual(abs(result.query_vector[0]), math.sqrt(0.5))
            self.assertAlmostEqual(math.hypot(*result.query_vector), 1.0)
            self.assertEqual(result.query_vector, result.items[0].vector)
        value = payload()
        value["query_vector"] = [5e-324, 1e-323]
        result = parse_semantic_input(value, query=QUERY)
        self.assertAlmostEqual(result.query_vector[0], 1 / math.sqrt(5))
        self.assertAlmostEqual(result.query_vector[1], 2 / math.sqrt(5))

    def test_serialized_size_exact_boundary_uses_utf8_not_character_count(self) -> None:
        value = payload()
        value["model"] = "modèle-東京"
        encoded_size = len(
            json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        )
        with patch.object(semantic_vectors, "_MAX_SERIALIZED_BYTES", encoded_size):
            self.assertIsNotNone(parse_semantic_input(value, query=QUERY))
        with patch.object(semantic_vectors, "_MAX_SERIALIZED_BYTES", encoded_size - 1):
            self.assert_invalid(value)

    def test_actual_two_mebibyte_limit_rejects_otherwise_valid_input(self) -> None:
        value = payload()
        vector = [0.12345678901234567] * 2048
        item = value["items"][0]
        value["query_vector"] = vector
        value["items"] = [
            {**item, "id": f"card_{index}", "vector": vector} for index in range(64)
        ]
        self.assertGreater(
            len(json.dumps(value, separators=(",", ":")).encode("utf-8")),
            2 * 1024 * 1024,
        )
        self.assertRegex(str(self.assert_invalid(value)), "2 MiB")

    def test_serialization_is_streamed_not_a_whole_document_copy(self) -> None:
        with patch.object(
            json, "dumps", side_effect=AssertionError("whole-document serialization")
        ):
            self.assertIsNotNone(parse_semantic_input(payload(), query=QUERY))

    def test_nested_and_cyclic_input_is_rejected_before_serialization(self) -> None:
        value = payload()
        value["query_vector"][0] = value
        self.assert_invalid(value)
        value = payload()
        value["items"] = [value]
        self.assert_invalid(value)

    def test_errors_do_not_echo_input_or_chained_validator_errors(self) -> None:
        marker = "private-input-must-not-appear"
        cases = []
        for field in ("model", "query_hash", "query_vector"):
            value = payload()
            value[field] = "file:///" + marker if field == "model" else marker
            cases.append(value)
        for field in ("kind", "id", "content_hash", "vector"):
            value = payload()
            value["items"][0][field] = "/" + marker
            cases.append(value)
        value = payload()
        value[marker] = marker
        cases.append(value)
        for value in cases:
            self.assertNotIn(marker, str(self.assert_invalid(value)))
        with patch.object(
            semantic_vectors,
            "validate_inference_model_identifier",
            side_effect=ValueError(marker),
        ):
            error = self.assert_invalid(payload())
        self.assertNotIn(marker, str(error))
        self.assertTrue(error.__suppress_context__)
        self.assertIsNone(error.__cause__)

    def test_parsing_and_scoring_do_no_io_or_model_calls(self) -> None:
        with (
            patch(
                "builtins.open", side_effect=AssertionError("unexpected file access")
            ),
            patch(
                "socket.socket", side_effect=AssertionError("unexpected network access")
            ),
            patch(
                "subprocess.Popen",
                side_effect=AssertionError("unexpected process access"),
            ),
            patch(
                "continuum.core.config.detect_hardware",
                side_effect=AssertionError("unexpected hardware access"),
            ),
        ):
            result = parse_semantic_input(payload(), query=QUERY)
            self.assertAlmostEqual(
                cosine_similarity(result.query_vector, result.items[0].vector), 0.96
            )


class CosineSimilarityTests(unittest.TestCase):
    def test_basic_direction_and_magnitude_invariance(self) -> None:
        for left, right, expected in (
            ((1.0, 0.0), (10.0, 0.0), 1.0),
            ((1.0, 0.0), (-10.0, 0.0), -1.0),
            ((1.0, 0.0), (0.0, 10.0), 0.0),
            ((3, 4), (4, 3), 0.96),
            ((-4.0,), (-2.0,), 1.0),
        ):
            self.assertAlmostEqual(cosine_similarity(left, right), expected)
            self.assertEqual(
                cosine_similarity(left, right), cosine_similarity(right, left)
            )

    def test_extreme_finite_values_do_not_overflow_or_underflow(self) -> None:
        for magnitude in (sys.float_info.max, 1e-308, 5e-324):
            self.assertEqual(
                cosine_similarity((magnitude, magnitude), (1.0, -1.0)), 0.0
            )
            self.assertAlmostEqual(
                cosine_similarity((magnitude, magnitude), (1.0, 1.0)), 1.0
            )
            self.assertAlmostEqual(
                cosine_similarity((magnitude, magnitude), (-1.0, -1.0)), -1.0
            )

    def test_rounding_never_escapes_closed_unit_interval(self) -> None:
        for dimension in (1, 2, 3, 5, 17, 100, 2048):
            vector = (1.0,) * dimension
            for other in (vector, tuple(-value for value in vector)):
                score = cosine_similarity(vector, other)
                self.assertTrue(math.isfinite(score))
                self.assertGreaterEqual(score, -1.0)
                self.assertLessEqual(score, 1.0)

    def test_compensated_sum_retains_small_cancellation_residue(self) -> None:
        self.assertAlmostEqual(
            cosine_similarity((1.0, 1e-8, 1.0), (1.0, 1e-8, -1.0)),
            5e-17,
            delta=1e-31,
        )

    def test_invalid_tuple_inputs_fail_without_custom_iteration(self) -> None:
        for invalid in (
            (),
            (0,),
            (0.0, -0.0),
            (True, 1),
            ("1", 2),
            (float("nan"), 1),
            (float("inf"), 1),
            (1 << 10000, 1),
            (ExplosiveValue(), 1),
            [1, 2],
            None,
            ExplosiveValue(),
            (1,) * 2049,
        ):
            with self.assertRaises(ValueError):
                cosine_similarity(invalid, (1.0, 2.0))
            with self.assertRaises(ValueError):
                cosine_similarity((1.0, 2.0), invalid)

    def test_mismatched_dimensions_fail(self) -> None:
        with self.assertRaises(ValueError):
            cosine_similarity((1.0,), (1.0, 2.0))


if __name__ == "__main__":
    unittest.main()
