from __future__ import annotations

import unittest

from vuln_pipeline.normalize.core import normalize_path_pattern, normalize_query_keys


class NormalizeTests(unittest.TestCase):
    def test_path_generalization(self) -> None:
        self.assertEqual(normalize_path_pattern("/users/123"), "/users/{id}")
        self.assertEqual(
            normalize_path_pattern("/files/550e8400-e29b-41d4-a716-446655440000"),
            "/files/{uuid}",
        )
        self.assertEqual(
            normalize_path_pattern("/tokens/abcdef1234567890abcdef1234567890"),
            "/tokens/{hex}",
        )

    def test_query_key_normalization(self) -> None:
        self.assertEqual(normalize_query_keys("https://a.test/search?B=1&a=2"), ["a", "b"])


if __name__ == "__main__":
    unittest.main()

