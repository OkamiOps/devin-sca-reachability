import unittest

from sca_reachability.errors import InputError
from sca_reachability.models import Component
from sca_reachability.osv import parse_batch_response


class OsvResponseTests(unittest.TestCase):
    def setUp(self):
        self.components = (
            Component(purl="pkg:pypi/demo@1.0", version="1.0"),
        )

    def test_parses_empty_result(self):
        self.assertEqual(
            parse_batch_response({"results": [{}]}, self.components),
            ((),),
        )

    def test_parses_vulnerability(self):
        parsed = parse_batch_response(
            {"results": [{"vulns": [{"id": "DEMO-0001"}]}]},
            self.components,
        )

        self.assertEqual(parsed[0][0].id, "DEMO-0001")

    def test_rejects_result_count_mismatch(self):
        with self.assertRaisesRegex(InputError, "result count"):
            parse_batch_response({"results": []}, self.components)

    def test_rejects_query_echo_out_of_order_or_mismatched(self):
        response = {
            "queries": [
                {
                    "package": {"purl": "pkg:pypi/other@1.0"},
                    "version": "1.0",
                }
            ],
            "results": [{}],
        }
        with self.assertRaisesRegex(InputError, "does not match"):
            parse_batch_response(response, self.components)

    def test_rejects_non_array_query_echo(self):
        with self.assertRaisesRegex(InputError, "queries.*JSON array"):
            parse_batch_response(
                {"queries": None, "results": [{}]},
                self.components,
            )

    def test_rejects_explicit_error_result(self):
        with self.assertRaisesRegex(InputError, "contains an error"):
            parse_batch_response(
                {"results": [{"error": "fixture failure"}]},
                self.components,
            )

    def test_rejects_nonempty_pagination_token(self):
        with self.assertRaisesRegex(InputError, "next_page_token"):
            parse_batch_response(
                {"results": [{"next_page_token": "continue-here"}]},
                self.components,
            )

    def test_rejects_malformed_vulnerability(self):
        with self.assertRaisesRegex(InputError, "non-empty 'id'"):
            parse_batch_response(
                {"results": [{"vulns": [{"summary": "missing id"}]}]},
                self.components,
            )
