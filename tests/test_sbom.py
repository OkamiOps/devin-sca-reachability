import unittest

from sca_reachability.errors import InputError
from sca_reachability.sbom import parse_cyclonedx


class CycloneDXTests(unittest.TestCase):
    def test_parses_components_with_purl_and_version(self):
        components = parse_cyclonedx(
            {
                "bomFormat": "CycloneDX",
                "components": [
                    {
                        "name": "demo",
                        "purl": "pkg:pypi/demo@1.0",
                        "version": "1.0",
                    }
                ],
            }
        )

        self.assertEqual(components[0].purl, "pkg:pypi/demo@1.0")
        self.assertEqual(components[0].version, "1.0")

    def test_accepts_empty_component_list(self):
        self.assertEqual(parse_cyclonedx({"bomFormat": "CycloneDX"}), ())

    def test_rejects_unsupported_format(self):
        with self.assertRaisesRegex(InputError, "CycloneDX"):
            parse_cyclonedx({"bomFormat": "SPDX", "components": []})

    def test_rejects_component_without_package_url(self):
        with self.assertRaisesRegex(InputError, "package URL"):
            parse_cyclonedx(
                {
                    "bomFormat": "CycloneDX",
                    "components": [{"version": "1.0"}],
                }
            )

    def test_rejects_empty_package_url(self):
        with self.assertRaisesRegex(InputError, "package URL"):
            parse_cyclonedx(
                {
                    "bomFormat": "CycloneDX",
                    "components": [{"purl": "pkg:", "version": "1.0"}],
                }
            )

    def test_rejects_nonempty_nested_components(self):
        with self.assertRaisesRegex(InputError, "nested components"):
            parse_cyclonedx(
                {
                    "bomFormat": "CycloneDX",
                    "components": [
                        {
                            "purl": "pkg:pypi/demo@1.0",
                            "version": "1.0",
                            "components": [
                                {
                                    "purl": "pkg:pypi/nested@1.0",
                                    "version": "1.0",
                                }
                            ],
                        }
                    ],
                }
            )

    def test_rejects_component_without_version(self):
        with self.assertRaisesRegex(InputError, "version"):
            parse_cyclonedx(
                {
                    "bomFormat": "CycloneDX",
                    "components": [{"purl": "pkg:pypi/demo"}],
                }
            )
