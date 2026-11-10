import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import update_lifecycle as updater


POLICY = {"vendor_url": "https://vendor.example/support", "eol_label": "Security Support"}


def feed(product="fedora", **release_changes):
    release = {"name": "38", "releaseDate": "2023-04-18", "eolFrom": "2024-05-21",
               "eoasFrom": "2023-12-01", "eoesFrom": "2028-01-01"}
    release.update(release_changes)
    return {"schema_version": "1.2.1", "result": {
        "name": product, "labels": {"eol": "Security Support"}, "releases": [release]}}


class LifecycleRefreshTests(unittest.TestCase):
    def test_selects_security_support_not_feature_or_paid_support(self):
        product = updater.normalize_product("fedora", POLICY, feed())
        self.assertEqual(product["releases"]["38"]["end"], "2024-05-21")
        self.assertEqual(product["source"], updater.API + "fedora")

    def test_preserves_unknown_cutoff_without_inventing_a_date(self):
        product = updater.normalize_product("fedora", POLICY, feed(eolFrom=None))
        self.assertIsNone(product["releases"]["38"]["end"])

    def test_rejects_bad_or_boolean_dates(self):
        for value in [True, False, "2024-02-30", "2024-5-21", "", 123]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                updater.normalize_product("fedora", POLICY, feed(eolFrom=value))

    def test_rejects_date_before_release(self):
        with self.assertRaisesRegex(ValueError, "before release"):
            updater.normalize_product("fedora", POLICY, feed(eolFrom="2000-01-01"))

    def test_rejects_semantic_schema_and_identity_changes(self):
        payloads = [feed(), feed(), feed()]
        payloads[0]["schema_version"] = "2.0.0"
        payloads[1]["result"]["name"] = "ubuntu"
        payloads[2]["result"]["labels"]["eol"] = "Paid Extended Support"
        for payload in payloads:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                updater.normalize_product("fedora", POLICY, payload)

    def test_rejects_empty_or_duplicate_releases(self):
        for releases in [[], [feed()["result"]["releases"][0]] * 2]:
            payload = feed()
            payload["result"]["releases"] = releases
            with self.assertRaises(ValueError):
                updater.normalize_product("fedora", POLICY, payload)

    def test_windows_uses_latest_service_pack_without_collapsing_r2(self):
        releases = {"2003": {"end": "2007-04-10"}, "2003-sp2": {"end": "2015-07-14"},
                    "2008": {"end": "2011-07-12"}, "2008-r2-sp1": {"end": "2020-01-14"}}
        result = updater.windows_release_families(releases)
        self.assertEqual(result["2003"], {"end": "2015-07-14"})
        self.assertEqual(result["2003-r2"], result["2003"])
        self.assertEqual(result["2008"], {"end": "2011-07-12"})
        self.assertEqual(result["2008-r2"], {"end": "2020-01-14"})

    def test_windows_unknown_service_pack_prevents_eol_verdict(self):
        result = updater.windows_release_families({"2003": {"end": "2007-04-10"}, "2003-sp2": {"end": None}})
        self.assertIsNone(result["2003"]["end"])

    def test_unchanged_data_keeps_original_timestamp(self):
        old = updater.refresh({"fedora": POLICY}, None, lambda _: feed(), "2026-01-01T00:00:00Z")
        same = updater.refresh({"fedora": POLICY}, old, lambda _: feed(), "2026-01-08T00:00:00Z")
        self.assertEqual(same, old)

    def test_date_change_updates_timestamp(self):
        old = updater.refresh({"fedora": POLICY}, None, lambda _: feed(), "2026-01-01T00:00:00Z")
        new = updater.refresh({"fedora": POLICY}, old, lambda _: feed(eolFrom="2024-06-01"), "2026-01-08T00:00:00Z")
        self.assertEqual(new["refreshed_at"], "2026-01-08T00:00:00Z")
        self.assertEqual(new["products"]["fedora"]["releases"]["38"]["end"], "2024-06-01")

    def test_rejects_disappearing_release_or_date(self):
        old = updater.refresh({"fedora": POLICY}, None, lambda _: feed())
        for changes in [{"name": "39"}, {"eolFrom": None}]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                updater.refresh({"fedora": POLICY}, old, lambda _: feed(**changes))

    def test_rejects_disappearing_product(self):
        old = updater.refresh({"fedora": POLICY}, None, lambda _: feed())
        with self.assertRaisesRegex(ValueError, "remove product"):
            updater.refresh({}, old, lambda _: feed())

    def test_failed_download_keeps_existing_file_byte_identical(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "snapshot.json"
            old = updater.refresh({"fedora": POLICY}, None, lambda _: feed())
            updater.write_snapshot(output, old)
            original = output.read_bytes()
            sources = Path(directory) / "sources.json"
            sources.write_text(json.dumps({"fedora": POLICY}))
            with patch.object(updater, "SOURCES", sources), patch.object(updater, "fetch_json", side_effect=OSError("offline")), patch("sys.argv", ["update_lifecycle.py", "--output", str(output)]):
                with self.assertRaises(OSError):
                    updater.main()
            self.assertEqual(output.read_bytes(), original)

    def test_failed_atomic_replace_keeps_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "snapshot.json"
            output.write_text("known good\n")
            with patch.object(updater.os, "replace", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    updater.write_snapshot(output, {"new": "data"})
            self.assertEqual(output.read_text(), "known good\n")
            self.assertEqual(list(Path(directory).iterdir()), [output])

    def test_new_releases_are_discovered_without_code_changes(self):
        old = updater.refresh({"fedora": POLICY}, None, lambda _: feed())
        payload = feed()
        extra = copy.deepcopy(payload["result"]["releases"][0])
        extra["name"] = "39"
        payload["result"]["releases"].append(extra)
        new = updater.refresh({"fedora": POLICY}, old, lambda _: payload)
        self.assertIn("39", new["products"]["fedora"]["releases"])


if __name__ == "__main__":
    unittest.main()
