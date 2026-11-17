#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

"""
    AirTap - Packaging & Release Metadata Test Suite

    Guards defects that only appear in an installed artifact, never when
    running from a source checkout, and so survive a fully green test run.

    The motivating bug: pyproject.toml declared both `package-dir`
    (airtap = src) and `packages.find` (where = src). The latter wins, so
    setuptools installed src/'s subdirectories as the top-level names
    `inputs`, `modules` and `protocol`. `pip install airtap` then succeeded
    while `import airtap` and the console script both failed with
    ModuleNotFoundError, and three generic names were squatted in any
    environment the wheel touched. Every test passed throughout, because the
    source tree imports fine either way.
"""

import os
import re
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(name):
    with open(os.path.join(REPO, name), encoding="utf-8") as fd:
        return fd.read()


def load_pyproject():
    try:
        import tomllib
    except ImportError:  # Python < 3.11
        try:
            import tomli as tomllib
        except ImportError:
            return None
    with open(os.path.join(REPO, "pyproject.toml"), "rb") as fd:
        return tomllib.load(fd)


class TestPackageLayout(unittest.TestCase):
    """The wheel must install exactly one top-level package: airtap."""

    def setUp(self):
        self.cfg = load_pyproject()
        if self.cfg is None:
            self.skipTest("no TOML parser available (Python < 3.11 without tomli)")
        self.setuptools = self.cfg.get("tool", {}).get("setuptools", {})

    def test_package_dir_maps_airtap_to_src(self):
        self.assertEqual(self.setuptools.get("package-dir"), {"airtap": "src"})

    def test_packages_are_listed_explicitly(self):
        """Auto-discovery under src/ silently overrides the package-dir map."""
        packages = self.setuptools.get("packages")
        self.assertIsNotNone(packages, "no explicit package list in pyproject.toml")
        self.assertIsInstance(
            packages, list,
            "packages must be an explicit list, not a find/auto-discovery table; "
            "`packages.find` with where=src installs src/'s subdirectories as "
            "top-level packages and breaks `import airtap`")

    def test_every_package_is_namespaced_under_airtap(self):
        for pkg in self.setuptools.get("packages", []):
            self.assertTrue(
                pkg == "airtap" or pkg.startswith("airtap."),
                "%r would install as a top-level name and collide with "
                "unrelated distributions" % pkg)

    def test_source_subpackages_are_all_declared(self):
        """A new src/ subpackage must be added to the install list."""
        declared = set(self.setuptools.get("packages", []))
        src = os.path.join(REPO, "src")
        for root, dirs, files in os.walk(src):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            if "__init__.py" not in files:
                continue
            rel = os.path.relpath(root, src).replace(os.sep, ".")
            name = "airtap" if rel == "." else "airtap." + rel
            self.assertIn(name, declared,
                          "%s has an __init__.py but is not in the install "
                          "list; it will be missing from the wheel" % name)

    def test_entry_point_targets_the_airtap_package(self):
        scripts = self.cfg.get("project", {}).get("scripts", {})
        self.assertEqual(scripts.get("airtap"), "airtap.main:main")


class TestVersionConsistency(unittest.TestCase):
    """One version of record, surfaced everywhere else dynamically."""

    def setUp(self):
        self.version = re.search(
            r"^__version__\s*=\s*'([^']+)'", read(os.path.join("src", "__init__.py")),
            re.MULTILINE).group(1)

    def test_pyproject_reads_version_from_package(self):
        cfg = load_pyproject()
        if cfg is None:
            self.skipTest("no TOML parser available")
        dynamic = cfg.get("tool", {}).get("setuptools", {}).get("dynamic", {})
        self.assertEqual(dynamic.get("version"), {"attr": "airtap.__version__"})

    def test_gui_does_not_hardcode_a_version(self):
        """index.html drifted to three different hardcoded versions.

        The asset cache-busting query and the brand badge are now templated
        and stamped by the server from the running package version.
        """
        html = read(os.path.join("src", "modules", "gui_assets", "index.html"))
        stale = re.findall(r'\?v=(\d+\.\d+\.\d+)', html)
        self.assertEqual(stale, [],
                         "hardcoded asset version(s) %s in index.html; use "
                         "{{AIRTAP_VERSION}}" % stale)
        self.assertIn("{{AIRTAP_VERSION}}", html)

    def test_server_substitutes_the_version_placeholder(self):
        server = read(os.path.join("src", "modules", "gui_server.py"))
        self.assertIn("{{AIRTAP_VERSION}}", server,
                      "gui_server.py does not stamp the version into the HTML")


class TestReleaseMetadata(unittest.TestCase):
    """Claims in the metadata must match what CI actually verifies."""

    def test_python_requirement_matches_ci_matrix(self):
        cfg = load_pyproject()
        if cfg is None:
            self.skipTest("no TOML parser available")
        requires = cfg["project"]["requires-python"]

        ci_path = os.path.join(REPO, ".github", "workflows", "ci.yml")
        if not os.path.exists(ci_path):
            self.skipTest("no CI workflow to compare against")
        ci = read(os.path.join(".github", "workflows", "ci.yml"))
        tested = sorted(set(re.findall(r"'(3\.\d+)'", ci)),
                        key=lambda v: int(v.split(".")[1]))
        self.assertTrue(tested, "could not parse the CI python matrix")

        floor = re.search(r">=\s*(\d+\.\d+)", requires)
        self.assertIsNotNone(floor, "requires-python has no lower bound")
        self.assertEqual(
            floor.group(1), tested[0],
            "requires-python claims %s but CI's lowest tested version is %s; "
            "an untested floor breaks for users pip resolves onto it"
            % (floor.group(1), tested[0]))

    def test_classifiers_do_not_claim_untested_versions(self):
        cfg = load_pyproject()
        if cfg is None:
            self.skipTest("no TOML parser available")
        claimed = {c.rsplit(" :: ", 1)[-1]
                   for c in cfg["project"]["classifiers"]
                   if c.startswith("Programming Language :: Python :: 3.")}
        ci = read(os.path.join(".github", "workflows", "ci.yml"))
        tested = set(re.findall(r"'(3\.\d+)'", ci))
        self.assertTrue(
            claimed.issubset(tested),
            "classifiers claim untested Python versions: %s"
            % sorted(claimed - tested))

    def test_setup_py_agrees_with_pyproject(self):
        """Both files ship; a divergence is a silent, build-order-dependent bug."""
        cfg = load_pyproject()
        if cfg is None:
            self.skipTest("no TOML parser available")
        setup = read("setup.py")

        floor = re.search(r">=\s*(\d+\.\d+)", cfg["project"]["requires-python"]).group(1)
        self.assertIn("python_requires = '>=%s'" % floor, setup,
                      "setup.py python_requires disagrees with pyproject.toml")

    def test_repository_urls_are_consistent(self):
        """A wrong clone URL makes the documented install fail."""
        seen = set()
        for name in ("README.md", "pyproject.toml", "setup.py"):
            seen.update(re.findall(
                r"github\.com/([A-Za-z0-9_.-]+/AirTAP-Framework)", read(name)))
        self.assertLessEqual(
            len(seen), 1,
            "conflicting repository URLs across release metadata: %s" % sorted(seen))

    def test_no_secret_bearing_files_are_tracked(self):
        """Cheap guard against a credential landing in a public repo."""
        import subprocess
        try:
            out = subprocess.run(["git", "ls-files"], cwd=REPO,
                                 capture_output=True, text=True, timeout=30)
        except Exception:
            self.skipTest("git unavailable")
        if out.returncode != 0:
            self.skipTest("not a git checkout")

        bad = re.compile(
            r"(^|/)(\.env|secrets\.json|credentials\.json|auth\.json|tokens\.json|"
            r"id_rsa|id_ed25519)$|\.(pem|p12|pfx|pkcs12)$")
        offenders = [f for f in out.stdout.splitlines() if bad.search(f)]
        self.assertEqual(offenders, [],
                         "credential-bearing files are tracked: %s" % offenders)


if __name__ == "__main__":
    unittest.main()
