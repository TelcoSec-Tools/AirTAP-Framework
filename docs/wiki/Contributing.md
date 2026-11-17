# Contributing

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for the full policy. This page covers the
practical conventions that catch people out.

---

## Setup

```bash
git clone https://github.com/TelcoSec-Tools/AirTAP-Framework.git
cd AirTAP-Framework
pip install -e ".[dev]"
```

Optional tooling for the full suite:

```bash
pip install lupa      # Lua interpreter tests (skip cleanly without it)
# Node.js             # GUI frontend tests (skip cleanly without it)
```

## Testing

```bash
pytest                                        # 302 tests
python tests/tests.py                         # unittest runner
python -m unittest discover -s tests
pytest tests/tests_sec_audit.py               # one file
python -m compileall src tests                # what CI lints
flake8 src tests --select=E9,F63,F7,F82
```

Both runners are canonical; CI runs both across Linux, Windows and macOS on Python
3.9–3.13.

---

## Conventions

**Python 3.9+.** Avoid syntax or stdlib features newer than 3.9 without a fallback.

**Lazy logging on hot paths.** In `_base_input.py` and `usb_modem_pyserial.py`, defer
byte formatting and debug-string construction so it costs nothing when debug logging is
off.

**Degrade, never crash.** DIAG and serial streams deliver partial, corrupt and
interleaved frames. A parser that raises into the main capture loop ends the capture.

**No stub code.** New features need tests in `tests/tests_<module>.py` covering boundary
conditions and malformed frames, not just the happy path.

---

## Lua dissectors

**Always include the bitwise compatibility shim** if your dissector uses bitwise
operations. Copy it from any bundled file. Without it the dissector works on your
Wireshark and fails silently on a different version — globals resolve at call time, so
it loads cleanly and then dies on the first matching packet.

**Never drive an alert from a hex substring search.** Read the decoded field via
`Field.new()` where the native dissector provides one, or walk the TLV to the element's
defined offset. Searching a bit-packed ASN.1 payload matches at any nibble offset
regardless of field position; a one-byte pattern hits most arbitrary PDUs by chance.
`tests_wireshark_lua_runtime.py` enforces this across all 107 dissectors.

**Keep per-packet accumulators per-packet.** A `local alerts = {}` filled by
`table.insert` must stay inside the dissect function. Hoisting it to module scope makes
findings accumulate across every packet in the capture.

Test with:

```bash
pytest tests/tests_wireshark_lua_runtime.py
```

which compiles all 107 dissectors under a real Lua 5.3+ interpreter and drives a sample
against crafted frames.

---

## Documentation

These wiki pages live in `docs/wiki/` so they are versioned with the code and reviewed
in the same pull requests. Update them alongside behaviour changes.

## Releasing

Releases are cut by pushing a version tag. `.github/workflows/release.yml` then
builds, validates and publishes.

```bash
# 1. Bump the single source of truth
#    src/__init__.py  ->  __version__ = '2.7.0'
# 2. Add a CHANGELOG entry
# 3. Merge to master and wait for CI to go green
# 4. Tag and push
git tag -a v2.7.0 -m "AirTap 2.7.0"
git push origin v2.7.0
```

The workflow refuses to publish if the tag disagrees with `__version__`. A PyPI
version can never be reused once uploaded, so that gate exists to stop a
mismatched release becoming permanent.

Before uploading it also:

- builds on Linux (a Windows-built wheel loses the executable bit on the bundled
  `adb` binaries);
- runs `twine check`;
- asserts the wheel exposes exactly one top-level package, `airtap`, and that the
  107 `.lua` dissectors and executable `adb` binaries are present;
- installs the wheel into a clean virtualenv and confirms `import airtap`, the
  console script, and dissector discovery all work.

That last check exists because a previous build installed `src/`'s subdirectories
as top-level packages: `pip install` succeeded while `import airtap` failed.

### PyPI Trusted Publishing

No API token is stored. PyPI mints a short-lived credential from the workflow's
OIDC identity, so there is no long-lived secret to leak or rotate.

One-time setup on PyPI (https://pypi.org/manage/account/publishing/):

| Field | Value |
| :--- | :--- |
| PyPI project name | `airtap` |
| Owner | `TelcoSec-Tools` |
| Repository | `AirTAP-Framework` |
| Workflow name | `release.yml` |
| Environment | `pypi` |

Then create a repository environment named `pypi` under **Settings → Environments**.
Adding required reviewers there gives a manual approval gate before every upload.

To rehearse without touching the real index, run the workflow manually
(**Actions → Release → Run workflow**) and select `testpypi`.

---

## Pull requests

CI must be green — lint, the 15-job test matrix, and the build job that verifies the
wheel contains the `.lua` dissectors and that `adb_linux` / `adb_macos` keep their
executable bits.
