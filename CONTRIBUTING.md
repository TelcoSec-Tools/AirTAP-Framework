# Contributing to AirTap

Thank you for your interest in contributing to **AirTap**! We welcome bug fixes, protocol dissectors, hardware support, diagnostic decoders, and documentation improvements.

---

## Code of Conduct & Ethical Guidelines

AirTap is a telecommunications security and radio diagnostics framework. Contributors must adhere to strict ethical and legal standards:
- All contributions must be intended for research, authorized diagnostics, security defense, and educational purposes.
- Contributions must respect user privacy.
- Code submissions must comply with the [GNU General Public License v3.0](LICENSE).

---

## Development Setup

1. **Fork and Clone the Repository**:
   ```bash
   git clone https://github.com/<your-username>/AirTAP-Framework.git
   cd AirTAP-Framework
   ```

2. **Create a Virtual Environment**:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install Dependencies in Editable Mode**:
   ```bash
   pip install --upgrade pip
   pip install -e .[dev]
   ```

---

## Running the Test Suite

AirTap includes a comprehensive automated test suite testing protocol parsers, GSMTAP encapsulation, SIB decoding, EFS shell commands, radio security rules, and malformed packet robustness.

You can run the tests using either `pytest` or Python's built-in `unittest` runner:

```bash
# Using pytest (recommended):
pytest

# Using the unittest runner:
python tests/tests.py

# Or via unittest discovery:
python -m unittest discover -s tests
```

All 113+ unit tests must pass cleanly before submitting a pull request.

---

## Coding Standards & Conventions

- **Python Version Compatibility**: AirTap supports Python 3.8 through Python 3.13 (the versions exercised by CI). Avoid using features exclusive to newer Python versions without backwards-compatible fallbacks.
- **Lazy Logging**: For high-throughput capture paths (such as `_base_input.py` and `usb_modem_pyserial.py`), defer byte-formatting and debug string construction to avoid CPU overhead when debug mode is disabled.
- **Error Robustness**: Modem serial streams can deliver partial, corrupt, or interleaved frames. Parsers should gracefully handle truncated data without crashing the main capture loop.
- **No Mockup Code**: Do not commit placeholder or stub code. All features should be fully functional with accompanying unit tests.

---

## Pull Request Guidelines

1. **Create a Feature Branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Write Unit Tests**:
   - Add test cases in `tests/tests_<module_name>.py`.
   - Ensure boundary conditions, malformed frames, and standard payloads are tested.

3. **Validate Locally**:
   ```bash
   python -m compileall src tests
   pytest
   python tests/tests.py
   ```

4. **Submit a Pull Request**:
   - Fill out the PR template with a clear description of the change, tested hardware/modems, and test results.
   - Link any related GitHub issues.

---

## Questions, Support & Training

Feel free to open an issue for questions or feature discussions. For security vulnerability disclosures, please refer to our [Security Policy](SECURITY.md).

For professional telecom security training and research labs, explore **[TelcoSec Academy (app.telcosec.net)](https://app.telcosec.net)**.

