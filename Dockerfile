# ==============================================================================
# AirTap Framework - TelcoSec
# Cellular radio diagnostics & packet capture for 2G/3G/4G/5G basebands
#
# Build:
#   docker build -t telcosec/airtap:2.6.0 -t telcosec/airtap:latest .
#
# Run (full hardware access, see docker-compose.yml for the easy path):
#   docker run --rm -it --privileged \
#     -v /dev/bus/usb:/dev/bus/usb -v /run/udev:/run/udev:ro \
#     -v "$PWD/captures:/captures" telcosec/airtap --adb --pcap-dump /captures/c.pcap
#
# Two stages: the builder compiles wheels (pycrate has a build step), the
# runtime carries only the installed result. Keeps the image to ~400MB with
# tshark instead of ~1.2GB with build toolchain + full Wireshark GUI.
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 1: build the dependency wheels
# ------------------------------------------------------------------------------
FROM python:3.12-slim-trixie AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

# gcc/python3-dev: pycrate ships C extensions. libusb dev headers let pyusb
# resolve its backend at build time rather than failing at import.
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libc6-dev \
        python3-dev \
        libusb-1.0-0-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy only the dependency manifests first so this layer caches across
# source edits - the expensive compile is not redone when src/ changes.
COPY requirements.txt ./

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip setuptools wheel \
    && /opt/venv/bin/pip install -r requirements.txt

# Now add the project itself and install it so the `airtap` console script
# exists on PATH with correct package-dir mapping (src -> airtap).
COPY pyproject.toml setup.py MANIFEST.in README.md LICENSE CHANGELOG.md ./
COPY src ./src

# Verify the real import surface. Note pycrate installs NO top-level `pycrate`
# module - AirTap uses pycrate_core and the pycrate_asn1dir RRC specs, so those
# are what must be checked. RRCNR/RRCLTE are the expensive ASN.1 dirs that
# decode 5G NR and LTE RRC; importing them here fails the build early rather
# than at first capture.
RUN /opt/venv/bin/pip install --no-deps . \
    && /opt/venv/bin/python -c "\
import airtap, serial, usb.core, crcmod; \
from pycrate_core.utils import pack_val; \
from pycrate_asn1dir import RRC3G, RRCLTE, RRCNR; \
print('deps OK, airtap', airtap.__version__)"

# ------------------------------------------------------------------------------
# Stage 2: runtime
# ------------------------------------------------------------------------------
FROM python:3.12-slim-trixie AS runtime

LABEL org.opencontainers.image.title="AirTap Framework" \
      org.opencontainers.image.description="Cellular radio diagnostics and packet capture framework for 2G/3G/4G/5G basebands" \
      org.opencontainers.image.vendor="TelcoSec" \
      org.opencontainers.image.source="https://github.com/TelcoSec-Tools/AirTAP-Framework" \
      org.opencontainers.image.licenses="GPL-3.0-only" \
      org.opencontainers.image.documentation="https://github.com/TelcoSec-Tools/AirTAP-Framework#readme"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    AIRTAP_IN_DOCKER=1 \
    HOME=/root

# Runtime packages only - no compilers.
#   libusb-1.0-0      : pyusb backend for direct USB DIAG interface access
#   usbutils          : lsusb, for confirming the baseband enumerated
#   adb               : adb client (called android-tools-adb before trixie);
#                       AirTap prefers a PATH adb over its bundled copy
#   tshark            : headless Wireshark for dissecting captures in-container.
#                       Must link Lua 5.4 - see the dissector note below.
#   socat             : relays the GUI's hardcoded 127.0.0.1 bind to 0.0.0.0
#   udev/usb-modeswitch: device node metadata + flipping modems out of
#                        storage mode into their DIAG composition
RUN apt-get update && apt-get install -y --no-install-recommends \
        libusb-1.0-0 \
        usbutils \
        adb \
        socat \
        udev \
        usb-modeswitch \
        usb-modeswitch-data \
        ca-certificates \
        procps \
        tini \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv

# The repo is kept at /opt/airtap for its Lua dissectors, docs and tools, but
# is deliberately NOT the working directory: the repo root holds a dev launcher
# `airtap.py`, and with it on sys.path[0] `import airtap` resolves to that
# 7-line shim instead of the installed package - breaking airtap.__version__
# and any `from airtap.x import y`. Work from /captures instead.
COPY . /opt/airtap
WORKDIR /captures

# Install the bundled GSMTAP Lua dissectors into the location tshark reads, so
# captures decode as LTE/NR RRC and NAS rather than raw UDP payloads.
#
# IMPORTANT - this is why the base image is trixie, not bookworm: these
# dissectors use native Lua bitwise operators (&, |, ~, <<, >>), which are a
# PARSE error before Lua 5.3. Bookworm's tshark 4.0 links liblua5.2 and every
# plugin fails to load with "'end' expected near '&'"; trixie's tshark 4.4
# links liblua5.4 and they load clean. The build asserts this below, so a base
# image bump that regresses the Lua version fails here rather than silently
# shipping an image that decodes RRC as raw UDP.
RUN mkdir -p /root/.local/lib/wireshark/plugins /captures \
    && cp -f /opt/airtap/src/modules/wireshark_plugin/*.lua \
             /root/.local/lib/wireshark/plugins/ 2>/dev/null || true \
    && tshark -G protocols >/dev/null 2>/tmp/lua.err || true; \
    if grep -qiE 'lua|syntax error' /tmp/lua.err; then \
        echo "ERROR: tshark rejected the bundled Lua dissectors:" >&2; \
        grep -iE 'lua|syntax error' /tmp/lua.err >&2; \
        exit 1; \
    fi; \
    echo "Lua dissectors loaded cleanly ($(ls /root/.local/lib/wireshark/plugins/*.lua | wc -l) files, $(tshark --version | head -1))"

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh \
    && chmod +x /opt/airtap/src/inputs/external/adb/adb_linux 2>/dev/null || true

# Captures land here; mount a host directory over it to keep them.
VOLUME ["/captures"]

# AirTap Visual Operations Suite (GUI). The app itself binds 127.0.0.1:5000,
# which is unreachable from outside, so the entrypoint runs a socat relay on
# 0.0.0.0:5080 -> 127.0.0.1:5000. Publish 5080, not 5000:
#   docker run -p 5000:5080 ... --gui   ->  http://localhost:5000
EXPOSE 5080

# Runs as root deliberately: raw USB endpoint access and `adb root` against a
# baseband are not delegable to an unprivileged user in a throwaway container.

# tini reaps the adb server and Wireshark/socat children AirTap spawns, so
# Ctrl-C closes the pcap cleanly instead of leaving a truncated file.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/docker-entrypoint.sh"]
CMD ["--help"]
