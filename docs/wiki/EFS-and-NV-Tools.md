# EFS & NV Tools

Direct access to the baseband's filesystem and non-volatile configuration.

> ⚠️ **NV writes are persistent and can brick a modem.** They survive reboots and
> factory resets. Record the original value before changing anything, and only operate
> on hardware you own.

---

## EFS filesystem shell

```bash
airtap --shell
```

An interactive shell over the modem's EFS2 filesystem.

| Command | Action |
| :--- | :--- |
| `ls [path]` | List entries with permissions and type |
| `cd <path>` | Change directory |
| `cat <file>` | Print file contents |
| `get <file>` | Download to the local machine |
| `stat <path>` | File metadata |
| `statfs` | Filesystem capacity |
| `find <query>` | Recursive search |
| `exit` | Leave the shell |

Non-interactive dump:

```bash
airtap --dump-fs ./efs_backup
```

### What lives there

| Path | Contents |
| :--- | :--- |
| `/nv` | NV item backing store |
| `/sim` | SIM/USIM mirrors (`ef_imsi.bin`, `ef_msisdn.bin`) |
| `/ims` | IMS/VoLTE config: `sip_config.xml`, `volte_apn.xml`, `aka_challenge_profile.dat` |
| `/policyman` | Carrier policy: `carrier_policy.xml`, `volte_policy.xml`, `seg_rules.xml` |

These are the richest forensic artefacts on a modem — carrier provisioning, IMS
configuration, and band policy all live here.

---

## NV items

```bash
airtap --nv-read 850            # read one item
airtap --nv-dump ./nv_backup    # dump the common set
```

NV items are numbered configuration slots. Frequently inspected ones:

| ID | Meaning |
| :--- | :--- |
| 10 | ESN / serial |
| 550 | Band preference (legacy) |
| 850 | Roaming list reference |
| 1877 | 2G/3G RF band configuration mask |
| 6828 / 6829 | LTE band mask |
| 71502 | 5G NR band mask |

Writing is available through the GUI's **NV & Bands** tab, which exposes band masks as
checkboxes and carrier presets rather than raw hex — considerably harder to get wrong
than hand-assembling a mask.

---

## Band locking

The **NV & Bands** tab configures which RF bands the modem will use: 2G/3G, LTE, and
5G NR including mmWave (n1…n261), plus SA/NSA mode control.

Legitimate uses include forcing a specific band for measurement, reproducing a coverage
problem, and testing fallback behaviour.

**Before changing anything:** dump the current configuration.

```bash
airtap --nv-dump ./nv_before_changes
```

An incorrect band mask can leave a modem unable to attach to any network. Recovery
means restoring the original NV values — which you will only have if you saved them.

---

## SIM & Keys

The GUI's **SIM & Keys** tab inventories the UICC card profile and the key material the
baseband holds. Secrets are redacted by default and revealed only per field; Ki and OPc
are reported as sealed because they are not extractable in principle.

See [Visual Operations Suite](Visual-Operations-Suite.md#sim--keys).

## See also

- [CLI Reference](CLI-Reference.md) — all EFS and NV flags
- [Architecture](Architecture.md) — EFS2 protocol implementation
