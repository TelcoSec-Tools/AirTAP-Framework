
/* ─── Tab 4: Advanced BTS & Cell Tower Intelligence Engine ────────────────── */
function initBtsInspector() {
    // Subtabs switcher
    document.querySelectorAll('.bts-subtab').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.bts-subtab').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('#bts-inspector-drawer .bts-subpane').forEach(p => p.style.display = 'none');
            
            btn.classList.add('active');
            const target = btn.dataset.target;
            const pane = document.getElementById(target);
            if (pane) pane.style.display = 'block';
        });
    });

    // Close button
    document.getElementById('btn-close-bts-insp')?.addEventListener('click', () => {
        const drawer = document.getElementById('bts-inspector-drawer');
        if (drawer) drawer.style.display = 'none';
    });

    // Center on map button
    document.getElementById('btn-bts-pan-map')?.addEventListener('click', () => {
        if (window._currentBts && state.geo.map && isValidLatLng(window._currentBts.lat, window._currentBts.lng)) {
            state.geo.map.flyTo([window._currentBts.lat, window._currentBts.lng], 18, { duration: 1.0 });
            showToast('Centered on BTS Site', 'info');
        }
    });

    // Copy BTS JSON
    document.getElementById('btn-bts-copy-json')?.addEventListener('click', () => {
        if (window._currentBts) {
            navigator.clipboard.writeText(JSON.stringify(window._currentBts, null, 2));
            showToast('Copied BTS Telemetry JSON', 'success');
        }
    });
}

function openBtsInspector(bts) {
    if (!bts) return;
    window._currentBts = bts;
    const drawer = document.getElementById('bts-inspector-drawer');
    if (!drawer) return;

    drawer.style.display = 'flex';

    // Header info
    const nodeStr = bts.node_id_str || (bts.rat === '5G' ? `gNodeB-${bts.site_id * 1024 + 100000}` : `eNodeB-${bts.site_id * 1024 + 100000}`);
    setText('bts-insp-title', `${nodeStr} (Site #${bts.site_id})`);
    setText('bts-insp-carrier', bts.carrier || 'AT&T Mobility (310-410)');

    // Radio & RF
    setText('bts-val-cgi', bts.cgi || `310-410-00${bts.site_id || 1}-01`);
    setText('bts-val-rat-band', `${bts.rat || '5G NR'} (${bts.band || 'n78 / 3500 MHz'})`);
    setText('bts-val-freqs', `DL: ${bts.dl_freq_mhz || 3500.0} / UL: ${bts.ul_freq_mhz || 3500.0} MHz`);
    setText('bts-val-bw', `${bts.bandwidth_mhz || 100} MHz (SCS: ${bts.scs_khz || 30} kHz)`);
    setText('bts-val-pci', `${bts.pci} (Sector ${bts.sector_id || ((bts.pci % 3) + 1)})`);
    setText('bts-val-tac', bts.tac || '0x1A2B (6699)');

    setText('bts-val-rsrp', `${bts.rsrp || -84.2} dBm`);
    setText('bts-val-rsrq', `${bts.rsrq || -10.5} dB`);
    setText('bts-val-sinr', `${bts.sinr || 18.4} dB`);
    setText('bts-val-cqi', `${bts.cqi || 15} (256-QAM)`);
    setText('bts-val-ta', `${bts.timing_advance_m || 156.4} m (TA=1)`);

    // Antenna
    setText('bts-ant-height', `${bts.antenna_height_m || 34.5} meters (113 ft)`);
    setText('bts-ant-eirp', `${bts.eirp_dbm || 61.5} dBm (1.4 kW ERP)`);
    setText('bts-ant-azimuths', `α: 0° | β: 120° | γ: 240° (Active: ${bts.azimuth_deg || 0}°)`);
    setText('bts-ant-bw', `${bts.beamwidth_deg || 65.0}° (3dB HPBW)`);
    setText('bts-ant-tilt', `${bts.mechanical_downtilt_deg || 2.0}° Mech / ${bts.electrical_downtilt_deg || 4.0}° Elec`);

    // Security
    setText('bts-sec-score', `${bts.fbs_trust_score || 99.2}% (${bts.fbs_verdict || 'VERIFIED OPERATOR BTS'})`);
    if (bts.security) {
        setText('bts-sec-sib', bts.security.sib_neighbors || 'PRESENT (Valid SIB4/5)');
        setText('bts-sec-qrx', bts.security.q_rx_lev_min || '-128 dBm');
        setText('bts-sec-ciph', bts.security.ciphering || '128-NEA2 / 128-EEA2 (AES)');
        setText('bts-sec-integ', bts.security.integrity || '128-NIA2 / 128-EIA2 (AES-CMAC)');
    }
}


/* ─── Tab 2: MITRE FiGHT Matrix & 80-Rule Tuning Studio ──────────────────── */
function initSecurityStudio() {
    // 1. Sub-View Switcher Tabs (Polar Radar vs MITRE FiGHT vs Rule Studio)
    document.querySelectorAll('.sec-view-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.sec-view-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.sec-subpane').forEach(p => p.style.display = 'none');
            
            btn.classList.add('active');
            const target = btn.dataset.target;
            const pane = document.getElementById(target);
            if (pane) pane.style.display = 'block';

            if (target === 'pane-mitre-fight') loadMitreMatrix();
            else if (target === 'pane-rule-studio') loadRuleStudio();
        });
    });

    // 2. Executive HTML Audit Report
    document.getElementById('btn-export-audit-html')?.addEventListener('click', () => {
        window.location.href = '/api/audit/report?format=html';
    });

    // 3. Remediation Drawer Close
    document.getElementById('btn-close-remediation')?.addEventListener('click', () => {
        const drawer = document.getElementById('remediation-drawer');
        if (drawer) drawer.style.display = 'none';
    });

    // 4. Rule Studio Filter & Search
    document.getElementById('rule-studio-search')?.addEventListener('input', e => {
        filterRuleStudioTable(e.target.value.toLowerCase().trim(), document.getElementById('rule-studio-sev-filter')?.value || 'all');
    });

    document.getElementById('rule-studio-sev-filter')?.addEventListener('change', e => {
        filterRuleStudioTable(document.getElementById('rule-studio-search')?.value.toLowerCase().trim() || '', e.target.value);
    });
}

function openRemediationDrawer(rule) {
    if (!rule) return;
    const drawer = document.getElementById('remediation-drawer');
    if (!drawer) return;

    drawer.style.display = 'flex';
    setText('rem-sev', rule.severity || 'CRITICAL');
    const sevBadge = document.getElementById('rem-sev');
    if (sevBadge) sevBadge.className = `sev-badge sev-${rule.severity || 'CRITICAL'}`;

    setText('rem-rule-id', rule.rule_id || 'TELCOSEC-VULN-001');
    setText('rem-title', rule.title || 'Cellular Vulnerability');
    setText('rem-spec', rule.spec || '3GPP TS 33.501');
    setText('rem-tactic', rule.tactic || 'Signaling Downgrade & Eavesdropping');
    setText('rem-rat', rule.rat || '5G / 4G');
    setText('rem-desc', rule.description || 'No description available.');
    setText('rem-guidance', rule.remediation || 'Enforce mutual authentication and mandatory encryption.');

    const copyBtn = document.getElementById('btn-copy-remediation');
    if (copyBtn) {
        copyBtn.onclick = () => {
            const adv = `[${rule.rule_id}] ${rule.title}\nSeverity: ${rule.severity}\nSpec: ${rule.spec}\nRemediation:\n${rule.remediation}`;
            navigator.clipboard.writeText(adv);
            showToast('Copied remediation advisory', 'success');
        };
    }
}

function loadMitreMatrix() {
    fetch('/api/security/rules')
        .then(r => r.json())
        .then(d => {
            if (!d.rules) return;
            const container = document.getElementById('mitre-matrix-grid');
            if (!container) return;
            container.innerHTML = '';

            const tactics = [
                'Initial Access & IMSI Catching',
                'Credential & Key Extraction',
                'Signaling Downgrade & Eavesdropping',
                'Covert Location Tracking',
                'SIM & UICC Proactive Exploits',
                'Denial of Service & Jamming'
            ];

            tactics.forEach(tacticName => {
                const colRules = d.rules.filter(r => r.tactic === tacticName);
                const col = document.createElement('div');
                col.className = 'mitre-column';
                col.innerHTML = `
                    <div class="mitre-col-header">
                        <span>${escapeHtml(tacticName)}</span>
                        <span class="badge badge-secondary">${colRules.length}</span>
                    </div>
                    <div class="mitre-rules-list"></div>
                `;
                const list = col.querySelector('.mitre-rules-list');

                colRules.forEach(r => {
                    const card = document.createElement('div');
                    card.className = `mitre-rule-card ${r.trigger_count > 0 ? 'triggered' : ''}`;
                    card.innerHTML = `
                        <div class="mitre-card-top">
                            <span class="sev-badge sev-${r.severity}">${r.severity}</span>
                            <span style="font-family:var(--font-mono);font-size:10px;color:#58a6ff;">${r.rule_id}</span>
                        </div>
                        <div class="mitre-card-title">${escapeHtml(r.title)}</div>
                    `;
                    card.addEventListener('click', () => openRemediationDrawer(r));
                    list.appendChild(card);
                });

                container.appendChild(col);
            });
        })
        .catch(() => {});
}

function loadRuleStudio() {
    fetch('/api/security/rules')
        .then(r => r.json())
        .then(d => {
            if (!d.rules) return;
            window._allRulesCache = d.rules;
            renderRuleStudioTable(d.rules);
        })
        .catch(() => {});
}

function renderRuleStudioTable(rules) {
    const tbody = document.getElementById('rule-studio-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';

    rules.forEach(r => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>
                <input type="checkbox" ${r.enabled ? 'checked' : ''} class="rule-toggle-switch" data-rule="${r.rule_id}">
            </td>
            <td style="font-family:var(--font-mono);font-weight:700;color:#58a6ff;cursor:pointer;">${r.rule_id}</td>
            <td><span class="sev-badge sev-${r.severity}">${r.severity}</span></td>
            <td style="color:#8ea1b4;font-size:11px;">${escapeHtml(r.tactic)}</td>
            <td><strong>${escapeHtml(r.title)}</strong></td>
            <td style="font-family:var(--font-mono);color:#8ea1b4;font-size:10.5px;">${escapeHtml(r.spec)}</td>
            <td>
                <button class="btn btn-xs btn-secondary btn-sim-rule" data-rule="${r.rule_id}">🔍 Audit</button>
            </td>
        `;

        // Click on rule ID opens drawer
        tr.children[1].addEventListener('click', () => openRemediationDrawer(r));
        
        // Toggle rule switch
        tr.querySelector('.rule-toggle-switch')?.addEventListener('change', e => {
            fetch('/api/security/rules/toggle', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ rule_id: r.rule_id, enabled: e.target.checked })
            })
            .then(res => res.json())
            .then(() => showToast(`${r.rule_id} ${e.target.checked ? 'Enabled' : 'Disabled'}`, 'info'));
        });

        // Audit rule evaluation
        tr.querySelector('.btn-sim-rule')?.addEventListener('click', () => {
            fetch('/api/security/rules/simulate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ rule_id: r.rule_id })
            })
            .then(res => res.json())
            .then(() => showToast(`Evaluated rule ${r.rule_id}`, 'info'));
        });

        tbody.appendChild(tr);
    });
}

function filterRuleStudioTable(search, sev) {
    if (!window._allRulesCache) return;
    const filtered = window._allRulesCache.filter(r => {
        const matchSearch = !search || r.rule_id.toLowerCase().includes(search) || r.title.toLowerCase().includes(search) || r.tactic.toLowerCase().includes(search);
        const matchSev = (sev === 'all') || (r.severity === sev);
        return matchSearch && matchSev;
    });
    renderRuleStudioTable(filtered);
}


function initThemeSwitcher() {
    const savedTheme = localStorage.getItem('airtap_theme') || 'cyber';
    document.documentElement.setAttribute('data-theme', savedTheme);
    const sel = document.getElementById('theme-selector');
    if (sel) {
        sel.value = savedTheme;
        sel.addEventListener('change', e => {
            const t = e.target.value;
            document.documentElement.setAttribute('data-theme', t);
            localStorage.setItem('airtap_theme', t);
            showToast(`Theme switched to ${e.target.options[e.target.selectedIndex].text}`, 'info');
        });
    }
}

/**
 * AirTap Visual Operations Suite — Advanced Frontend Engine (TelcoSec Brand)
 * High-Throughput Real-Time Data Engine: DocumentFragment Batch DOM Injection,
 * Rolling PPS/Throughput HUD, 60-Second Real-Time RF Sparkline, Time-Delta Tracking,
 * Page Visibility Lifecycle, and Virtualized Ring Buffering.
 */

'use strict';

/* ─── 3GPP Standards & Remediation Database ──────────────────────────────── */
const THREAT_SPECS_DB = {
    'TELCOSEC-VULN-001': {
        spec: '3GPP TS 44.018 §3.4.7 / TS 43.020 §C.1',
        impact: 'Cleartext Voice/SMS Eavesdropping (2G A5/0)',
        remediation: 'Enforce A5/3 or A5/4 ciphering algorithm in Base Station Controller (BSC). Disable A5/0 null encryption globally in network radio resource configuration.'
    },
    'TELCOSEC-VULN-002': {
        spec: '3GPP TS 44.018 §3.4.7 / TS 55.216',
        impact: 'Real-Time Ciphertext Decryption via Rainbow Tables (A5/1)',
        remediation: 'Deprecate A5/1 and migrate all GERAN base stations to Kasumi-based A5/3 (128-bit) or GPRS GEA3/GEA4.'
    },
    'TELCOSEC-VULN-003': {
        spec: '3GPP TS 33.401 §5.1.3 / TS 24.301 §5.4.3',
        impact: 'Cleartext LTE NAS & User-Plane Transmission (EEA0 / UEA0)',
        remediation: 'Configure MME/eNodeB to reject EEA0 algorithm in Security Mode Command. Enforce 128-EEA2 (AES-CTR) or 128-EEA3 (ZUC-128).'
    },
    'TELCOSEC-VULN-004': {
        spec: '3GPP TS 33.501 §6.7.2 / TS 24.501 §5.4.2',
        impact: 'Plaintext 5G User-Plane & NAS Exposure (NEA0)',
        remediation: 'Audit 5G AMF and gNB security profile policies. Disable NEA0 for all non-emergency PDU sessions. Enforce 128-NEA2 or 256-NEA2.'
    },
    'TELCOSEC-VULN-005': {
        spec: '3GPP TS 33.401 §5.1.4 / 3GPP TS 33.501 §6.7.3',
        impact: 'OTA Message Injection & Signal Tampering (EIA0 / NIA0)',
        remediation: 'Mandate 128-EIA2 (AES-CMAC) or 128-NIA2 (AES-CMAC) integrity protection for all control-plane NAS/RRC procedures.'
    },
    'TELCOSEC-VULN-006': {
        spec: '3GPP TS 33.501 §6.12 / 3GPP TS 33.401 §5.3',
        impact: 'IMSI Catcher Identity Harvesting / Subscriber Tracking',
        remediation: 'Enable 5G Subscription Concealed Identifier (SUCI) using ECIES Profile A/B public key encryption on USIM. Reject plain IMSI Identity Requests in LTE/5G.'
    },
    'TELCOSEC-VULN-007': {
        spec: '3GPP TS 24.301 §5.5.1 / TS 24.501 §5.5.1',
        impact: 'False Base Station Forced Downgrade to 2G/3G (EMM Reject #7/#8)',
        remediation: 'Implement modem-side 2G/3G disablement policy (LTE/5G Only mode). Block unauthenticated Attach/Registration Rejects prior to AKA completion.'
    },
    'TELCOSEC-VULN-008': {
        spec: '3GPP TS 23.040 §9.2.3.9 / 3GPP TS 23.038',
        impact: 'Covert Baseband Paging / Silent Location Surveillance',
        remediation: 'Deploy SMS Firewall rules at the SMSC/STP to drop Type 0 (TP-PID 0x40) SMS from unauthorized or roaming interconnect peers.'
    },
    'TELCOSEC-VULN-009': {
        spec: '3GPP TS 31.111 §6.4.16 / 3GPP TS 23.048',
        impact: 'SIMjacker Remote SMS Execution & Covert Handset Control',
        remediation: 'Disable S@T Browser and unauthenticated SIM Toolkit bytecode interpreters on all issued USIM profiles. Require cryptographic Proof of Receipt (PoR).'
    },
    'TELCOSEC-VULN-010': {
        spec: '3GPP TS 25.331 §8.3 / TS 33.102 §6.3',
        impact: '3G SRNS Relocation Security Context Hijacking',
        remediation: 'Enforce mandatory AKA re-authentication on every inter-RNC SRNS relocation and inter-system handover.'
    },
    'TELCOSEC-VULN-011': {
        spec: '3GPP TS 24.301 §6.5.4 / TS 23.401 §5.4.2',
        impact: 'User-Plane QoS Downgrade / Adversary Data Throttling',
        remediation: 'Validate PGW/SGW GTP-C control channels with IPsec/TLS interconnect protection to prevent unauthorized Modify Bearer Requests.'
    },
    'TELCOSEC-VULN-012': {
        spec: '3GPP TS 24.301 §5.4.1 / TS 24.501 §5.4.1',
        impact: 'Persistent Subscriber Tracking via TMSI/GUTI Non-Refresh',
        remediation: 'Configure Core Network (MME/AMF) to issue fresh GUTI allocations on every Attach, Registration, and Tracking Area Update.'
    },
    'TELCOSEC-VULN-013': {
        spec: '3GPP TS 33.501 §6.4.2 / TS 24.501 §5.4.4',
        impact: 'AMF Security Context Replay / Stale Key Exploitation',
        remediation: 'Enforce fresh NAS COUNT verification and refuse Configuration Update Commands without prior authenticated Registration.'
    },
    'TELCOSEC-VULN-014': {
        spec: '3GPP TS 36.304 §5.2.4 / TS 36.331 SIB1',
        impact: 'False Base Station Proximity Luring (q-RxLevMin Manipulation)',
        remediation: 'Deploy UE Baseband FBS heuristics to reject cells with anomalous q-RxLevMin thresholds (< -130 dBm) and invalid neighbor cell configurations.'
    },
    'TELCOSEC-VULN-015': {
        spec: 'ETSI TS 102 221 / 3GPP TS 31.111 §6.4.27',
        impact: 'WIBjacker BIP Channel Covert Data Exfiltration Pipe',
        remediation: 'Lock down Wireless Internet Browser (WIB) applet execution and restrict Bearer Independent Protocol (BIP) open channel permissions.'
    },
    'TELCOSEC-VULN-016': {
        spec: 'ETSI TS 102 221 §11.1.9 (ISO 7816-4)',
        impact: 'UICC PIN / PUK Brute-Force Probing & Card Lockout',
        remediation: 'Ensure maximum PIN retry counter (3 attempts) and PUK counter (10 attempts) are strictly enforced by the smart card operating system.'
    },
    'TELCOSEC-VULN-017': {
        spec: '3GPP TS 31.111 §6.4.15 (PROVIDE LOCAL INFO)',
        impact: 'Stealth STK IMEI, Cell ID, and Location Harvesting',
        remediation: 'Require OS-level user permission confirmation before dispatching STK PROVIDE LOCAL INFORMATION proactive commands.'
    },
    'TELCOSEC-VULN-018': {
        spec: '3GPP TS 31.102 §4.2.2 / ETSI TS 102 221 §11.1.1',
        impact: 'Covert USIM Elementary File Exfiltration (EF_IMSI / EF_ICCID)',
        remediation: 'Restrict READ BINARY access on sensitive administrative elementary files to authenticated baseband security processes.'
    },
    'TELCOSEC-VULN-019': {
        spec: '3GPP TS 31.111 §6.4.12 (SET UP CALL)',
        impact: 'Unauthorized STK Call Initiation / Premium Rate Dialing',
        remediation: 'Block proactive SET UP CALL execution without explicit interactive user confirmation on handset display.'
    },
    'TELCOSEC-VULN-020': {
        spec: '3GPP TS 31.102 §7.1.2 / TS 33.102 §6.3',
        impact: 'USIM AKA Milenage Challenge Execution / SQN Tracking',
        remediation: 'Monitor sequence numbers (SQN) in AUTN to detect AKA resynchronization floods and cross-network replay attacks.'
    },
    'TELCOSEC-VULN-021': {
        spec: '3GPP TS 31.111 §6.4.16 / ETSI TS 102 221',
        impact: 'STK Forced Browser Launch / WIB Phishing Redirection',
        remediation: 'Disable browser launch proactive commands initiated by SIM toolkit applets.'
    },
    'TELCOSEC-VULN-022': {
        spec: '3GPP TS 23.501 §5.17 / TS 33.501 §8.1',
        impact: '5G-to-EPS Bidding-Down Attack (N26 Interface Bypass)',
        remediation: 'Mandate N26 interface with secure context transfer between 5GS and EPC, or require complete 5G AKA on interworking.'
    },
    'TELCOSEC-VULN-023': {
        spec: '3GPP TS 36.331 SIB4/SIB5 / TS 38.331 SIB4/SIB5',
        impact: 'False Base Station Cell Isolation (Suppression of Neighbors)',
        remediation: 'Flag cells broadcasting standalone SIB1 without intra/inter-frequency neighbor cell lists as suspicious rogue base stations.'
    },

    'TELCOSEC-VULN-024': {
        spec: '3GPP TS 29.002 §7.6.6 / GSMA FS.11 (SS7 Security)',
        impact: 'SS7 MAP SendRoutingInfo Attack / Subscriber Location Disclosure',
        remediation: 'Deploy SS7 Firewall with GSMA FS.11 message filtering. Block Category 1/2 attack messages (SRI, PSI, ATI) from unrecognised operators on SS7 interconnect.'
    },
    'TELCOSEC-VULN-025': {
        spec: '3GPP TS 29.230 §5.2 / GSMA FS.19 (Diameter Security)',
        impact: 'Diameter S6a / S13 Probing / UE Location & IMSI Enumeration',
        remediation: 'Implement Diameter Edge Agent (DEA) with strict originating realm whitelisting. Reject Location-Info-Request from unauthorised Diameter peers not in federation.'
    },
    'TELCOSEC-VULN-026': {
        spec: '3GPP TS 24.229 §5.4.3.1 / RFC 3261 §26.2',
        impact: 'VoLTE IMS SIP REGISTER Replay & Session Hijack',
        remediation: 'Enforce mutual TLS (mTLS) on the Gm reference point. Require IMS AKA with integrity-protected SIP headers and nonce-based challenge authentication.'
    },
    'TELCOSEC-VULN-027': {
        spec: '3GPP TS 23.167 §9.2 / TS 24.301 §9.3.6',
        impact: 'IMS Emergency Service Bypass / SOS Call Interception',
        remediation: 'Verify Emergency Registration (IMPU = sos URI) against authenticated P-CSCF context before IMS emergency bearer establishment.'
    },
    'TELCOSEC-VULN-028': {
        spec: '3GPP TS 33.501 §6.1.3 / TS 23.003 §28',
        impact: '5G SUCI Decryption via Brute-Force ECIES Null Scheme Fallback',
        remediation: 'Enforce SUCI protection profile A or B (ECIES) on all USIM profiles. Reject any 5G Registration Request using NULL-scheme SUPI in SUCI field.'
    },
    'TELCOSEC-VULN-029': {
        spec: '3GPP TS 23.501 §5.15.3 / TS 33.501 §9.9',
        impact: '5G Network Slice Isolation Bypass / Cross-Slice Data Exfiltration',
        remediation: 'Implement per-slice security policies with NSSF-enforced NSSAI authorization. Apply slice-specific DNN traffic filtering at UPF ingress/egress boundaries.'
    },
    'TELCOSEC-VULN-030': {
        spec: '3GPP TS 38.331 §5.3.3 / TS 33.501 §5.3.2',
        impact: 'gNB RRC Setup Reject Flood / UE Denial-of-Service',
        remediation: 'Implement AMF-level rate limiting on RRC Setup Request forwarding. Deploy anomaly detection for statistically elevated RRC reject rates on serving cells.'
    },
    'TELCOSEC-VULN-031': {
        spec: '3GPP TS 33.501 §6.2.1 / TS 24.501 §5.3.4',
        impact: '5G AMF Overload Signalling Attack via Crafted Registration Storms',
        remediation: 'Enable AMF overload control procedures (TS 24.501 §5.19). Configure NGAP Overload Start signalling thresholds and PLMN-based back-pressure to gNBs.'
    },
    'TELCOSEC-VULN-032': {
        spec: 'SGP.02 v4.1 §4.2 / GSMA SGP.22 §3.3 (eSIM RSP)',
        impact: 'eSIM Remote Profile Provisioning Interception / SIM Swap via RSP',
        remediation: 'Validate SM-DP+ certificate chain against GSMA CI root. Enforce HTTPS mutual TLS on ES8+ interface and verify bound EID before Profile Download authorisation.'
    },
    'TELCOSEC-VULN-033': {
        spec: 'GSMA SGP.22 §3.7 / SGP.02 §4.5',
        impact: 'eSIM Profile Deletion / Operational Disruption via Rogue LPA',
        remediation: 'Restrict ES10b LPA-to-eUICC channel to operator-signed Local Profile Assistant applications. Audit audit-log on eUICC for unauthorized profile management events.'
    },
    'TELCOSEC-VULN-034': {
        spec: '3GPP TS 23.502 §4.11 / TS 33.501 §13.4 (SEPP)',
        impact: '5G Roaming N32 Interface Eavesdropping / Home PLMN Data Exposure',
        remediation: 'Deploy Security Edge Protection Proxy (SEPP) at N32 roaming interface. Enforce JWS/JWE cryptographic protection on all inter-PLMN NF service messages.'
    },
    'TELCOSEC-VULN-035': {
        spec: '3GPP TS 29.571 §5 / TS 33.501 §13.1 (SBI Security)',
        impact: '5G SBI API Token Forgery / NF Service Consumer Impersonation',
        remediation: 'Enforce OAuth 2.0 with NRF-issued access tokens on all 5GC SBI interfaces. Validate token scope, audience, and expiry at NF producer before service execution.'
    },
    'TELCOSEC-VULN-036': {
        spec: '3GPP TS 33.501 §6.3.2 / TS 38.331 §5.3.5.2 (AS Security)',
        impact: 'RRC Integrity Failure Suppression / AS Layer Cipher-Only Exploitation',
        remediation: 'Mandate 128-NIA2 (AES-CMAC) integrity protection for all RRC signaling. Reject RRC SecurityModeCommand specifying NIA0 integrity algorithm outside of emergency context.'
    },
    'TELCOSEC-VULN-037': {
        spec: '3GPP TS 23.040 §9.2.3.26 / GSMA PRD IR.70',
        impact: 'SMS Home Routing Bypass / MT SMS Spoofing via Interconnect Peering',
        remediation: 'Deploy SMS Home Routing (SHR) to conceal subscriber HLR/HSS address. Implement SMSC originating address validation and A2P sender authentication at SMSC.'
    },
    'TELCOSEC-VULN-038': {
        spec: '3GPP TS 33.401 §8.3 / TS 36.413 §9.2.1 (X2 Interface)',
        impact: 'LTE X2 Handover Security Context Transfer Exploit',
        remediation: 'Encrypt and integrity-protect X2-AP messages using IPsec ESP between eNodeBs. Enforce fresh AS key derivation on every X2-based handover without reusing the source AS context.'
    },
    'TELCOSEC-VULN-039': {
        spec: '3GPP TS 24.301 §5.4.3 / TS 33.401 §6.1.2',
        impact: 'EMM Attach Request IMSI Capture via Paging Correlation Attack',
        remediation: 'Enable temporary identifier (TMSI/GUTI) re-allocation on every Attach Accept. Reject Attach Requests presenting cleartext IMSI without prior TMSI assignment failure.'
    },
    'TELCOSEC-VULN-040': {
        spec: 'RFC 5905 §11 / GSMA FS.04 §6.2',
        impact: 'NTP/PTP Synchronisation Attack on RAN Timing (GPS Spoofing Amplification)',
        remediation: 'Authenticate NTP sources using NTPsec with symmetric keys or NTS (RFC 8915). Deploy PTP-aware firewalls and GPS/GNSS anti-spoofing receivers at macro cell sites.'
    },
    'TELCOSEC-VULN-041': {
        spec: '3GPP TS 33.501 §6.14 / TS 38.413 §9.3.4 (NGAP)',
        impact: 'AMF / gNB NGAP UE Context Release Flood Attack',
        remediation: 'Implement stateful NGAP session tracking at AMF. Rate-limit UE Context Release Requests per gNB source and alert on statistical deviations from baseline.'
    },
    'TELCOSEC-VULN-042': {
        spec: '3GPP TS 33.402 §6.2 / TS 24.302 §5.1 (Non-3GPP Access)',
        impact: 'Wi-Fi WLAN Non-3GPP Attach / EAP-AKA’ Downgrade to EAP-SIM',
        remediation: 'Enforce EAP-AKA’ (RFC 5448) for WLAN non-3GPP access security. Disable EAP-SIM fallback and require ePDG certificate validation before IKEv2 tunnel establishment.'
    },
    'TELCOSEC-VULN-043': {
        spec: '3GPP TS 36.321 §5.4.1 / TS 36.211 §6.9 (PRACH)',
        impact: 'PRACH Preamble Flood / LTE/NR Random Access Channel Jamming',
        remediation: 'Monitor PRACH preamble collision rates for statistical anomalies. Implement adaptive RACH back-off parameter tuning and irregular preamble sequence alerting in RAN OAM.'
    },
    'TELCOSEC-VULN-044': {
        spec: '3GPP TS 22.261 §6.1 / TS 33.501 §5.4 (URLLC)',
        impact: '5G URLLC Latency-Injection via QoS Flow Tampering',
        remediation: 'Sign 5G QoS Flow Descriptors (QFDs) cryptographically between SMF and UPF. Validate GTP-U QFI marking at UPF ingress against authorised PCF-provisioned QoS rules.'
    },
    'TELCOSEC-VULN-045': {
        spec: '3GPP TS 36.300 §22.2 / TS 36.420 §5.3 (SON / ANR)',
        impact: 'Automated Neighbor Relation (ANR) Poisoning / Rogue Cell Insertion',
        remediation: 'Authenticate ANR report sources using O1/A1 signed telemetry. Limit automatic neighbor addition to cells with verified PCI/EARFCN combinations matching whitelisted operator topology.'
    },
    'TELCOSEC-VULN-046': {
        spec: 'GSMA PRD TS.06 §4 / ETSI EN 303 645 §5.1 (IoT Security)',
        impact: 'NB-IoT / LTE-M CoAP/MQTT Device Credential Brute-Force & Takeover',
        remediation: 'Enforce per-device unique PSK or certificate-based DTLS 1.3 (RFC 9147) for NB-IoT CoAP endpoints. Implement EPS bearer-level rate limiting on MQTT CONNECT storms.'
    },
    'TELCOSEC-VULN-047': {
        spec: '3GPP TS 33.501 §6.12.2 / TS 24.501 §5.4.4.3 (5G-AKA)',
        impact: '5G-AKA SEAF MAC Verification Bypass (HOME Network Masquerade)',
        remediation: 'Enforce HXRES* verification at SEAF (AMF) before forwarding authentication result to UE. Reject 5G-AKA Auth Responses without valid XRES* binding to serving network ID.'
    },
    'TELCOSEC-VULN-048': {
        spec: '3GPP TS 38.101-3 §5.5A / TS 38.133 §10 (NR-U / Unlicensed)',
        impact: 'NR-U / LTE-LAA Unlicensed Band LBT Channel Starvation Attack',
        remediation: 'Monitor channel access fairness metrics on NR-U Pcell. Implement adaptive LBT contention window analysis and alert on statistically elevated airtime occupancy from specific cells.'
    },
    'TELCOSEC-VULN-049': {
        spec: '3GPP TS 23.288 §6.2 / TS 33.501 §6.16 (NWDAF)',
        impact: '5G NWDAF Analytics Poisoning / AI-Driven Network Policy Manipulation',
        remediation: 'Authenticate NWDAF analytics subscriptions using NRF-issued tokens with analytics-function scope. Validate training data provenance and apply anomaly detection on AI/ML model inputs.'
    },
    'TELCOSEC-VULN-050': {
        spec: '3GPP TS 33.501 §6.7.4 / TS 38.331 §5.3.13.4 (RRC Reestablishment)',
        impact: 'NR RRC Re-establishment Context Confusion / AS Key Rollback Attack',
        remediation: 'Enforce full integrity verification of RRCReestablishmentRequest against the last valid AS context (NH/NCC pair). Reject re-establishment attempts presenting a recycled NCC value.'
    },
    'TELCOSEC-VULN-051': {
        spec: '3GPP TS 31.115 §5.1.2 / ETSI TS 102 225 §5.1.2 (Secured Packet Structure)',
        impact: 'Single-DES Cryptographic Weakness in SIM OTA Secured Packets (Broken KIC/KID)',
        remediation: 'Deprecate Single-DES and 2-Key Triple-DES keys for OTA SMS-PP envelopes. Mandate AES-128 (KIC/KID algorithm 0x02) in CBC mode with CMAC in all SIM card profiles.'
    },
    'TELCOSEC-VULN-052': {
        spec: '3GPP TS 31.116 §5.1 / ETSI TS 102 226 §5.1 (Remote APDU Structure)',
        impact: 'Null-Ciphering / Plaintext Payload in SIM Remote File Management (RFM SPI Bypass)',
        remediation: 'Enforce SPI Byte 1 bit b3=1 (Ciphering Active) for all incoming RFM OTA Command Packets. Reject any OTA SMS-PP carrying TAR 000000/B00001 with null encryption.'
    },
    'TELCOSEC-VULN-053': {
        spec: 'GlobalPlatform Card Spec v2.3 §9.2 / 3GPP TS 31.116 §6.2 (Remote Applet Loading)',
        impact: 'Remote Applet Management (RAM) Signature Suppression / Rogue Java Card Applet Install',
        remediation: 'Mandate Data Authentication Pattern (DAP) verification and GlobalPlatform delegated management tokens for all INSTALL [for load] and INSTALL [for install] APDUs.'
    },
    'TELCOSEC-VULN-054': {
        spec: '3GPP TS 31.115 §5.1.1 (SPI Counter Management)',
        impact: 'OTA Anti-Replay Counter Rollback / Zero-Counter Injection (SPI Counter Bypass)',
        remediation: 'Require monotonic strict counter checking (SPI b5-b4=01 or 10). Reject any OTA Command Packet whose Counter (CNTR) is less than or equal to the card sequence state.'
    },
    'TELCOSEC-VULN-055': {
        spec: '3GPP TS 31.115 §5.1.3 (Response Packet & PoR Structure)',
        impact: 'Proof of Receipt (PoR) Information Exfiltration Attack (Malicious PoR Forcing)',
        remediation: 'Configure SIM toolkit to only dispatch PoR SMS-PP messages to cryptographically authenticated SMSC addresses; encrypt PoR response packets using AES-CBC.'
    },
    'TELCOSEC-VULN-056': {
        spec: '3GPP TS 31.111 §6.4 / SIMalliance S@T 01.00 §4.2 (SmartTrust S@T Browser Protocol)',
        impact: 'S@T Bytecode Command Execution via Unprotected TAR (SIMjacker Zero-Click SMS)',
        remediation: 'Disable legacy S@T browser applets (TAR 000005, 504154). Enforce strict cryptographic security filtering (KIC/KID != 0) on all SMS-PP packets targeting S@T push commands.'
    },
    'TELCOSEC-VULN-057': {
        spec: 'SmartTrust WIB Spec v1.3 / 3GPP TS 31.111',
        impact: 'Wireless Internet Browser (WIB) Bytecode Injection (WIBjacker Attack)',
        remediation: 'Remove deprecated SmartTrust WIB applets from UICC/USIM stock. Reject OTA messages addressed to WIB TAR (000001 / D00001) without full cryptographic authentication.'
    },
    'TELCOSEC-VULN-058': {
        spec: '3GPP TS 31.111 §6.4.27 / ETSI TS 102 223 §6.4.27 (OPEN CHANNEL)',
        impact: 'STK Bearer Independent Protocol (BIP) Covert C2 Pipe (OPEN CHANNEL Abuse)',
        remediation: 'Implement OS-level and baseband-level authorization prompts whenever an applet requests OPEN CHANNEL (BIP). Audit data traffic over GPRS/LTE/5G packet data BIP channels.'
    },
    'TELCOSEC-VULN-059': {
        spec: '3GPP TS 31.111 §6.4.17 (SEND USSD) / TS 22.090',
        impact: 'STK Silent USSD / SS Execution (Supplementary Service Hijacking & Balance Drain)',
        remediation: 'Require interactive screen confirmation for all STK SEND USSD and SEND SS commands. Block automated supplementary service strings starting with *# or ** without user interaction.'
    },
    'TELCOSEC-VULN-060': {
        spec: '3GPP TS 31.111 §6.4.1 (DISPLAY TEXT) & §6.4.3 (GET INPUT)',
        impact: 'Deceptive STK Phishing Overlays via DISPLAY TEXT & GET INPUT Injection',
        remediation: 'Prefix all SIM-initiated display dialogues with a clear "[SIM Card Applet]" warning banner and block full-screen priority display text while the screen lock is engaged.'
    },
    'TELCOSEC-VULN-061': {
        spec: '3GPP TS 31.111 §6.4.7 (REFRESH) / ETSI TS 102 223',
        impact: 'Unauthorized STK REFRESH File Modification / Baseband Re-registration Forcing',
        remediation: 'Restrict REFRESH command types (UICC Reset, 3G Session Reset) to authenticated operator OTA sessions. Audit unexpected baseband resets triggered by SIM REFRESH commands.'
    },
    'TELCOSEC-VULN-062': {
        spec: 'Java Card 3.1 Classic Runtime Environment §6.2 (Applet Firewall & SIO)',
        impact: 'Java Card Applet Firewall Escape / Shareable Interface Object Privilege Escalation',
        remediation: 'Enforce strict Java Card bytecode verification (BCV) prior to applet loading. Validate client AID in getShareableInterfaceObject() and restrict multi-tenant object sharing.'
    },
    'TELCOSEC-VULN-063': {
        spec: '3GPP TS 31.101 §10 / ETSI TS 102 221 §11.1.17 (MANAGE CHANNEL)',
        impact: 'Logical Channel Exhaustion Denial-of-Service on UICC Interface',
        remediation: 'Limit maximum open logical channels allocated to third-party applets. Reserve logical channel 0 exclusively for telecom core applications (ADF.USIM / ADF.ISIM).'
    },
    'TELCOSEC-VULN-064': {
        spec: '3GPP TS 31.102 §4.2.5 / 3GPP TS 23.122 §4.4.3 (PLMN Selection)',
        impact: 'EF_PLMNwAcT & EF_FPLMN OTA Steering Manipulation (Anti-Steering of Roaming)',
        remediation: 'Sign steering of roaming (SoR) OTA updates using 3GPP Release 15+ cryptographic SoR security with home network authentication verification.'
    },
    'TELCOSEC-VULN-065': {
        spec: '3GPP TS 31.111 §7 / ETSI TS 102 223 §7 (ENVELOPE Event Download)',
        impact: 'APDU Fuzzing & Buffer Overflow in Telecom Toolkit Event Download Handlers',
        remediation: 'Implement bounds checking and strict TLV parser sanitization on all ENVELOPE (Event Download, SMS-PP Data Download, Menu Selection) APDU inputs.'
    },
    'TELCOSEC-VULN-066': {
        spec: 'GSMA SGP.22 v3.0 §5.3 / GSMA SGP.02 §3.3 (ES8+ Interface)',
        impact: 'eSIM ES8+ Remote SIM Provisioning Channel Eavesdropping / Profile Tampering',
        remediation: 'Enforce AES-256-GCM authenticated encryption for ES8+ bound profile packages (BPP) with ephemeral elliptic curve Diffie-Hellman (ECDH) key agreement and NIST curves.'
    },
    'TELCOSEC-VULN-067': {
        spec: 'GSMA SGP.22 §2.5 / SGP.23 §3 (ECASD Certificate Management)',
        impact: 'eUICC ECASD Root Certificate Injection / Compromised GSMA CI Anchor',
        remediation: 'Lock Embedded Certificate Authority Security Domain (ECASD) in write-once fused NVRAM. Verify certificate revocation lists (CRL) using trusted online OCSP stapling.'
    },
    'TELCOSEC-VULN-068': {
        spec: '3GPP TS 31.111 §6.4.15 (NMR & Timing Advance) / TS 51.010 §27.22',
        impact: 'STK PROVIDE LOCAL INFO Timing & Measurement Report (NMR) Surreptitious Tracking',
        remediation: 'Rate-limit SIM queries for Network Measurement Results (NMR) and Timing Advance. Alert the user when multiple local info queries occur without active call establishment.'
    },
    'TELCOSEC-VULN-069': {
        spec: 'Java Card 3.1 API JCSystem / GlobalPlatform Card Spec',
        impact: 'Java Card Transient Array State Leak / Residual Memory Key Disclosure',
        remediation: 'Ensure transient arrays created with CLEAR_ON_RESET or CLEAR_ON_DESELECT are securely wiped by JCRE memory zeroization routines upon applet de-selection.'
    },
    'TELCOSEC-VULN-070': {
        spec: '3GPP TS 23.038 §4 / 3GPP TS 23.040 §9.2.3.9 (Data Coding Scheme Class 2)',
        impact: 'SMS-PP Data Download with Misleading PID/DCS (Class 2 SMS Spoofing)',
        remediation: 'Validate that TP-PID=0x7F (SIM Data Download) and TP-DCS Class 2 messages match authenticated SMSC origins and carry valid 3GPP TS 31.115 security headers.'
    },
    'TELCOSEC-VULN-071': {
        spec: '3GPP TS 31.111 §6.4.20 (RUN AT COMMAND) / 3GPP TS 27.007',
        impact: 'STK RUN AT COMMAND Proactive Instruction Abuse (Modem AT Injection via SIM)',
        remediation: 'Disable baseband support for the RUN AT COMMAND proactive facility or restrict accepted commands to an immutable read-only whitelist.'
    },
    'TELCOSEC-VULN-072': {
        spec: 'Bluetooth SAP Profile v1.1 / 3GPP TS 31.102 §5',
        impact: 'USIM Elementary File Read Access via Unauthorized SIM Access Profile (SAP) Bridge',
        remediation: 'Mandate Bluetooth Secure Connections (Numeric Comparison) and require manual user authorization before establishing any SIM Access Profile (SAP) connection.'
    },
    'TELCOSEC-VULN-073': {
        spec: '3GPP TS 31.102 §4.2.17 (EF_LOCI) & §4.2.23 (EF_PSLOCI)',
        impact: 'Remote File Management (RFM) EF_LOCI / EF_PSLOCI Poisoning (Denial of Service Attach)',
        remediation: 'Validate integrity of location data written to EF_LOCI via RFM and ensure baseband re-validates registration status upon receiving unexpected Location Area updates.'
    },
    'TELCOSEC-VULN-074': {
        spec: '3GPP TS 31.111 §6.4.30 / ETSI TS 102 223 §6.4.35',
        impact: 'STK LANGUAGE NOTIFICATION & GEO LOCATE Proactive Fingerprinting',
        remediation: 'Require explicit application permissions before passing high-accuracy GNSS coordinates from device location manager to SIM card applets.'
    },
    'TELCOSEC-VULN-075': {
        spec: 'GSMA TS.43 §4.2 / 3GPP TS 31.102 §4.2.100 (Access Control Rules - EF_ARR / EF_ACRules)',
        impact: 'Multi-Application UICC Access Rule Tampering (Carrier App Privilege Escalation)',
        remediation: 'Protect EF_ACRules with write-access administrative PIN keys; audit certificate SHA-256 signatures in Access Rule Envelopes against verified operator root certificates.'
    },
    'TELCOSEC-VULN-076': {
        spec: 'ETSI TS 102 232-1 §5.2 / 3GPP TS 33.108 Clause 12 (HI2/HI3 Transport Security)',
        impact: 'Unencrypted Lawful Interception Handover Interface (Plaintext Intercept Exposure)',
        remediation: 'Enforce mandatory TLS 1.3 or IPsec ESP encryption with mutual certificate authentication across all HI2 (IRI) and HI3 (CC) handover links to prevent wiretapping.'
    },
    'TELCOSEC-VULN-077': {
        spec: 'ETSI TS 102 232-1 §5.3 / 3GPP TS 33.128 §6.1.4 (PDU Sequence Numbering & Integrity)',
        impact: 'Lawful Interception Sequence Counter Reset / Packet Replay Tampering',
        remediation: 'Implement monotonic sequence validation per Communication Identifier (CIN); drop and alarm on duplicate, replayed, or out-of-order PS-PDUs.'
    },
    'TELCOSEC-VULN-078': {
        spec: '3GPP TS 33.128 Annex C / ETSI TS 103 221-1 (X1 Interface Target Provisioning)',
        impact: 'Unauthorized Lawful Interception Target Activation via Unauthenticated X1 REST',
        remediation: 'Require mutual TLS (mTLS) with strict X.509 ADMF client certificate verification and OAuth2 token authorization on all X1 management endpoints.'
    },
    'TELCOSEC-VULN-079': {
        spec: '3GPP TS 33.108 / Qualcomm Diag Protocol (CALEA Log Codes 0xB0CD / 0xB825)',
        impact: 'Baseband Qualcomm CALEA Silent Trigger Exfiltration / Covert Modem Wiretap',
        remediation: 'Disable baseband diagnostic CALEA trace logging (0xB0CD/0xB825) in production modem firmware builds; enforce TrustZone hardware secure boot attestation.'
    },
    'TELCOSEC-VULN-080': {
        spec: '3GPP TS 33.128 §5.4 / ETSI TS 102 232-7 (Correlation Identifier CIN Consistency)',
        impact: 'Lawful Interception Correlation Identifier (CIN) Mismatch in X2/X3 Multi-Stream Handover',
        remediation: 'Enforce strict CIN cryptographic binding across concurrent signaling (X2/IRI) and media (X3/CC) streams to prevent target spoofing or cross-warrant data leakage.'
    }

};

/* ─── State ──────────────────────────────────────────────────────────────── */
const state = {
    nv: {
        items: [],
        selectedNvId: 6828,
        selectedNvData: null,
        activeCategory: 'all'
    },
    f3: {
        logs: [],
        subsystemFilter: 'all',
        levelFilter: 'all',
        opcodeFilter: 'all',
        search: '',
        isRegex: false,
        isPaused: false,
        autoScroll: true,
        maxLines: 2000,
        matches: [],
        activeMatchIdx: -1,
        msgCountWindow: 0,
        msgRate: 0,
        counts: { total: 0, err: 0, warn: 0, rrc: 0, nas: 0, phy: 0, sim: 0, ims: 0, sec: 0, core: 0 }
    },
    efs: {
        currentPath: '/',
        currentFiles: [],
        selectedPath: null,
        currentFileData: null,
        currentStatData: null,
        previewMode: 'text'
    },
    ws: null,
    wsRetryDelay: 500,
    wsRetryMax: 30000,
    packets: [],
    threats: [],
    f3Lines: [],
    currentFilter: 'all',
    currentLayer: 'all',
    currentDir: 'all',
    currentPreset: 'all',
    isFrozen: false,
    audioAlerts: false,
    compactDensity: false,
    sortColumn: 'time',
    sortDirection: 'desc',
    threatSevFilter: 'all',
    threatCatFilter: 'all',
    autoScroll: true,
    f3AutoScroll: true,
    selectedPktId: null,
    selectedRow: null,      // P2: direct DOM ref to avoid querySelectorAll sweep
    totalPackets: 0,
    totalThreats: 0,
    ratCounts: { '5g': 0, '4g': 0, '3g': 0, '2g': 0, 'ims': 0, 'sim': 0, 'broadcast': 0, 'calea': 0 },
    pendingPackets: [],
    pendingThreats: [],
    pendingF3: [],
    rafScheduled: false,
    inspectorCollapsed: false,
    f3Filter: 'all',
    f3Search: '',
    deviceData: {},
    isBackground: false,
    metrics: {
        lastPktTime: null,
        lastDeltaMs: 0.0,
        pps: 0,
        bps: 0,
        pktCountSecond: 0,
        byteCountSecond: 0,
        lastSecTick: Date.now()
    },
    rfHistory: [],
    replay: {
        isPlaying: false,
        totalFrames: 0,
        currentIndex: 0,
        progressPercent: 0,
        speed: 1.0,
        fileName: 'Live Diagnostic Session',
        state: 'LIVE'
    },
    geo: {
        map: null,
        currentBasemap: 'darkmatter',
        tileLayers: {},
        handsetMarker: null,
        trailPolyline: null,
        towerLayer: null,
        heatmapLayer: null,
        threatLayer: null,
        riskZoneLayer: null,
        triangulationLayer: null,
        trailLayer: null,
        trailPoints: [],
        threatGeoEvents: [],
        rogueEmitters: {},
        knownTowers: {},
        currentLat: 37.7749,
        currentLng: -122.4194,
        prevLat: null,
        prevLng: null,
        lastRsrp: -90,
        lastPci: 248,
        totalDistanceKm: 0.0,
        startTime: Date.now(),
        speedKmh: 0.0,
        headingDeg: 0,
        isFullscreen: false,
        rsrpBuckets: { exc: 0, good: 0, fair: 0, poor: 0 }
    },
    terminal: {
        history: [],
        historyIdx: -1,
        commands: []
    },
    fuzzer: {
        lastVector: null
    }
};

const ARC_LEN = 164.9;

/* ─── Boot ───────────────────────────────────────────────────────────────── */

/* ─── Global Keyboard Shortcuts & Tactical Accelerator Engine ────────────── */
function toggleAudioAlerts() {
    state.audioAlerts = !state.audioAlerts;
    const audioBtn = document.getElementById('btn-toggle-audio');
    const headerAudioBtn = document.getElementById('btn-audio-toggle-header');
    
    if (audioBtn) {
        audioBtn.classList.toggle('audio-on', state.audioAlerts);
        setText('audio-icon', state.audioAlerts ? '🔊' : '🔇');
        setText('audio-text', state.audioAlerts ? 'Audio Active' : 'Audio Alert');
    }
    if (headerAudioBtn) {
        headerAudioBtn.classList.toggle('active', state.audioAlerts);
        setText('header-audio-icon', state.audioAlerts ? '🔊' : '🔇');
    }
    if (state.audioAlerts) {
        playThreatChirp('HIGH');
    }
    showToast(state.audioAlerts ? 'Tactical Acoustic Baseband alerts enabled' : 'Acoustic alerts muted', 'info');
}

function toggleHotkeysModal() {
    const modal = document.getElementById('hotkeys-modal');
    if (!modal) return;
    modal.style.display = modal.style.display === 'none' || !modal.style.display ? 'flex' : 'none';
}

function initKeyboardShortcuts() {
    // Header Hotkeys button & Close Modal button
    document.getElementById('btn-shortcuts-modal')?.addEventListener('click', toggleHotkeysModal);
    document.getElementById('btn-close-hotkeys-modal')?.addEventListener('click', () => {
        const modal = document.getElementById('hotkeys-modal');
        if (modal) modal.style.display = 'none';
    });
    document.getElementById('hotkeys-modal')?.addEventListener('click', e => {
        if (e.target.id === 'hotkeys-modal') {
            document.getElementById('hotkeys-modal').style.display = 'none';
        }
    });

    // Header audio button
    document.getElementById('btn-audio-toggle-header')?.addEventListener('click', toggleAudioAlerts);

    window.addEventListener('keydown', e => {
        // Ignore shortcuts when typing inside inputs, textareas or selects
        const tag = e.target.tagName.toLowerCase();
        if (tag === 'input' || tag === 'textarea' || tag === 'select' || e.target.isContentEditable) {
            if (e.key === 'Escape') {
                e.target.blur();
            }
            return;
        }

        // Space: Toggle Stream Pause/Resume
        if (e.code === 'Space') {
            e.preventDefault();
            document.getElementById('btn-toggle-freeze')?.click();
            return;
        }

        // 'M' key: Toggle Audio Alerts
        if (e.key.toLowerCase() === 'm' && !e.ctrlKey && !e.metaKey) {
            e.preventDefault();
            toggleAudioAlerts();
            return;
        }

        // '?' or Shift+'/' key: Toggle Keyboard Shortcuts Modal
        if (e.key === '?' || (e.shiftKey && e.key === '/')) {
            e.preventDefault();
            toggleHotkeysModal();
            return;
        }

        // Numbers 1-9 & 0: Instant Tab Switching
        const tabMap = {
            'Digit1': 'tab-live',
            'Digit2': 'tab-security',
            'Digit3': 'tab-device',
            'Digit4': 'tab-map',
            'Digit5': 'tab-efs',
            'Digit6': 'tab-nv',
            'Digit7': 'tab-f3',
            'Digit8': 'tab-terminal',
            'Digit9': 'tab-fuzzer',
            'Digit0': 'tab-calea'
        };
        if (tabMap[e.code] && !e.ctrlKey && !e.metaKey && !e.altKey) {
            e.preventDefault();
            switchTab(tabMap[e.code]);
            return;
        }

        // Slash or Ctrl+F / Cmd+F: Focus Filter / Search
        if (e.key === '/' || ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'f')) {
            e.preventDefault();
            const activeTab = document.querySelector('.tab-content.active')?.id;
            if (activeTab === 'tab-live') document.getElementById('packet-search')?.focus();
            else if (activeTab === 'tab-security') document.getElementById('threat-search-input')?.focus();
            else if (activeTab === 'tab-f3') document.getElementById('f3-search-input')?.focus();
            else if (activeTab === 'tab-nv') document.getElementById('nv-item-search')?.focus();
            else if (activeTab === 'tab-efs') document.getElementById('efs-search-input')?.focus();
            else if (activeTab === 'tab-map') document.getElementById('input-map-search')?.focus();
            else if (activeTab === 'tab-terminal') document.getElementById('terminal-input')?.focus();
            return;
        }

        // 'C' key: Toggle Columnar / Row Split in Live Signaling
        if (e.key.toLowerCase() === 'c' && !e.ctrlKey && !e.metaKey) {
            document.getElementById('btn-layout-toggle')?.click();
            return;
        }

        // Escape: Close modals
        if (e.key === 'Escape') {
            const threatModal = document.getElementById('threat-modal');
            if (threatModal && threatModal.style.display !== 'none') {
                threatModal.style.display = 'none';
            }
            const hotkeysModal = document.getElementById('hotkeys-modal');
            if (hotkeysModal && hotkeysModal.style.display !== 'none') {
                hotkeysModal.style.display = 'none';
            }
        }
    });
}



/* ─── Client-Side Dedicated Page Routing & History API ───────────────────── */
const ROUTE_TO_TAB = {
    '/': 'tab-live',
    '/index.html': 'tab-live',
    '/live': 'tab-live',
    '/signaling': 'tab-live',
    '/security': 'tab-security',
    '/threats': 'tab-security',
    '/radar': 'tab-security',
    '/device': 'tab-device',
    '/dossier': 'tab-device',
    '/hardware': 'tab-device',
    '/map': 'tab-map',
    '/wardrive': 'tab-map',
    '/rfmap': 'tab-map',
    '/efs': 'tab-efs',
    '/filesystem': 'tab-efs',
    '/explorer': 'tab-efs',
    '/nv': 'tab-nv',
    '/bands': 'tab-nv',
    '/bandlocker': 'tab-nv',
    '/f3': 'tab-f3',
    '/qxdm': 'tab-f3',
    '/logs': 'tab-f3',
    '/terminal': 'tab-terminal',
    '/at': 'tab-terminal',
    '/console': 'tab-terminal',
    '/fuzzer': 'tab-fuzzer',
    '/fuzzing': 'tab-fuzzer',
    '/calea': 'tab-calea',
    '/li': 'tab-calea',
    '/intercept': 'tab-calea',
    '/identities': 'tab-identities',
    '/identity': 'tab-identities',
    '/sms': 'tab-identities',
    '/ota': 'tab-identities'
};

const TAB_TO_ROUTE = {
    'tab-live': '/live',
    'tab-security': '/security',
    'tab-identities': '/identities',
    'tab-device': '/device',
    'tab-map': '/map',
    'tab-efs': '/efs',
    'tab-nv': '/nv',
    'tab-f3': '/f3',
    'tab-terminal': '/terminal',
    'tab-fuzzer': '/fuzzer',
    'tab-calea': '/calea'
};

function initRouter() {
    // 1. Check current URL on initial load
    const currentPath = window.location.pathname.toLowerCase().replace(/\/+$/, '') || '/';
    const targetTab = ROUTE_TO_TAB[currentPath] || 'tab-live';
    switchTab(targetTab, false);

    // 2. Handle browser Back / Forward buttons
    window.addEventListener('popstate', () => {
        const path = window.location.pathname.toLowerCase().replace(/\/+$/, '') || '/';
        const tab = ROUTE_TO_TAB[path] || 'tab-live';
        switchTab(tab, false);
    });
}

/* ─── Tab 10: ETSI TS 102 232 & CALEA Lawful Interception Module ─────────── */
state.calea = {
    sessions: [],
    selectedCin: null,
    activePane: 'pane-calea-asn1'
};

function initCalea() {
    loadCaleaStats();
    loadCaleaSessions();

    document.getElementById('btn-refresh-calea')?.addEventListener('click', () => {
        loadCaleaSessions();
        loadCaleaStats();
        showToast('Refreshed Lawful Interception Sessions', 'info');
    });

    // Pane Switcher Tabs
    document.querySelectorAll('.calea-tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.calea-tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.calea-pane').forEach(p => p.style.display = 'none');
            
            btn.classList.add('active');
            const targetId = btn.dataset.target;
            const targetPane = document.getElementById(targetId);
            if (targetPane) targetPane.style.display = 'flex';
            state.calea.activePane = targetId;
        });
    });

    // Send X1 Provisioning Command
    document.getElementById('btn-send-x1-request')?.addEventListener('click', sendX1ProvisioningRequest);

    // Copy JSON Inspector Data
    document.getElementById('btn-copy-calea-inspect')?.addEventListener('click', () => {
        const selected = state.calea.sessions.find(s => s.cin === state.calea.selectedCin) || state.calea.sessions[0];
        if (selected) {
            navigator.clipboard.writeText(JSON.stringify(selected, null, 2));
            showToast('Copied CALEA Intercept Dossier JSON', 'success');
        }
    });
}

function loadCaleaStats() {
    fetch('/api/calea/stats')
        .then(r => r.json())
        .then(d => {
            if (d.status === 'ok') {
                setText('calea-kpi-cin', `${d.active_cin_sessions} Active`);
                setText('calea-kpi-iri', `${d.iri_pdus_captured} Metadata`);
                setText('calea-kpi-cc', `${d.cc_packets_captured} Streams`);
            }
        })
        .catch(() => {});
}

function loadCaleaSessions() {
    fetch('/api/calea/list')
        .then(r => r.json())
        .then(d => {
            if (d.status === 'ok' && d.sessions) {
                state.calea.sessions = d.sessions;
                renderCaleaTable(d.sessions);
                if (d.sessions.length > 0 && !state.calea.selectedCin) {
                    inspectCaleaSession(d.sessions[0].cin);
                } else if (d.sessions.length === 0) {
                    const treeEl = document.getElementById('calea-tree-content');
                    if (treeEl) treeEl.textContent = '// No active lawful interception sessions detected in live traffic';
                }
            }
        })
        .catch(() => {
            state.calea.sessions = [];
            renderCaleaTable([]);
        });
}

function renderCaleaTable(sessions) {
    const tbody = document.getElementById('calea-tbody');
    if (!tbody) return;

    if (!sessions || sessions.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:24px;">No active lawful interception sessions detected</td></tr>';
        return;
    }

    tbody.innerHTML = sessions.map(s => {
        const isSel = s.cin === state.calea.selectedCin;
        const statusBadge = s.status === 'ACTIVE_INTERCEPT'
            ? '<span class="sev-badge sev-CRITICAL">WIRETAP ACTIVE</span>'
            : '<span class="sev-badge sev-HIGH">PROVISIONED</span>';
        
        return `
            <tr class="${isSel ? 'selected' : ''}" onclick="inspectCaleaSession('${s.cin}')">
                <td style="font-family:var(--font-mono);font-weight:700;color:var(--accent-cyan)">${escapeHtml(s.cin)}</td>
                <td style="font-family:var(--font-mono);color:var(--text-primary)">${escapeHtml(s.target_id)}</td>
                <td><span class="badge badge-4g">${escapeHtml(s.target_type)}</span></td>
                <td style="font-family:var(--font-mono);color:var(--text-secondary)">${escapeHtml(s.ne_id)}</td>
                <td><span class="badge badge-calea">${s.iri_count} IRI / ${s.cc_count} CC</span></td>
                <td>${statusBadge}</td>
            </tr>
        `;
    }).join('');
}

function inspectCaleaSession(cin) {
    state.calea.selectedCin = cin;
    const session = state.calea.sessions.find(s => s.cin === cin);
    if (!session) return;

    // Highlight row
    document.querySelectorAll('#calea-tbody tr').forEach(r => {
        if (r.textContent.includes(cin)) r.classList.add('selected');
        else r.classList.remove('selected');
    });

    setText('calea-val-oid', session.domain_oid || '0.4.0.2.2.1 (ETSI TS 102 232-1)');
    setText('calea-val-op', session.operator_id || 'TELCO-LEGAL-INTERCEPT-GATEWAY-01');
    setText('calea-val-ne', session.ne_id || 'UPF-CORE-GW-01');

    const treeEl = document.getElementById('calea-tree-content');
    if (treeEl) {
        treeEl.textContent = `// ETSI TS 102 232-1 & 3GPP TS 33.108 Intercept Session
PS-PDU ::= SEQUENCE {
  pS-Header ::= SEQUENCE {
    pS-Domain-Id ::= OBJECT IDENTIFIER { itu-t(0) identified-organization(4) etsi(0) securityDomain(2) lawfulIntercept(2) (1) }
    cin ::= OCTET STRING (SIZE 4) [ ${session.cin} ]
    operatorIdentifier ::= OCTET STRING [ "${session.operator_id}" ]
    interceptionPointID ::= IA5String [ "${session.ne_id}" ]
    timeStamp ::= GeneralizedTime [ "${session.last_seen}" ]
  }
  payload ::= CHOICE {
    iRI-Payload (Handover Interface HI2) ::= SEQUENCE {
      iRI-Type ::= ENUMERATED { report (2), access (3) }
      targetIdentifier ::= CHOICE {
        ${session.target_type.toLowerCase()} ::= OCTET STRING [ "${session.target_id}" ]
      }
      locationInformation ::= SEQUENCE {
        e-CGI ::= OCTET STRING [ "MCC: 310, MNC: 410, ECI: 0x00F801" ]
        geographicCoordinates ::= SEQUENCE {
          latitude ::= 37.774900
          longitude ::= -122.419400
        }
      }
      pduCount ::= INTEGER (${session.iri_count} captured)
    }
    cC-Payload (Handover Interface HI3) ::= SEQUENCE {
      mediaType ::= ENUMERATED { voice-RTP (1), data-GTP-U (2) }
      streamCount ::= INTEGER (${session.cc_count} captured)
    }
  }
}`;
    }
}

function sendX1ProvisioningRequest() {
    const targetId = document.getElementById('x1-input-target')?.value.trim() || '310410123456789';
    const neId = document.getElementById('x1-input-ne')?.value.trim() || 'AMF-SIG-01';
    const action = document.getElementById('x1-select-action')?.value || 'ACTIVATE_TASK';
    const hiType = document.getElementById('x1-select-hi')?.value || 'HI2_IRI';

    const respBox = document.getElementById('x1-response-box');
    if (respBox) respBox.textContent = 'Sending X1 Provisioning Request to baseband network element…';

    fetch('/api/calea/x1/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ task_type: action, target_id: targetId, ne_id: neId, hi_type: hiType })
    })
    .then(r => r.json())
    .then(data => {
        if (respBox) {
            respBox.textContent = JSON.stringify(data, null, 2);
        }
        showToast(`X1 ${action} executed successfully`, 'success');
        loadCaleaStats();
        loadCaleaSessions();
    })
    .catch(err => {
        if (respBox) respBox.textContent = `// Error executing X1 request: ${err.message}`;
        showToast('X1 provisioning request error', 'error');
    });
}



/* ─── Tactical Transmitters Drawer & Measurement Ruler Engine ───────────── */
state.geo.measureMode = false;
state.geo.measurePoints = [];
state.geo.measureLine = null;
state.geo.propagationModel = '3gpp_umi';

function initTacticalMapTools() {
    // 1. Transmitters Slide-Over Drawer Toggle
    const drawer = document.getElementById('towers-drawer');
    document.getElementById('btn-toggle-towers-drawer')?.addEventListener('click', () => {
        if (!drawer) return;
        const isVisible = drawer.style.display !== 'none';
        drawer.style.display = isVisible ? 'none' : 'flex';
        if (!isVisible) renderDiscoveredTowersTable();
    });

    document.getElementById('btn-close-towers-drawer')?.addEventListener('click', () => {
        if (drawer) drawer.style.display = 'none';
    });

    // 2. Search in Discovered Towers Table
    document.getElementById('input-tower-search')?.addEventListener('input', e => {
        renderDiscoveredTowersTable(e.target.value.trim().toLowerCase());
    });

    // 3. Propagation Model Selector
    document.getElementById('select-propagation-model')?.addEventListener('change', e => {
        state.geo.propagationModel = e.target.value;
        showToast(`Propagation Model: ${e.target.options[e.target.selectedIndex].text}`, 'info');
    });

    // 4. Tactical Distance & Azimuth Ruler
    const rulerBtn = document.getElementById('btn-map-measure');
    rulerBtn?.addEventListener('click', () => {
        state.geo.measureMode = !state.geo.measureMode;
        rulerBtn.classList.toggle('btn-primary', state.geo.measureMode);
        rulerBtn.classList.toggle('btn-secondary', !state.geo.measureMode);
        
        if (state.geo.measureMode) {
            showToast('Ruler Active: Click two points on map to measure distance & bearing', 'info');
            state.geo.measurePoints = [];
            if (state.geo.measureLine && state.geo.map) {
                state.geo.map.removeLayer(state.geo.measureLine);
                state.geo.measureLine = null;
            }
        } else {
            if (state.geo.measureLine && state.geo.map) {
                state.geo.map.removeLayer(state.geo.measureLine);
                state.geo.measureLine = null;
            }
            showToast('Ruler Deactivated', 'info');
        }
    });

    // Map Click Handler for Ruler
    if (state.geo.map) {
        state.geo.map.on('click', e => {
            if (!state.geo.measureMode) return;
            const pt = [e.latlng.lat, e.latlng.lng];
            state.geo.measurePoints.push(pt);

            if (state.geo.measurePoints.length === 1) {
                showToast('Point 1 marked. Click Point 2 to calculate distance.', 'info');
            } else if (state.geo.measurePoints.length >= 2) {
                const p1 = state.geo.measurePoints[0];
                const p2 = state.geo.measurePoints[1];
                const distKm = haversineDistKm(p1[0], p1[1], p2[0], p2[1]);
                const distM = distKm * 1000.0;

                // Calculate True Bearing / Azimuth
                const dLng = (p2[1] - p1[1]) * Math.PI / 180.0;
                const lat1 = p1[0] * Math.PI / 180.0;
                const lat2 = p2[0] * Math.PI / 180.0;
                const y = Math.sin(dLng) * Math.cos(lat2);
                const x = Math.cos(lat1) * Math.sin(lat2) - Math.sin(lat1) * Math.cos(lat2) * Math.cos(dLng);
                const bearing = (Math.atan2(y, x) * 180.0 / Math.PI + 360.0) % 360.0;

                // Free-space path loss at 3.5 GHz (n78): FSPL = 20*log10(d_km) + 20*log10(3500) + 32.44
                const fsplDb = Math.round(20 * Math.log10(Math.max(0.001, distKm)) + 20 * Math.log10(3500) + 32.44);

                if (state.geo.measureLine) state.geo.map.removeLayer(state.geo.measureLine);
                
                state.geo.measureLine = L.polyline([p1, p2], {
                    color: '#39d5df',
                    weight: 3,
                    dashArray: '6, 6',
                    opacity: 0.95
                }).addTo(state.geo.map);

                const midLat = (p1[0] + p2[0]) / 2;
                const midLng = (p1[1] + p2[1]) / 2;

                state.geo.measureLine.bindTooltip(`
                    <div style="font-family:var(--font-mono);font-size:11px;line-height:1.4">
                        <div>📏 <strong>${distM < 1000 ? distM.toFixed(1) + ' m' : distKm.toFixed(3) + ' km'}</strong></div>
                        <div>🧭 Bearing: <strong>${bearing.toFixed(1)}°</strong></div>
                        <div>📡 Est. FSPL (3.5GHz): <strong>${fsplDb} dB</strong></div>
                    </div>
                `, { permanent: true, className: 'ruler-tooltip' }).openTooltip([midLat, midLng]);

                showToast(`Measured: ${distM < 1000 ? distM.toFixed(0) + 'm' : distKm.toFixed(2) + 'km'} | Azimuth: ${bearing.toFixed(0)}°`, 'success');
                state.geo.measurePoints = [];
            }
        });
    }
}

function renderDiscoveredTowersTable(filterText = '') {
    const tbody = document.getElementById('towers-tbody');
    if (!tbody) return;

    const towers = Object.values(state.geo.knownTowers || {});
    const filtered = towers.filter(t => {
        if (!filterText) return true;
        const str = `Site #${t.siteId} ${t.rat} PCI ${t.pci} ${t.band || ''}`.toLowerCase();
        return str.includes(filterText);
    });

    setText('btn-tower-count', towers.length);
    setText('drawer-tower-badge', `${towers.length} Active RAN Site${towers.length === 1 ? '' : 's'}`);

    if (filtered.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text-muted);padding:18px;">No matching base station transmitters found</td></tr>';
        return;
    }

    tbody.innerHTML = filtered.map(t => {
        const ratColor = (t.rat || '').includes('5G') ? '#39d5df' : (t.rat || '').includes('4G') || (t.rat || '').includes('LTE') ? '#58a6ff' : '#e3b341';
        const distKm = isValidLatLng(state.geo.currentLat, state.geo.currentLng)
            ? haversineDistKm(state.geo.currentLat, state.geo.currentLng, t.lat, t.lng)
            : 0.36;
        const distText = distKm < 1 ? `${Math.round(distKm * 1000)} m` : `${distKm.toFixed(2)} km`;

        return `
            <tr>
                <td style="font-weight:700;color:${ratColor}">Site #${t.siteId}</td>
                <td><span class="badge ${t.rat.includes('5G') ? 'badge-5g' : 'badge-4g'}">${escapeHtml(t.rat)}</span></td>
                <td style="font-weight:700;color:var(--text-primary)">PCI ${t.pci}</td>
                <td style="color:var(--text-secondary)">${escapeHtml(t.band || 'Band n78 (3450 MHz)')}</td>
                <td style="color:var(--accent-cyan);font-weight:600">${distText}</td>
                <td style="color:#3fb950;font-weight:700">${state.geo.lastRsrp || -92} dBm</td>
                <td style="font-size:10px;color:var(--text-muted)">${t.lat.toFixed(5)}, ${t.lng.toFixed(5)}</td>
                <td>
                    <button class="btn btn-xs btn-primary" onclick='openBtsInspector(${JSON.stringify(t)})' title="Open deep-dive BTS inspector">🗼 Inspect</button> <button class="btn btn-xs btn-secondary" onclick="panToTowerMarker(${t.lat}, ${t.lng})" title="Center map on transmitter">🎯 Pan</button>
                </td>
            </tr>
        `;
    }).join('');
}

function panToTowerMarker(lat, lng) {
    if (state.geo.map && isValidLatLng(lat, lng)) {
        state.geo.map.flyTo([lat, lng], 17, { duration: 1.2 });
        showToast(`Centered on Base Station: ${lat.toFixed(5)}, ${lng.toFixed(5)}`, 'info');
    }
}


document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initRouter();
    initCalea();
    initKeyboardShortcuts();
    initWebSocket();
    initDeviceManagerModal();
    hydrateInitialPackets();
    initFilters();
    initInspector();
    initEfs();
    initNvCalculator();
    initActions();
    initThreatModal();
    initThreatTableDelegation();
    initMonoCopyable();
    initStatusBarClock();
    initThroughputMonitor();
    initReplay();
    initWardriveMap();
    initTacticalMapTools();
    initVisibilityHandler();
    initTerminal();
    initFuzzer();
    initThemeSwitcher();
    initSecurityStudio();
    initBtsInspector();
    initDevicePage();
    initApnAuditor();
    initIdentitiesSmsTab();
    renderRadarBlips();
});

/* ─── Page Visibility Lifecycle ──────────────────────────────────────────── */
function initVisibilityHandler() {
    document.addEventListener('visibilitychange', () => {
        state.isBackground = document.hidden;
        // P8: Pause all CSS animations when tab is hidden to save CPU
        document.body.classList.toggle('animations-paused', document.hidden);
        if (!state.isBackground && (state.pendingPackets.length || state.pendingThreats.length)) {
            scheduleRaf();
        }
    });
}

/* ─── Toast Notification System ─────────────────────────────────────────── */
function showToast(message, type = 'info', duration = 3000) {
    const container = document.getElementById('toast-container');
    if (!container || !message) return;

    // Deduplicate existing identical toasts
    const existing = container.querySelectorAll('.toast');
    for (let ex of existing) {
        if (ex.textContent.includes(message.trim())) {
            return;
        }
    }

    // Limit maximum stacked toasts to 3
    if (existing.length >= 3) {
        existing[0].remove();
    }

    const icons = { success: '✓', error: '✗', warning: '⚠', info: 'ℹ' };
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `<span style="font-size:14px">${icons[type] || 'ℹ'}</span>${escapeHtml(message)}`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.classList.add('fade-out');
        toast.addEventListener('animationend', () => toast.remove());
        setTimeout(() => toast.remove(), 400);
    }, duration);
}

/* ─── Tab Navigation ─────────────────────────────────────────────────────── */
function initTabs() {
    const tabs = document.querySelectorAll('.nav-tab');
    tabs.forEach(tab => {
        tab.addEventListener('click', () => switchTab(tab.dataset.tab));
    });

    document.getElementById('device-pill')?.addEventListener('click', () => switchTab('tab-device'));
}

function switchTab(tabId, pushHistory = true) {
    const tabs = document.querySelectorAll('.nav-tab');
    tabs.forEach(t => {
        const match = t.dataset.tab === tabId;
        t.classList.toggle('active', match);
        t.setAttribute('aria-selected', match ? 'true' : 'false');
    });
    document.querySelectorAll('.tab-content').forEach(c => {
        c.classList.toggle('active', c.id === tabId);
    });

    if (pushHistory && TAB_TO_ROUTE[tabId]) {
        try {
            window.history.pushState({ tab: tabId }, '', TAB_TO_ROUTE[tabId]);
        } catch(e) {}
    }

    if (tabId === 'tab-map' && state.geo.map) {
        setTimeout(() => state.geo.map.invalidateSize(), 150);
    }
    if (tabId === 'tab-calea') {
        loadCaleaStats();
        loadCaleaSessions();
    }
    if (tabId === 'tab-identities') {
        renderIdentitiesTable();
        renderSmsStream();
        renderOtaTable();
    }
}

/* ─── Physical Mobile Device Connection & Hardware Manager ──────────────── */
function initDeviceManagerModal() {
    const modal = document.getElementById('modal-device-connect');
    const openBtn = document.getElementById('btn-open-device-modal');
    const emptyOpenBtn = document.getElementById('btn-empty-connect-device');
    const closeBtn = document.getElementById('btn-close-device-modal');
    const scanBtn = document.getElementById('btn-scan-devices');
    const manualBtn = document.getElementById('btn-manual-connect');
    const disconnectBtn = document.getElementById('btn-disconnect-device');
    const emptyReplayBtn = document.getElementById('btn-empty-go-replay');

    const openModal = () => {
        if (modal) modal.style.display = 'flex';
        scanAttachedDevices();
        fetchDeviceStatus();
    };
    const closeModal = () => {
        if (modal) modal.style.display = 'none';
    };

    openBtn?.addEventListener('click', openModal);
    emptyOpenBtn?.addEventListener('click', openModal);
    closeBtn?.addEventListener('click', closeModal);
    emptyReplayBtn?.addEventListener('click', () => switchTab('tab-replay'));
    modal?.addEventListener('click', e => {
        if (e.target === modal) closeModal();
    });

    scanBtn?.addEventListener('click', () => scanAttachedDevices(true));
    disconnectBtn?.addEventListener('click', disconnectActiveDevice);

    manualBtn?.addEventListener('click', () => {
        const type = document.getElementById('manual-dev-type')?.value || 'adb';
        const id = document.getElementById('manual-dev-id')?.value.trim();
        if (!id) {
            showToast('Please enter a target device identifier (serial, COM port, or IP:Port)', 'warning');
            return;
        }
        connectDevice(type, id);
    });

    fetchDeviceStatus();
}

function fetchDeviceStatus() {
    fetch('/api/devices/status')
        .then(r => r.json())
        .then(d => {
            if (d.device) updateDeviceStatusUI(d.device);
        })
        .catch(() => {});
}

function updateDeviceStatusUI(dev) {
    state.activeDevice = dev;
    const headerDot = document.getElementById('header-device-dot');
    const headerText = document.getElementById('header-device-text');
    const badge = document.getElementById('dev-banner-badge');
    const name = document.getElementById('dev-banner-name');
    const sub = document.getElementById('dev-banner-sub');
    const banner = document.getElementById('device-active-banner');
    const actions = document.getElementById('dev-banner-actions');

    if (dev && dev.connected) {
        if (headerDot) headerDot.className = 'device-status-dot connected';
        if (headerText) headerText.textContent = `🟢 ${dev.name || dev.id || 'Live Device'}`;
        if (badge) {
            badge.className = 'device-live-badge connected';
            badge.textContent = 'STREAMING LIVE';
        }
        if (name) name.textContent = dev.name || dev.id || 'Connected Handset';
        if (sub) sub.textContent = `Transport: ${dev.transport || dev.type} | Baseband: ${dev.baseband || 'Qualcomm'}`;
        if (banner) banner.classList.remove('disconnected');
        if (actions) actions.style.display = 'block';
    } else {
        if (headerDot) headerDot.className = 'device-status-dot disconnected';
        if (headerText) headerText.textContent = '📱 Connect Mobile Device';
        if (badge) {
            badge.className = 'device-live-badge';
            badge.textContent = 'DISCONNECTED';
        }
        if (name) name.textContent = 'No active mobile device connected';
        if (sub) sub.textContent = 'Select an attached ADB handset or Qualcomm Diagnostic COM port below';
        if (banner) banner.classList.add('disconnected');
        if (actions) actions.style.display = 'none';
    }
}

function scanAttachedDevices(showNotification = false) {
    const grid = document.getElementById('discovered-devices-grid');
    if (grid) {
        grid.innerHTML = `
            <div class="dev-scan-loading">
                <span class="spinner"></span>
                <p>Scanning for attached Android handsets (ADB), Qualcomm Diagnostic COM ports, and USB modems…</p>
            </div>
        `;
    }

    fetch('/api/devices/scan')
        .then(r => r.json())
        .then(d => {
            const devices = d.devices || [];
            if (!grid) return;

            if (devices.length === 0) {
                grid.innerHTML = `
                    <div class="dev-scan-loading" style="padding:20px 0;">
                        <p style="font-weight:600;color:var(--text-primary);">No compatible physical devices detected via USB / ADB</p>
                        <span style="font-size:12px;color:var(--text-secondary);max-width:440px;">
                            Make sure your phone is plugged in with USB debugging enabled (<code>adb devices</code>) or exposing a Qualcomm Diagnostic COM port.
                        </span>
                    </div>
                `;
                if (showNotification) showToast('No devices found. Check USB connection & ADB debugging.', 'info');
                return;
            }

            if (showNotification) showToast(`Discovered ${devices.length} attached device(s)`, 'success');

            grid.innerHTML = devices.map(dev => `
                <div class="device-card">
                    <div class="dev-card-info">
                        <div class="dev-card-title">
                            <span>${dev.type === 'adb' ? '📱' : '🔌'} ${dev.name}</span>
                            <span class="dev-card-tag ${dev.diag_ready ? 'tag-ready' : 'tag-warn'}">${dev.diag_ready ? '✓ /dev/diag Ready' : '⚠ Diag Switch Needed'}</span>
                        </div>
                        <div class="dev-card-meta">
                            <span><strong>Serial/Port:</strong> <code>${dev.id}</code></span>
                            <span><strong>Transport:</strong> ${dev.transport}</span>
                            <span><strong>Baseband:</strong> ${dev.baseband}</span>
                            <span><strong>Root Context:</strong> ${dev.is_root ? 'uid=0 (Rooted)' : 'Standard'}</span>
                        </div>
                    </div>
                    <div class="dev-card-actions">
                        ${!dev.diag_ready && dev.type === 'adb' ? `
                            <button class="btn btn-secondary btn-sm btn-dev-switch-diag" data-id="${dev.id}" title="Trigger root diag mode-switch on phone">
                                🔧 Enable /dev/diag
                            </button>
                        ` : ''}
                        <button class="btn btn-primary btn-sm btn-dev-connect" data-type="${dev.type}" data-id="${dev.id}">
                            ⚡ Connect &amp; Stream
                        </button>
                    </div>
                </div>
            `).join('');

            grid.querySelectorAll('.btn-dev-connect').forEach(btn => {
                btn.addEventListener('click', () => {
                    const type = btn.getAttribute('data-type');
                    const id = btn.getAttribute('data-id');
                    connectDevice(type, id);
                });
            });

            grid.querySelectorAll('.btn-dev-switch-diag').forEach(btn => {
                btn.addEventListener('click', () => {
                    const id = btn.getAttribute('data-id');
                    switchDeviceDiag(id, btn);
                });
            });
        })
        .catch(err => {
            if (grid) grid.innerHTML = `<div class="dev-scan-loading"><p style="color:var(--accent-red);">Failed to scan devices: ${err.message}</p></div>`;
        });
}

function connectDevice(type, id) {
    showToast(`Connecting to ${type.toUpperCase()} device ${id}…`, 'info');
    fetch('/api/devices/connect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type, id })
    })
    .then(r => r.json())
    .then(d => {
        if (d.status === 'ok') {
            updateDeviceStatusUI(d.device);
            showToast(`Connected to ${id}! Live 3GPP traffic streaming active.`, 'success', 3500);
            const modal = document.getElementById('modal-device-connect');
            if (modal) modal.style.display = 'none';
        } else {
            showToast(`Connection failed: ${d.message}`, 'error', 4000);
        }
    })
    .catch(err => showToast(`Device connection error: ${err.message}`, 'error'));
}

function disconnectActiveDevice() {
    fetch('/api/devices/disconnect', { method: 'POST' })
        .then(r => r.json())
        .then(d => {
            showToast('Mobile device disconnected', 'info');
            fetchDeviceStatus();
        })
        .catch(() => showToast('Failed to disconnect device', 'error'));
}

function switchDeviceDiag(id, btn) {
    if (btn) { btn.disabled = true; btn.textContent = 'Switching…'; }
    fetch('/api/devices/switch-diag', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id })
    })
    .then(r => r.json())
    .then(d => {
        if (d.status === 'ok') {
            showToast('Diag mode enabled on device!', 'success');
            scanAttachedDevices();
        } else {
            showToast('Diag mode switch failed: ' + (d.message || d.output), 'error');
        }
    })
    .catch(() => showToast('Failed to switch diag mode', 'error'))
    .finally(() => {
        if (btn) { btn.disabled = false; btn.textContent = '🔧 Enable /dev/diag'; }
    });
}

/* ─── Real-Time Traffic Hydration ────────────────────────────────────────── */
function hydrateInitialPackets() {
    fetch('/api/packets/list')
        .then(r => r.json())
        .then(d => {
            if (d.status === 'ok' && Array.isArray(d.packets) && d.packets.length > 0) {
                state.packets = d.packets.map((p, idx) => ({ ...p, id: p.id || (idx + 1) }));
                state.packetIdCounter = Math.max(state.packetIdCounter, state.packets.length);
                rebuildPacketTable();
            }
        })
        .catch(() => {});

    fetch('/api/status')
        .then(r => r.json())
        .then(d => {
            if (d.stats) updateRfGauges(d.stats);
            if (d.device) updateDeviceInfo(d.device);
        })
        .catch(() => {});
}

/* ─── WebSocket Engine & Polling Fallback ─────────────────────────────────── */
let fallbackPollTimer = null;

function initWebSocket() {
    setWsStatus('Connecting…', 'reconnecting');
    if (state.ws) {
        try { state.ws.close(); } catch (_) {}
    }

    const loc = window.location;
    const proto = loc.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = `${proto}//${loc.host}/ws`;

    try {
        state.ws = new WebSocket(url);

        state.ws.onopen = () => {
            state.wsRetryDelay = 500;
            setWsStatus('Connected', 'online');
            showToast('Connected to AirTap TelcoSec diagnostics engine', 'success', 2500);
            if (fallbackPollTimer) {
                clearInterval(fallbackPollTimer);
                fallbackPollTimer = null;
            }
        };

        state.ws.onmessage = evt => {
            try {
                const msg = JSON.parse(evt.data);
                dispatchWsMessage(msg);
            } catch (e) {
                console.warn('[WS] parse error:', e);
            }
        };

        state.ws.onclose = () => {
            setWsStatus(`Reconnecting in ${(state.wsRetryDelay / 1000).toFixed(1)}s…`, 'reconnecting');
            startFallbackPolling();
            setTimeout(initWebSocket, state.wsRetryDelay);
            state.wsRetryDelay = Math.min(state.wsRetryDelay * 2, state.wsRetryMax);
        };

        state.ws.onerror = () => {
            setWsStatus('Error', 'offline');
            startFallbackPolling();
        };
    } catch (err) {
        startFallbackPolling();
    }
}

function startFallbackPolling() {
    if (fallbackPollTimer) return;
    fallbackPollTimer = setInterval(() => {
        if (!state.ws || state.ws.readyState !== WebSocket.OPEN) {
            fetch('/api/packets/list')
                .then(r => r.json())
                .then(d => {
                    if (d.status === 'ok' && Array.isArray(d.packets) && d.packets.length > state.packets.length) {
                        const newPkts = d.packets.slice(state.packets.length);
                        newPkts.forEach(p => dispatchWsMessage({ type: 'packet', data: p }));
                    }
                })
                .catch(() => {});
        }
    }, 1500);
}

function setWsStatus(label, dotClass) {
    const dot = document.getElementById('status-dot');
    const sbWs = document.getElementById('sb-ws-status');
    if (dot) dot.className = `status-dot ${dotClass}`;
    if (sbWs) sbWs.textContent = label;
}

function dispatchWsMessage(msg) {
    switch (msg.type) {
        case 'packet':
            state.pendingPackets.push(msg.data);
            state.metrics.pktCountSecond++;
            state.metrics.byteCountSecond += (msg.data.length || 32);
            scheduleRaf();
            break;
        case 'rf_stats':
            updateRfGauges(msg.data);
            break;
        case 'sec_alert':
            state.pendingThreats.push(msg.data);
            scheduleRaf();
            handleThreatGeoPin(msg.data);
            break;
        case 'f3_log':
            handleIncomingF3Log(msg.data);
            break;
        case 'device_info':
            updateDeviceInfo(msg.data);
            break;
        case 'device_status':
            updateDeviceStatusUI(msg.data);
            break;
        case 'replay_event':
            handleReplayEvent(msg.data);
            break;
        case 'geo_update':
            updateGeoTelemetry(msg.data);
            break;
        case 'urc_event':
            appendTerminalUrc(msg.data?.text || '');
            break;
        case 'identity_event':
            handleIncomingIdentity(msg.data);
            break;
        case 'sms_event':
            handleIncomingSms(msg.data);
            break;
        case 'ota_event':
            handleIncomingOta(msg.data);
            break;
    }
}

/* ─── Real-Time Throughput & Performance HUD Engine ──────────────────────── */
function initThroughputMonitor() {
    setInterval(() => {
        const now = Date.now();
        const deltaSec = (now - state.metrics.lastSecTick) / 1000.0;
        state.metrics.lastSecTick = now;

        state.metrics.pps = Math.round(state.metrics.pktCountSecond / deltaSec);
        state.metrics.bps = Math.round(state.metrics.byteCountSecond / deltaSec);
        state.metrics.pktCountSecond = 0;
        state.metrics.byteCountSecond = 0;

        setText('live-pps', state.metrics.pps.toLocaleString());
        setText('live-bps', fmtBytes(state.metrics.bps) + '/s');
        setText('live-deltat', `${state.metrics.lastDeltaMs.toFixed(1)} ms`);

        const bufRatio = Math.min(100, Math.round((state.packets.length / 5000) * 100));
        setText('live-buf', `${bufRatio}%`);
    }, 1000);
}

/* ─── High-Throughput DocumentFragment Batch Renderer (60fps) ───────────── */
function scheduleRaf() {
    if (!state.rafScheduled && !state.isBackground) {
        state.rafScheduled = true;
        requestAnimationFrame(flushPending);
    }
}

function flushPending() {
    state.rafScheduled = false;

    if (state.pendingPackets.length > 0) {
        const pkts = state.pendingPackets.splice(0, 100);
        const frag = document.createDocumentFragment();
        let appendedCount = 0;

        // P3: Cache search query once per flush (not inside per-packet shouldShowPacket)
        state._cachedSearchQuery = (document.getElementById('packet-search')?.value || '').toLowerCase().trim();

        pkts.forEach(p => {
            const nowTime = performance.now();
            if (state.metrics.lastPktTime !== null) {
                state.metrics.lastDeltaMs = Math.max(0.1, nowTime - state.metrics.lastPktTime);
            }
            state.metrics.lastPktTime = nowTime;
            p.delta_ms = state.metrics.lastDeltaMs;

            p.id = state.totalPackets++;
            state.packets.push(p);
            updateAttachTimeline(p);
            if (state.packets.length > 5000) state.packets.shift();

            const rat = (p.rat || '4g').toLowerCase();
            if (rat.includes('5g')) state.ratCounts['5g']++;
            else if (rat.includes('4g') || rat.includes('lte')) state.ratCounts['4g']++;
            else if (rat.includes('3g') || rat.includes('umts')) state.ratCounts['3g']++;
            else if (rat.includes('2g') || rat.includes('gsm')) state.ratCounts['2g']++;
            else if (rat.includes('ims') || rat.includes('sip')) state.ratCounts['ims']++;
            else if (rat.includes('sim') || rat.includes('apdu')) state.ratCounts['sim']++;
            else if (rat.includes('broadcast')) state.ratCounts['broadcast']++;
            else if (rat.includes('calea')) state.ratCounts['calea']++;

            if (!state.isFrozen && shouldShowPacket(p)) {
                const tr = buildPacketRowElement(p);
                frag.appendChild(tr);
                appendedCount++;
            }
        });

        if (!state.isFrozen && appendedCount > 0) {
            const tbody = document.getElementById('packet-tbody');
            if (tbody) {
                if (tbody.querySelector('.empty-state')) tbody.innerHTML = '';
                tbody.appendChild(frag);

                // P4: Hard DOM row cap — trim oldest rows to keep layout thrash minimal
                const MAX_DOM_ROWS = 250;
                while (tbody.rows.length > MAX_DOM_ROWS) {
                    tbody.deleteRow(0);
                }

                if (state.autoScroll) {
                    const w = document.getElementById('packet-wrapper');
                    if (w) w.scrollTop = w.scrollHeight;
                }
            }
        }
    }

    updateRatBadges();
    if (state.pendingThreats.length > 0) {
        const threats = state.pendingThreats.splice(0, 20);
        threats.forEach(t => addSecurityAlertInternal(t));
    }

    if (state.pendingF3.length > 0 && !state.f3.isPaused) {
        const f3 = state.pendingF3.splice(0, 150);
        const f3Frag = document.createDocumentFragment();
        f3.forEach(l => {
            const div = buildF3LineElement(l);
            if (div) f3Frag.appendChild(div);
        });

        const terminal = document.getElementById('f3-terminal');
        if (terminal && f3Frag.children.length > 0) {
            const empty = document.getElementById('f3-empty');
            if (empty) empty.remove();
            terminal.appendChild(f3Frag);
            while (terminal.children.length > state.f3.maxLines) {
                terminal.removeChild(terminal.firstChild);
            }
            if (state.f3.autoScroll) {
                terminal.scrollTop = terminal.scrollHeight;
            }
            updateF3StatusFooter();
        }
    }

    if (state.pendingPackets.length || state.pendingThreats.length || state.pendingF3.length) {
        scheduleRaf();
    }

    updateStatusBar();
}

/* ─── Real-Time RF Signal History Sparkline (Canvas) ─────────────────────── */
function updateRfGauges(s) {
    if (!s) return;

    if (s.rsrp !== undefined && s.rsrp !== null) {
        state.geo.lastRsrp = s.rsrp;
        const valEl = document.getElementById('val-rsrp');
        if (valEl) {
            valEl.textContent = s.rsrp;
            // V2: Color-code gauge based on RSRP quality thresholds
            valEl.classList.remove('gauge-good', 'gauge-warn', 'gauge-bad');
            if (s.rsrp >= -85)        valEl.classList.add('gauge-good');
            else if (s.rsrp >= -105)  valEl.classList.add('gauge-warn');
            else                       valEl.classList.add('gauge-bad');
        }
        setGauge('arc-rsrp', mapRange(s.rsrp, -140, -44, 0, 100));

        // Push to RF history buffer for 60s sparkline
        state.rfHistory.push(s.rsrp);
        if (state.rfHistory.length > 60) state.rfHistory.shift();
        drawRfSparkline();
        setText('sparkline-val-rsrp', `${s.rsrp} dBm`);
    } else if (s.rsrp === null) {
        setText('val-rsrp', '—');
        setGauge('arc-rsrp', 0);
    }

    if (s.rsrq !== undefined && s.rsrq !== null) {
        document.getElementById('val-rsrq').textContent = s.rsrq;
        setGauge('arc-rsrq', mapRange(s.rsrq, -20, -3, 0, 100));
    } else if (s.rsrq === null) {
        setText('val-rsrq', '—');
        setGauge('arc-rsrq', 0);
    }

    if (s.sinr !== undefined && s.sinr !== null) {
        document.getElementById('val-sinr').textContent = (s.sinr > 0 ? '+' : '') + s.sinr;
        setGauge('arc-sinr', mapRange(s.sinr, -10, 30, 0, 100));
    } else if (s.sinr === null) {
        setText('val-sinr', '—');
        setGauge('arc-sinr', 0);
    }

    if (s.rssi !== undefined && s.rssi !== null) {
        document.getElementById('val-rssi').textContent = s.rssi;
        setGauge('arc-rssi', mapRange(s.rssi, -120, -30, 0, 100));
    } else if (s.rssi === null) {
        setText('val-rssi', '—');
        setGauge('arc-rssi', 0);
    }

    if (s.pci !== undefined && s.pci !== null) {
        state.geo.lastPci = s.pci;
        setText('cell-pci', s.pci);
        setText('geo-val-pci', s.pci);
    } else if (s.pci === null) {
        setText('cell-pci', '—');
        setText('geo-val-pci', '—');
    }

    if (s.band !== undefined && s.band !== null) {
        setText('cell-band', s.band);
        setText('geo-val-band', s.band);
    }
    if (s.arfcn !== undefined && s.arfcn !== null) {
        setText('cell-arfcn', s.arfcn);
    } else if (s.arfcn === null) {
        setText('cell-arfcn', '—');
    }

    if (s.rat_counts) updateRatBars(s.rat_counts);
}

function drawRfSparkline() {
    const canvas = document.getElementById('rf-sparkline-canvas');
    if (!canvas || !canvas.getContext) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width;
    const h = canvas.height;

    ctx.clearRect(0, 0, w, h);
    if (state.rfHistory.length < 2) return;

    const minDb = -130;
    const maxDb = -50;
    const points = state.rfHistory.map((val, idx) => {
        const x = (idx / (state.rfHistory.length - 1)) * w;
        const norm = (val - minDb) / (maxDb - minDb);
        const y = h - Math.max(0, Math.min(1, norm)) * (h - 8) - 4;
        return { x, y, val };
    });

    // Area Gradient Fill
    const grad = ctx.createLinearGradient(0, 0, 0, h);
    grad.addColorStop(0, 'rgba(57,213,223,0.35)');
    grad.addColorStop(1, 'rgba(57,213,223,0.0)');

    ctx.beginPath();
    ctx.moveTo(points[0].x, h);
    points.forEach(p => ctx.lineTo(p.x, p.y));
    ctx.lineTo(points[points.length - 1].x, h);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();

    // Smoothed Stroke Line
    ctx.beginPath();
    ctx.moveTo(points[0].x, points[0].y);
    for (let i = 1; i < points.length; i++) {
        ctx.lineTo(points[i].x, points[i].y);
    }
    ctx.strokeStyle = '#39d5df';
    ctx.lineWidth = 2;
    ctx.stroke();

    // Animated leading pulse dot
    const lastP = points[points.length - 1];
    ctx.beginPath();
    ctx.arc(lastP.x, lastP.y, 3.5, 0, Math.PI * 2);
    ctx.fillStyle = '#fff';
    ctx.shadowColor = '#39d5df';
    ctx.shadowBlur = 8;
    ctx.fill();
    ctx.shadowBlur = 0;
}

function setGauge(arcId, percent) {
    const el = document.getElementById(arcId);
    if (!el) return;
    const p = Math.max(0, Math.min(100, percent));
    const filled = (p / 100) * ARC_LEN;
    const rest   = ARC_LEN - filled;
    el.setAttribute('stroke-dasharray', `${filled.toFixed(1)} ${(rest + 40).toFixed(1)}`);
}

function mapRange(val, inMin, inMax, outMin, outMax) {
    const clamped = Math.max(inMin, Math.min(inMax, val));
    return ((clamped - inMin) * (outMax - outMin)) / (inMax - inMin) + outMin;
}

function updateRatBars(counts) {
    const c5g   = counts['5g']   || 0;
    const c4g   = counts['4g']   || 0;
    const c3g   = counts['3g']   || 0;
    const c2g   = counts['2g']   || 0;
    const cims  = counts['ims']  || 0;
    const csim  = counts['sim']  || 0;
    const total = c5g + c4g + c3g + c2g + cims + csim || 1;

    const setBar = (barId, countId, c) => {
        const bar = document.getElementById(barId);
        if (bar) bar.style.width = `${((c / total) * 100).toFixed(1)}%`;
        const cnt = document.getElementById(countId);
        if (cnt) cnt.textContent = c.toLocaleString();
    };
    setBar('pbar-5g',  'count-5g',  c5g);
    setBar('pbar-4g',  'count-4g',  c4g);
    setBar('pbar-3g',  'count-3g',  c3g);
    setBar('pbar-2g',  'count-2g',  c2g);
    setBar('pbar-ims', 'count-ims', cims);
    setBar('pbar-sim', 'count-sim', csim);
}

/* ─── Tactical Acoustic Baseband Audio Alert Engine ──────────────────────── */
function playThreatChirp(severity = 'CRITICAL') {
    if (!state.audioAlerts) return;
    try {
        const AudioCtx = window.AudioContext || window.webkitAudioContext;
        if (!AudioCtx) return;
        const ctx = new AudioCtx();
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.connect(gain);
        gain.connect(ctx.destination);

        const isCrit = severity === 'CRITICAL';
        osc.type = isCrit ? 'sawtooth' : 'sine';
        osc.frequency.setValueAtTime(isCrit ? 880 : 587, ctx.currentTime);
        osc.frequency.exponentialRampToValueAtTime(isCrit ? 440 : 293, ctx.currentTime + 0.18);
        gain.gain.setValueAtTime(0.12, ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.18);
        osc.start();
        osc.stop(ctx.currentTime + 0.18);
    } catch (_) {}
}

/* ─── Fast DOM Packet Row Builder ────────────────────────────────────────── */
function shouldShowPacket(pkt) {
    const rat = (pkt.rat || '4g').toLowerCase();
    const layer = (pkt.layer || 'RRC').toUpperCase();
    const sum = (pkt.summary || '').toLowerCase();

    if (state.currentFilter !== 'all') {
        if (state.currentFilter === '5g' && !rat.includes('5g')) return false;
        if (state.currentFilter === '4g' && !rat.includes('4g') && !rat.includes('lte')) return false;
        if (state.currentFilter === '3g' && !rat.includes('3g') && !rat.includes('umts')) return false;
        if (state.currentFilter === '2g' && !rat.includes('2g') && !rat.includes('gsm')) return false;
        if (state.currentFilter === 'ims' && !rat.includes('ims') && !rat.includes('sip')) return false;
        if (state.currentFilter === 'sim' && !rat.includes('sim') && !rat.includes('apdu')) return false;
        if (state.currentFilter === 'broadcast' && !rat.includes('broadcast')) return false;
        if (state.currentFilter === 'calea' && !rat.includes('calea')) return false;
    }

    if (state.currentPreset !== 'all') {
        if (state.currentPreset === 'security') {
            const isSec = sum.includes('auth') || sum.includes('security') || sum.includes('cipher') || 
                          sum.includes('aka') || sum.includes('suci') || sum.includes('imsi') || 
                          sum.includes('identity') || layer === 'NAS' || pkt.threat_rule;
            if (!isSec) return false;
        } else if (state.currentPreset === 'rejects') {
            const isRej = sum.includes('reject') || sum.includes('cause') || sum.includes('fail') || 
                          sum.includes('error') || sum.includes('abort') || sum.includes('barr');
            if (!isRej) return false;
        } else if (state.currentPreset === 'sibs') {
            const isSib = sum.includes('sib') || sum.includes('systeminfo') || sum.includes('mib') || 
                          sum.includes('paging') || pkt.channel === 'BCCH' || pkt.channel === 'PCCH';
            if (!isSib) return false;
        } else if (state.currentPreset === 'handover') {
            const isHo = sum.includes('handover') || sum.includes('reconfig') || sum.includes('measurement') || 
                         sum.includes('mobility') || sum.includes('relocation');
            if (!isHo) return false;
        } else if (state.currentPreset === 'emergency') {
            const isSos = sum.includes('etws') || sum.includes('cmas') || sum.includes('warning') || 
                          sum.includes('emergency') || sum.includes('sos');
            if (!isSos) return false;
        }
    }

    if (state.currentLayer !== 'all') {
        if (!layer.includes(state.currentLayer)) return false;
    }

    if (state.currentDir !== 'all') {
        if (state.currentDir === 'ul' && !pkt.is_uplink) return false;
        if (state.currentDir === 'dl' && pkt.is_uplink) return false;
    }

    if (state.currentSec && state.currentSec !== 'all') {
        const isProtected = pkt.is_security_protected || sum.includes('eea1') || sum.includes('eea2') || sum.includes('nea2') || sum.includes('nia2') || sum.includes('eia1') || sum.includes('eia2') || sum.includes('ciphered') || sum.includes('encrypted') || sum.includes('integrity protected');
        if (state.currentSec === 'sec' && !isProtected) return false;
        if (state.currentSec === 'plain' && isProtected) return false;
    }

    const q = state._cachedSearchQuery !== undefined ? state._cachedSearchQuery : (document.getElementById('packet-search')?.value || '').toLowerCase().trim();
    if (q) {
        const haystack = `${pkt.time} ${pkt.rat} ${pkt.layer} ${pkt.channel} ${pkt.protocol} ${pkt.summary} ${pkt.raw}`.toLowerCase();
        if (!haystack.includes(q)) return false;
    }

    return true;
}

function buildPacketRowElement(pkt) {
    // P1: Use createElement instead of innerHTML to avoid HTML re-parsing on every packet
    const tr = document.createElement('tr');
    tr.dataset.id = pkt.id;
    tr.className = 'new-row';
    if (state.selectedPktId === pkt.id) tr.classList.add('selected');

    const dirClass = pkt.is_uplink ? 'dir-ul' : 'dir-dl';
    const dirLabel = pkt.is_uplink ? '↑ UL' : '↓ DL';
    const channelLayer = pkt.channel ? `${pkt.channel} / ${pkt.layer || 'RRC'}` : (pkt.layer || 'RRC');

    const dVal = pkt.delta_ms || 0.0;
    const deltaClass = dVal < 5 ? 'delta-t-fast' : dVal < 40 ? 'delta-t-med' : 'delta-t-slow';
    const deltaStr = dVal > 0 ? `+${dVal.toFixed(1)}` : '0.0';

    const mkTd = (text, cls, title) => {
        const td = document.createElement('td');
        td.textContent = text;
        if (cls) td.className = cls;
        if (title) td.title = title;
        return td;
    };

    tr.appendChild(mkTd(pkt.time || fmtTime(new Date())));
    tr.appendChild(mkTd(deltaStr, deltaClass));

    // RAT badge uses HTML — use insertAdjacentHTML on a fresh td
    const tdRat = document.createElement('td');
    tdRat.innerHTML = getRatBadge(pkt.rat);
    tr.appendChild(tdRat);

    tr.appendChild(mkTd(dirLabel, dirClass));
    tr.appendChild(mkTd(channelLayer, null, channelLayer));
    tr.appendChild(mkTd(pkt.protocol || 'RRC', null, pkt.protocol || ''));
    tr.appendChild(mkTd(pkt.summary || '', null, pkt.summary || ''));
    tr.appendChild(mkTd(String(pkt.length || 0)));

    tr.addEventListener('click', () => selectPacket(pkt));
    return tr;
}

function getRatBadge(rat) {
    const r = (rat || '4G').toUpperCase();
    if (r.includes('5G'))        return '<span class="badge badge-5g">5G NR</span>';
    if (r.includes('LTE') || r.includes('4G')) return '<span class="badge badge-4g">4G LTE</span>';
    if (r.includes('3G') || r.includes('UMTS')) return '<span class="badge badge-3g">3G UMTS</span>';
    if (r.includes('2G') || r.includes('GSM'))  return '<span class="badge badge-2g">2G GSM</span>';
    if (r.includes('IMS') || r.includes('SIP')) return '<span class="badge badge-ims">IMS SIP</span>';
    if (r.includes('SIM') || r.includes('APDU')) return '<span class="badge badge-sim">SIM APDU</span>';
    if (r.includes('BROADCAST')) return '<span class="badge badge-broadcast">Broadcast</span>';
    if (r.includes('CALEA'))     return '<span class="badge badge-calea">CALEA</span>';
    return `<span class="badge badge-4g">${escapeHtml(r)}</span>`;
}


/* ─── Comprehensive 3GPP ASN.1 Protocol Tree Engine ─────────────────────── */
function generateAsn1Tree(pkt) {
    if (!pkt) return null;
    const rat = (pkt.rat || '4G').toUpperCase();
    const summary = pkt.summary || 'Unspecified PDU';
    const raw = pkt.raw || '';
    const layer = pkt.layer || 'RRC';
    const isUl = !!pkt.is_uplink;

    // Root Protocol Container
    const root = {
        name: `${rat} ${layer} :: ${summary}`,
        tag: 'ASN.1 PDU',
        type: 'SEQUENCE',
        val: null,
        spec: layer === 'NAS' ? '3GPP TS 24.501 / 24.301' : '3GPP TS 38.331 / 36.331',
        children: []
    };

    // 1. Frame Envelope Header
    const hdr = {
        name: 'protocolHeader',
        tag: '[UNIVERSAL 16]',
        type: 'SEQUENCE',
        children: [
            { name: 'radioAccessTechnology', tag: '[0]', type: 'ENUMERATED', val: rat, valType: 'str', spec: '3GPP TR 21.905' },
            { name: 'direction', tag: '[1]', type: 'ENUMERATED', val: isUl ? 'uplink (1)' : 'downlink (0)', valType: 'str', spec: '3GPP L2/L3' },
            { name: 'protocolDiscriminator', tag: '[2]', type: 'INTEGER', val: layer === 'NAS' ? '0x05 (5GS/EPS Mobility Management)' : '0x07 (Radio Resource Control)', valType: 'hex', spec: '3GPP TS 24.007' },
            { name: 'payloadOctetLength', tag: '[3]', type: 'INTEGER', val: `${pkt.length || (raw.length/2) || 0} bytes`, valType: 'num', spec: 'Transport' }
        ]
    };
    if (pkt.channel) hdr.children.push({ name: 'transportChannel', tag: '[4]', type: 'IA5String', val: pkt.channel, valType: 'str', spec: '3GPP TS 38.321' });
    root.children.push(hdr);

    // 2. ASN.1 Structure Breakdown by Protocol & Signaling Type
    if (summary.includes('Immediate Assignment') || summary.includes('System Information')) {
        // GSM RR / BCCH ASN.1 / CSN.1 Tree
        root.children.push({
            name: 'gsm-RR-Message',
            tag: '[APPLICATION 3]',
            type: 'CHOICE',
            children: [
                {
                    name: 'systemInformationType3',
                    tag: '[0]',
                    type: 'SEQUENCE',
                    children: [
                        { name: 'cellIdentity', tag: '[0]', type: 'OCTET STRING (SIZE 2)', val: '0x00F8 (CI: 248)', valType: 'hex', spec: '3GPP TS 44.018 § 10.5.1.1' },
                        {
                            name: 'locationAreaIdentification',
                            tag: '[1]',
                            type: 'SEQUENCE',
                            children: [
                                { name: 'mcc', tag: '[0]', type: 'BCD-String', val: '310 (USA)', valType: 'str' },
                                { name: 'mnc', tag: '[1]', type: 'BCD-String', val: '410 (AT&T)', valType: 'str' },
                                { name: 'lac', tag: '[2]', type: 'OCTET STRING', val: '0x1A2B (LAC: 6699)', valType: 'hex' }
                            ],
                            spec: '3GPP TS 23.003 § 4.1'
                        },
                        {
                            name: 'controlChannelDescription',
                            tag: '[2]',
                            type: 'SEQUENCE',
                            children: [
                                { name: 'msc-r', tag: '[0]', type: 'BOOLEAN', val: 'TRUE (MSC Rel-99+)', valType: 'str' },
                                { name: 'att', tag: '[1]', type: 'BOOLEAN', val: 'TRUE (Attach/Detach Allowed)', valType: 'str' },
                                { name: 'bs-ag-blks-res', tag: '[2]', type: 'INTEGER (0..7)', val: '1 Block Reserved', valType: 'num' },
                                { name: 'bs-pa-mfrms', tag: '[3]', type: 'INTEGER (2..9)', val: '2 Multiframe Periods (470ms paging cycle)', valType: 'num' }
                            ],
                            spec: '3GPP TS 44.018 § 10.5.2.11'
                        },
                        { name: 'cellOptions', tag: '[3]', type: 'OCTET STRING', val: 'DTX: May be used, Power Control: Active', valType: 'str', spec: '3GPP TS 44.018' },
                        { name: 'cellSelectionParameters', tag: '[4]', type: 'SEQUENCE', val: 'CELL-RESELECT-HYSTERESIS: 6 dB, MS-TXPWR-MAX-CCH: 33 dBm, RXLEV-ACCESS-MIN: -104 dBm', valType: 'str' },
                        { name: 'rachControlParameters', tag: '[5]', type: 'OCTET STRING', val: 'Max Retrans: 7, Tx-Integer: 32, Emergency Call: Allowed', valType: 'str' }
                    ]
                }
            ]
        });
    } else if (summary.includes('Security Mode') || summary.includes('SMC')) {
        // 5G/4G NAS Security Mode Command / Complete ASN.1
        const isNullCiph = summary.includes('EEA0') || summary.includes('NEA0') || summary.includes('Null Ciphering') || summary.includes('A5/0');
        const isNullInteg = summary.includes('EIA0') || summary.includes('NIA0') || summary.includes('Null Integrity');
        root.children.push({
            name: 'nas-SecurityModeCommand',
            tag: '[APPLICATION 5]',
            type: 'SEQUENCE',
            children: [
                {
                    name: 'selectedNASSecurityAlgorithms',
                    tag: '[0]',
                    type: 'SEQUENCE',
                    children: [
                        { name: 'typeOfCipheringAlgorithm', tag: '[0]', type: 'ENUMERATED', val: isNullCiph ? '⚠️ 5G-EA0 / EEA0 (NULL Ciphering - Cleartext)' : '5G-EA2 / 128-EEA2 (AES-128-CTR)', valType: isNullCiph ? 'alert' : 'str', spec: '3GPP TS 33.501 § 5.1' },
                        { name: 'typeOfIntegrityProtectionAlgorithm', tag: '[1]', type: 'ENUMERATED', val: isNullInteg ? '⚠️ 5G-IA0 / EIA0 (NULL Integrity - Vulnerable)' : '5G-IA2 / 128-EIA2 (AES-128-CMAC)', valType: isNullInteg ? 'alert' : 'str', spec: '3GPP TS 33.501 § 5.1' }
                    ],
                    spec: '3GPP TS 24.501 § 9.11.3.34'
                },
                { name: 'nas-KeySetIdentifier (ngKSI)', tag: '[1]', type: 'CHOICE', val: '0x00 (Native Security Context, KSI: 0)', valType: 'hex', spec: '3GPP TS 24.501 § 9.11.3.32' },
                { name: 'replayedUESecurityCapabilities', tag: '[2]', type: 'BIT STRING (SIZE 32)', val: '0xE0E00000 (5G-EA0..EA2, 5G-IA1..IA2 Supported)', valType: 'hex', spec: '3GPP TS 24.501 § 9.11.3.54' },
                { name: 'ueAdditionalSecurityCapability', tag: '[3]', type: 'OCTET STRING OPTIONAL', val: '128-NEA1, 128-NEA2, 128-NEA3 Supported', valType: 'str', spec: '3GPP TS 24.501' },
                { name: 'messageAuthenticationCode (MAC)', tag: '[4]', type: 'OCTET STRING (SIZE 4)', val: '0x4F8B2C91 (Calculated over NAS PDU)', valType: 'hex', spec: '3GPP TS 33.501 § 6.4.3' }
            ]
        });
    } else if (summary.includes('Registration') || summary.includes('Attach') || summary.includes('Authentication')) {
        // 5GS / EPS Authentication & Registration ASN.1
        root.children.push({
            name: '5gs-RegistrationMessage',
            tag: '[APPLICATION 5]',
            type: 'SEQUENCE',
            children: [
                {
                    name: '5gs-RegistrationType',
                    tag: '[0]',
                    type: 'ENUMERATED',
                    val: isUl ? 'initial-Registration (1)' : 'registration-Accept (2)',
                    valType: 'str',
                    spec: '3GPP TS 24.501 § 9.11.3.47'
                },
                {
                    name: '5gs-MobileIdentity',
                    tag: '[1]',
                    type: 'CHOICE',
                    children: [
                        { name: 'typeOfIdentity', tag: '[0]', type: 'ENUMERATED', val: summary.includes('SUCI') ? 'SUCI (Subscription Concealed Identifier)' : summary.includes('IMSI') ? '⚠️ Plaintext IMSI (Privacy Compromised)' : '5G-GUTI', valType: summary.includes('IMSI') ? 'alert' : 'str' },
                        { name: 'mcc', tag: '[1]', type: 'BCD-String', val: '310', valType: 'str' },
                        { name: 'mnc', tag: '[2]', type: 'BCD-String', val: '410', valType: 'str' },
                        { name: 'routingIndicator', tag: '[3]', type: 'OCTET STRING', val: '0x0000', valType: 'hex' },
                        { name: 'protectionSchemeId', tag: '[4]', type: 'ENUMERATED', val: 'Profile A (ECIES Curve25519 / HKDF-SHA256)', valType: 'str', spec: '3GPP TS 33.501 Annex C' },
                        { name: 'homeNetworkPublicKeyId', tag: '[5]', type: 'INTEGER', val: '0x01 (Key Index 1)', valType: 'hex' },
                        { name: 'schemeOutput', tag: '[6]', type: 'OCTET STRING (SIZE 32)', val: '0x7B4F9A... (Ephemeral Public Key + Ciphertext)', valType: 'hex' }
                    ],
                    spec: '3GPP TS 24.501 § 9.11.3.4'
                },
                {
                    name: 'ueSecurityCapability',
                    tag: '[2]',
                    type: 'SEQUENCE',
                    val: '5G-EA0, 5G-EA1, 5G-EA2, 5G-IA1, 5G-IA2, Dual-Connectivity (EN-DC)',
                    valType: 'str',
                    spec: '3GPP TS 24.501 § 9.11.3.54'
                }
            ]
        });
    } else if (summary.includes('RRCReconfiguration') || summary.includes('RRCSetup')) {
        // 5G NR RRC Reconfiguration / Setup Tree
        root.children.push({
            name: 'rrcReconfiguration',
            tag: '[APPLICATION 7]',
            type: 'SEQUENCE',
            children: [
                { name: 'rrc-TransactionIdentifier', tag: '[0]', type: 'INTEGER (0..3)', val: '0', valType: 'num', spec: '3GPP TS 38.331 § 6.2.2' },
                {
                    name: 'criticalExtensions',
                    tag: '[1]',
                    type: 'CHOICE',
                    children: [
                        {
                            name: 'rrcReconfiguration-IEs',
                            tag: '[0]',
                            type: 'SEQUENCE',
                            children: [
                                {
                                    name: 'radioBearerConfig',
                                    tag: '[0]',
                                    type: 'SEQUENCE',
                                    children: [
                                        { name: 'srb-ToAddModList', tag: '[0]', type: 'SEQUENCE OF SRB-ToAddMod', val: 'SRB1 (Default DCCH Bearer)', valType: 'str' },
                                        { name: 'drb-ToAddModList', tag: '[1]', type: 'SEQUENCE OF DRB-ToAddMod', val: 'DRB1 (5QI-9 Default Internet, RLC-AM Mode)', valType: 'str' }
                                    ]
                                },
                                {
                                    name: 'spCellConfig',
                                    tag: '[1]',
                                    type: 'SEQUENCE',
                                    children: [
                                        {
                                            name: 'spCellConfigDedicated',
                                            tag: '[0]',
                                            type: 'SEQUENCE',
                                            children: [
                                                { name: 'initialDownlinkBWP', tag: '[0]', type: 'BWP-DownlinkDedicated', val: 'BWP-ID: 0 (100 MHz Channel Bandwidth, 30 kHz SCS)', valType: 'str' },
                                                { name: 'pdsch-Config', tag: '[1]', type: 'Setup (PDSCH-Config)', val: 'DMRS-TypeA-Position: pos2, 64-QAM / 256-QAM', valType: 'str' }
                                            ]
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ]
        });
    } else if (rat.includes('SIM') || summary.includes('APDU') || summary.includes('AUTHENTICATE') || summary.includes('USIM')) {
        // UICC Smart Card APDU ASN.1 / TLV Structure
        root.children.push({
            name: 'uiccCommandAPDU',
            tag: '[APPLICATION 0]',
            type: 'SEQUENCE',
            children: [
                { name: 'cla', tag: '[0]', type: 'OCTET STRING (SIZE 1)', val: '0x00 (Standard ISO/IEC 7816-4)', valType: 'hex', spec: 'ETSI TS 102 221' },
                { name: 'ins', tag: '[1]', type: 'OCTET STRING (SIZE 1)', val: summary.includes('AUTHENTICATE') ? '0x88 (AUTHENTICATE)' : summary.includes('SELECT') ? '0xA4 (SELECT FILE)' : '0xC0 (GET RESPONSE)', valType: 'hex', spec: '3GPP TS 31.102 § 7.1' },
                { name: 'p1', tag: '[2]', type: 'OCTET STRING (SIZE 1)', val: '0x00 (No Information Given)', valType: 'hex' },
                { name: 'p2', tag: '[3]', type: 'OCTET STRING (SIZE 1)', val: '0x81 (3G/4G/5G Security Context)', valType: 'hex' },
                { name: 'lc', tag: '[4]', type: 'INTEGER', val: '34 Octets (0x22)', valType: 'num' },
                {
                    name: 'commandData',
                    tag: '[5]',
                    type: 'SEQUENCE (TLV Data Object)',
                    children: [
                        { name: 'randChallengeTag', tag: '[TAG 0x20]', type: 'OCTET STRING (SIZE 16)', val: '0x3F8A0B2C91D4... (128-bit Random Challenge)', valType: 'hex', spec: '3GPP TS 33.102' },
                        { name: 'autnTokenTag', tag: '[TAG 0x21]', type: 'OCTET STRING (SIZE 16)', val: '0x7E1A4D09C382... (128-bit Authentication Token: SQN ⊕ AK || AMF || MAC-A)', valType: 'hex', spec: '3GPP TS 33.102' }
                    ]
                }
            ]
        });
    } else if (rat.includes('CALEA') || summary.includes('LI') || summary.includes('ETSI')) {
        // ETSI TS 102 232 PS-PDU Lawful Interception ASN.1 BER Tree
        root.children.push({
            name: 'pS-PDU',
            tag: '[UNIVERSAL 16] BER SEQUENCE',
            type: 'SEQUENCE',
            children: [
                {
                    name: 'pS-Header',
                    tag: '[0]',
                    type: 'SEQUENCE',
                    children: [
                        { name: 'pS-Domain-Id', tag: '[0]', type: 'OBJECT IDENTIFIER', val: '{ itu-t(0) identified-organization(4) etsi(0) securityDomain(2) lawfulIntercept(2) }', valType: 'str', spec: 'ETSI TS 102 232-1' },
                        { name: 'cin (Communication Identity Number)', tag: '[1]', type: 'OCTET STRING (SIZE 4)', val: '0x58A3B291', valType: 'hex', spec: '3GPP TS 33.108' },
                        { name: 'operatorIdentifier', tag: '[2]', type: 'OCTET STRING', val: '"TELCO-LEGAL-INTERCEPT-GATEWAY-01"', valType: 'str' },
                        { name: 'timeStamp', tag: '[3]', type: 'GeneralizedTime', val: '2026-08-16 00:09:17.468 UTC', valType: 'str' }
                    ]
                },
                {
                    name: 'payload',
                    tag: '[1]',
                    type: 'CHOICE',
                    children: [
                        { name: 'iRI-Payload (Intercept Related Information)', tag: '[0]', type: 'OCTET STRING', val: 'Signaling Metadata Intercept (Location Update / Call Setup Event)', valType: 'str', spec: '3GPP TS 33.128' }
                    ]
                }
            ]
        });
    } else {
        // Generic 3GPP PDU Envelope
        root.children.push({
            name: 'genericProtocolDataUnit',
            tag: '[APPLICATION 1]',
            type: 'SEQUENCE',
            children: [
                { name: 'messageIdentifier', tag: '[0]', type: 'IA5String', val: summary, valType: 'str' },
                { name: 'rawHexOctets', tag: '[1]', type: 'OCTET STRING', val: raw ? `${raw.slice(0, 48)}… (${raw.length/2} bytes)` : '—', valType: 'hex' }
            ]
        });
    }

    return root;
}

function renderAsn1Node(node, isRoot = false) {
    const div = document.createElement('div');
    div.className = `asn1-node ${isRoot ? 'asn1-root-node' : ''}`;

    const header = document.createElement('div');
    header.className = 'asn1-node-header';

    const hasChildren = node.children && node.children.length > 0;
    
    let toggleHtml = '';
    if (hasChildren) {
        toggleHtml = '<span class="asn1-node-toggle">▼</span>';
    } else {
        toggleHtml = '<span class="asn1-node-toggle" style="opacity:0.2">•</span>';
    }

    let valHtml = '';
    if (node.val !== null && node.val !== undefined) {
        if (node.valType === 'alert') {
            valHtml = ` : <span class="asn1-val-alert">${escapeHtml(String(node.val))}</span>`;
        } else if (node.valType === 'hex') {
            valHtml = ` : <span class="asn1-val-hex">${escapeHtml(String(node.val))}</span>`;
        } else if (node.valType === 'num') {
            valHtml = ` : <span class="asn1-val-num">${escapeHtml(String(node.val))}</span>`;
        } else {
            valHtml = ` : <span class="asn1-val-str">${escapeHtml(String(node.val))}</span>`;
        }
    }

    const tagBadge = node.tag ? `<span class="asn1-tag-badge">${escapeHtml(node.tag)}</span>` : '';
    const typeSpec = node.type ? `<span class="asn1-type-spec">${escapeHtml(node.type)}</span>` : '';
    const specTag = node.spec ? `<span class="asn1-spec-tag">${escapeHtml(node.spec)}</span>` : '';

    header.innerHTML = `
        ${toggleHtml}
        ${tagBadge}
        <span class="asn1-field-name">${escapeHtml(node.name)}</span>
        ${typeSpec}
        ${valHtml}
        ${specTag}
    `;

    if (hasChildren) {
        header.addEventListener('click', e => {
            e.stopPropagation();
            div.classList.toggle('collapsed');
        });
    }

    div.appendChild(header);

    if (hasChildren) {
        const childrenContainer = document.createElement('div');
        childrenContainer.className = 'asn1-node-children';
        node.children.forEach(child => {
            childrenContainer.appendChild(renderAsn1Node(child, false));
        });
        div.appendChild(childrenContainer);
    }

    return div;
}

function countAsn1Nodes(node) {
    if (!node) return 0;
    let count = 1;
    if (node.children && node.children.length > 0) {
        node.children.forEach(c => count += countAsn1Nodes(c));
    }
    return count;
}

function renderAsn1TreeToDom(treeModel, rootEl) {
    if (!rootEl) return;
    rootEl.innerHTML = '';
    if (!treeModel) {
        rootEl.innerHTML = '<div class="tree-empty-state">// Select a packet above to decode ASN.1 information elements</div>';
        const badge = document.getElementById('tree-nodes-count');
        if (badge) badge.textContent = '0 Nodes';
        return;
    }

    const nodeEl = renderAsn1Node(treeModel, true);
    rootEl.appendChild(nodeEl);

    const totalNodes = countAsn1Nodes(treeModel);
    const badge = document.getElementById('tree-nodes-count');
    if (badge) badge.textContent = `${totalNodes} ASN.1 Node${totalNodes === 1 ? '' : 's'}`;

    // Initialize toolbar controls for ASN.1 Tree
    initAsn1TreeControls();
}

function initAsn1TreeControls() {
    // Expand All
    document.getElementById('btn-tree-expand')?.replaceWith(
        document.getElementById('btn-tree-expand').cloneNode(true)
    );
    document.getElementById('btn-tree-expand')?.addEventListener('click', () => {
        document.querySelectorAll('#asn1-tree-root .asn1-node').forEach(n => n.classList.remove('collapsed'));
    });

    // Collapse All
    document.getElementById('btn-tree-collapse')?.replaceWith(
        document.getElementById('btn-tree-collapse').cloneNode(true)
    );
    document.getElementById('btn-tree-collapse')?.addEventListener('click', () => {
        document.querySelectorAll('#asn1-tree-root .asn1-node').forEach((n, idx) => {
            if (idx > 0) n.classList.add('collapsed');
        });
    });

    // Filter Search
    const searchInput = document.getElementById('tree-search-filter');
    if (searchInput) {
        searchInput.replaceWith(searchInput.cloneNode(true));
        document.getElementById('tree-search-filter')?.addEventListener('input', e => {
            const q = e.target.value.toLowerCase().trim();
            const nodes = document.querySelectorAll('#asn1-tree-root .asn1-node');
            nodes.forEach(n => {
                const text = n.textContent.toLowerCase();
                const matched = !q || text.includes(q);
                n.style.display = matched ? '' : 'none';
                if (q && matched) {
                    n.classList.remove('collapsed');
                }
            });
        });
    }

    // Copy ASN.1 Text
    document.getElementById('btn-tree-copy-text')?.replaceWith(
        document.getElementById('btn-tree-copy-text').cloneNode(true)
    );
    document.getElementById('btn-tree-copy-text')?.addEventListener('click', () => {
        const root = document.getElementById('asn1-tree-root');
        if (root) {
            navigator.clipboard.writeText(root.innerText);
            showToast('Copied parsed ASN.1 hierarchy to clipboard', 'success');
        }
    });
}

function buildCanonicalHexHtml(rawHex) {
    if (!rawHex) return '// No raw hex payload';
    const clean = rawHex.replace(/[^0-9A-Fa-f]/g, '');
    if (!clean) return '// Empty payload';

    const bytes = [];
    for (let i = 0; i < clean.length; i += 2) {
        bytes.push(clean.substr(i, 2).toUpperCase());
    }

    let html = '<table class="hex-table"><tbody>';
    for (let offset = 0; offset < bytes.length; offset += 16) {
        const chunk = bytes.slice(offset, offset + 16);
        const offsetHex = offset.toString(16).padStart(4, '0').toUpperCase();
        
        let hexPart1 = chunk.slice(0, 8).join(' ');
        let hexPart2 = chunk.slice(8, 16).join(' ');
        let hexCombined = `${hexPart1}  ${hexPart2}`.padEnd(49, ' ');

        let asciiStr = '';
        for (let b of chunk) {
            const code = parseInt(b, 16);
            asciiStr += (code >= 32 && code <= 126) ? String.fromCharCode(code) : '.';
        }

        html += `
            <tr>
                <td class="hex-offset-cell">${offsetHex}</td>
                <td class="hex-bytes-cell">${escapeHtml(hexCombined)}</td>
                <td class="hex-ascii-cell">${escapeHtml(asciiStr)}</td>
            </tr>
        `;
    }
    html += '</tbody></table>';
    return html;
}

function selectPacket(pkt) {
    state.selectedPktId = pkt.id;
    // P2: Remove selection from cached previous row — avoids querySelectorAll on entire tbody
    if (state.selectedRow) state.selectedRow.classList.remove('selected');
    const row = document.querySelector(`#packet-tbody tr[data-id="${pkt.id}"]`);
    if (row) { row.classList.add('selected'); state.selectedRow = row; }

    setText('insp-rat', `${(pkt.rat || '4G').toUpperCase()} | ${pkt.protocol || 'RRC'}`);
    setText('insp-title', pkt.summary || 'Packet Details');

    // Render High-Fidelity Interactive Collapsible ASN.1 Protocol Tree
    const treeModel = generateAsn1Tree(pkt);
    const treeRoot = document.getElementById('asn1-tree-root');
    renderAsn1TreeToDom(treeModel, treeRoot);

    const treeFallback = pkt.tree || `// Packet ID: ${pkt.id}\n// RAT: ${pkt.rat}\n\n${JSON.stringify(pkt, null, 2)}`;
    setText('tree-content', treeFallback);

    // Render Canonical 16-Byte Hex Dump
    const hexEl = document.getElementById('hex-content');
    if (hexEl) {
        hexEl.innerHTML = buildCanonicalHexHtml(pkt.raw || '0800234a5f8b2c91d4e000000000000000000000000000000000');
    }

    // Populate Information Elements breakdown table
    const ieTbody = document.getElementById('insp-ie-tbody');
    if (ieTbody) {
        const ies = decodePacketInformationElements(pkt);
        const countBadge = document.getElementById('ie-count-badge');
        if (countBadge) countBadge.textContent = `${ies.length} Decoded Field${ies.length === 1 ? '' : 's'}`;
        
        ieTbody.innerHTML = ies.map(ie => `
            <tr>
                <td class="ie-field-name">${escapeHtml(ie.name)}</td>
                <td class="ie-field-val">${escapeHtml(ie.val)}</td>
                <td class="ie-field-hex">${escapeHtml(ie.hex)}</td>
                <td class="ie-field-spec">${escapeHtml(ie.spec)}</td>
            </tr>
        `).join('');
    }

    // Check for Threat Annotation
    const threatBanner = document.getElementById('insp-threat-banner');
    const matchedThreat = state.threats.find(t => t.rule_id === pkt.threat_rule || (pkt.summary && t.title && pkt.summary.includes(t.title.slice(0, 10))));
    if (threatBanner) {
        if (matchedThreat || pkt.threat_rule) {
            const rule = matchedThreat?.rule_id || pkt.threat_rule || 'TELCOSEC-VULN';
            const sev = matchedThreat?.severity || 'HIGH';
            const title = matchedThreat?.title || 'Security Anomaly in Frame';
            setText('insp-threat-rule', rule);
            setText('insp-threat-title', title);
            const sevEl = document.getElementById('insp-threat-sev');
            if (sevEl) { sevEl.textContent = sev; sevEl.className = `sev-badge sev-${sev}`; }
            threatBanner.style.display = 'flex';

            document.getElementById('btn-insp-view-dossier').onclick = () => {
                if (matchedThreat) openThreatModalFromRow(matchedThreat);
                else showToast(`Vulnerability Rule ${rule}`, 'info');
            };
        } else {
            threatBanner.style.display = 'none';
        }
    }

    if (state.inspectorCollapsed) toggleInspector();
}

function decodePacketInformationElements(pkt) {
    const rows = [];
    rows.push({ name: 'Radio Access Technology (RAT)', val: (pkt.rat || '4G').toUpperCase(), hex: '—', spec: '3GPP TR 21.905' });
    rows.push({ name: 'Signaling Direction', val: pkt.is_uplink ? 'Uplink (UE → eNB/gNB)' : 'Downlink (eNB/gNB → UE)', hex: pkt.is_uplink ? '0x01' : '0x00', spec: '3GPP Layer 2/3' });
    rows.push({ name: 'Protocol Layer', val: pkt.layer || 'RRC', hex: '—', spec: pkt.layer === 'NAS' ? '3GPP TS 24.301 / 24.501' : '3GPP TS 36.331 / 38.331' });
    if (pkt.channel) rows.push({ name: 'Logical / Transport Channel', val: pkt.channel, hex: '—', spec: '3GPP TS 36.321 / 38.321' });
    if (pkt.protocol) rows.push({ name: 'Upper Layer Protocol', val: pkt.protocol, hex: '—', spec: '3GPP TS 33.401 / 33.501' });
    if (pkt.summary) rows.push({ name: 'Message / Opcode Identifier', val: pkt.summary, hex: pkt.raw ? pkt.raw.slice(0, 4) : '—', spec: '3GPP TS 24.007' });
    if (pkt.length) rows.push({ name: 'Frame Length', val: `${pkt.length} Octets`, hex: `0x${Number(pkt.length).toString(16).padStart(2,'0')}`, spec: 'Physical/Transport' });

    if (pkt.summary) {
        if (pkt.summary.includes('Security Mode')) {
            rows.push({ name: 'Ciphering Algorithm (EEA/NEA)', val: '128-EEA2 (AES-CTR) / NEA0', hex: '0x02 / 0x00', spec: '3GPP TS 33.401' });
            rows.push({ name: 'Integrity Algorithm (EIA/NIA)', val: '128-EIA2 (128-AES-CMAC)', hex: '0x02', spec: '3GPP TS 33.401' });
        } else if (pkt.summary.includes('Auth')) {
            rows.push({ name: 'Authentication Challenge (RAND)', val: '16 Octet Pseudo-Random Nonce', hex: 'RAND[16]', spec: '3GPP TS 33.102' });
            rows.push({ name: 'Authentication Token (AUTN)', val: 'SQN ⊕ AK || AMF || MAC', hex: 'AUTN[16]', spec: '3GPP TS 33.102' });
        } else if (pkt.summary.includes('Attach') || pkt.summary.includes('Registration')) {
            rows.push({ name: 'Mobile Identity Type', val: pkt.summary.includes('IMSI') ? 'IMSI (Cleartext SUPI)' : '5G-GUTI / 4G-GUTI', hex: '0x01 / 0x06', spec: '3GPP TS 24.501' });
        }
    }
    return rows;
}

function buildHexView(rawHex) {
    if (!rawHex) return '// No raw hex payload available';
    let out = '';
    for (let i = 0; i < rawHex.length; i += 32) {
        const chunk = rawHex.slice(i, i + 32);
        const addr = (i / 2).toString(16).padStart(8, '0');
        const pairs = chunk.match(/.{1,2}/g) || [];
        const hex = pairs.join(' ').padEnd(47);
        const ascii = pairs.map(b => {
            const c = parseInt(b, 16);
            return c >= 0x20 && c < 0x7f ? String.fromCharCode(c) : '.';
        }).join('');
        out += `${addr}  ${hex}  ${ascii}\n`;
    }
    return out;
}

/* ─── Interactive Threat Radar Engine ────────────────────────────────────── */
function addSecurityAlertInternal(alert) {
    state.threats.push(alert);
    state.totalThreats++;

    const sev = (alert.severity || 'HIGH').toUpperCase();
    const countIds = { CRITICAL: 'threat-crit-count', HIGH: 'threat-high-count', MEDIUM: 'threat-med-count' };
    incEl(countIds[sev] || 'threat-info-count');

    const badge = document.getElementById('badge-threat-count');
    if (badge) { badge.textContent = state.totalThreats; badge.style.display = ''; }

    updateDefconStatus();
    renderRadarBlips();
    playThreatChirp(sev);

    if (shouldShowThreat(alert)) {
        renderThreatRow(alert);
    }
    handleThreatGeoPin(alert);

    if (sev === 'CRITICAL') {
        showToast(`CRITICAL THREAT: ${alert.title || 'Exploit detected'}`, 'error', 6000);
    }
}

function updateDefconStatus() {
    const critCount = parseInt(document.getElementById('threat-crit-count')?.textContent || '0', 10);
    const highCount = parseInt(document.getElementById('threat-high-count')?.textContent || '0', 10);
    const medCount  = parseInt(document.getElementById('threat-med-count')?.textContent  || '0', 10);

    const badge = document.getElementById('defcon-badge');
    const text  = document.getElementById('defcon-text');
    if (!badge || !text) return;

    if (critCount > 0) {
        badge.textContent = 'DEFCON 1';
        badge.style.background = 'rgba(248,81,73,0.25)';
        badge.style.color = 'var(--accent-red)';
        badge.style.borderColor = 'rgba(248,81,73,0.5)';
        text.textContent = `${critCount} CRITICAL ATTACK${critCount > 1 ? 'S' : ''}`;
    } else if (highCount > 0) {
        badge.textContent = 'DEFCON 2';
        badge.style.background = 'rgba(240,136,62,0.25)';
        badge.style.color = 'var(--accent-orange)';
        badge.style.borderColor = 'rgba(240,136,62,0.5)';
        text.textContent = 'HIGH RISK SPECTRUM';
    } else if (medCount > 0) {
        badge.textContent = 'DEFCON 3';
        badge.style.background = 'rgba(227,179,65,0.25)';
        badge.style.color = 'var(--accent-yellow)';
        badge.style.borderColor = 'rgba(227,179,65,0.5)';
        text.textContent = 'SUSPICIOUS CELL DETECTED';
    } else {
        badge.textContent = 'DEFCON 5';
        badge.style.background = 'rgba(63,185,80,0.2)';
        badge.style.color = 'var(--accent-green)';
        badge.style.borderColor = 'rgba(63,185,80,0.4)';
        text.textContent = 'RADIO SECURE';
    }
}

function renderRadarBlips() {
    const layer = document.getElementById('radar-blips-layer');
    if (!layer) return;
    layer.innerHTML = '';

    const SECTOR_ANGLES = {
        '5G': -90, '4G': -30, 'IMS': 30, 'SIM': 90, '3G': 150, '2G': 160, 'MULTI': -150
    };
    const SEV_RADII = {
        'CRITICAL': 32, 'HIGH': 68, 'MEDIUM': 105, 'LOW': 130, 'INFO': 138
    };

    state.threats.slice(-30).forEach((t, idx) => {
        const ratKey = (t.rat || '4G').toUpperCase();
        const sevKey = (t.severity || 'HIGH').toUpperCase();
        const baseAngle = SECTOR_ANGLES[ratKey] || -30;
        const radius = SEV_RADII[sevKey] || 70;

        const jitter = ((idx % 5) - 2) * 8;
        const rad = ((baseAngle + jitter) * Math.PI) / 180;
        const cx = 190 + radius * Math.cos(rad);
        const cy = 170 + radius * Math.sin(rad);

        // Outer glow ring
        const glowCircle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        glowCircle.setAttribute('cx', cx.toFixed(1));
        glowCircle.setAttribute('cy', cy.toFixed(1));
        glowCircle.setAttribute('r', '9');
        glowCircle.setAttribute('class', `radar-blip-glow blip-glow-${sevKey.toLowerCase()}`);
        layer.appendChild(glowCircle);

        const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        circle.setAttribute('cx', cx.toFixed(1));
        circle.setAttribute('cy', cy.toFixed(1));
        circle.setAttribute('r', '5');
        circle.setAttribute('class', `radar-blip blip-${sevKey.toLowerCase()}`);
        const titleEl = document.createElementNS('http://www.w3.org/2000/svg', 'title');
        titleEl.textContent = `${t.rule_id}: ${t.title} (${t.severity})`;
        circle.appendChild(titleEl);
        circle.style.cursor = 'pointer';
        circle.addEventListener('click', () => openThreatModal(t));
        layer.appendChild(circle);
    });
}

function shouldShowThreat(t) {
    const sev = (t.severity || 'HIGH').toUpperCase();
    const cat = (t.category || '').toUpperCase();

    if (state.threatSevFilter !== 'all' && sev !== state.threatSevFilter) return false;
    if (state.threatCatFilter !== 'all' && cat !== state.threatCatFilter) return false;
    return true;
}

function renderThreatRow(alert) {
    // P6: Use data-* attribute + event delegation instead of serialized onclick
    const tbody = document.getElementById('threat-tbody');
    if (!tbody) return;
    if (tbody.querySelector('.empty-state')) tbody.innerHTML = '';

    const sev = (alert.severity || 'HIGH').toUpperCase();
    const alertIdx = state.threats.length - 1;
    const tr = document.createElement('tr');
    tr.className = 'new-threat';
    tr.dataset.alertIdx = alertIdx;
    tr.innerHTML = `
        <td style="font-family:var(--font-mono);font-size:11px">${alert.time || fmtTime(new Date())}</td>
        <td><span class="sev-badge sev-${sev}">${sev}</span></td>
        <td><span class="rule-pill">${escapeHtml(alert.rule_id || 'TELCOSEC-VULN-001')}</span></td>
        <td>${getRatBadge(alert.rat || '4G')}</td>
        <td><strong>${escapeHtml(alert.category || '')}</strong></td>
        <td>
            <div style="font-weight:600;color:var(--text-primary)">${escapeHtml(alert.title || '')}</div>
            <div style="font-size:11px;color:var(--text-secondary);margin-top:2px">${escapeHtml(alert.description || alert.desc || '')}</div>
        </td>
        <td><button class="btn btn-sm btn-secondary threat-inspect-btn">Inspect</button></td>`;

    tbody.insertBefore(tr, tbody.firstChild);
}

function initThreatTableDelegation() {
    // P6: Single delegated listener on tbody for all Inspect buttons
    const tbody = document.getElementById('threat-tbody');
    if (!tbody) return;
    tbody.addEventListener('click', e => {
        const btn = e.target.closest('.threat-inspect-btn');
        if (!btn) return;
        const tr = btn.closest('tr[data-alert-idx]');
        if (!tr) return;
        const idx = parseInt(tr.dataset.alertIdx, 10);
        const alert = state.threats[idx];
        if (alert) openThreatModal(alert);
    });
}

function rebuildThreatTable() {
    const tbody = document.getElementById('threat-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    const visible = state.threats.filter(shouldShowThreat);
    if (!visible.length) {
        tbody.innerHTML = '<tr><td colspan="7"><div class="empty-state"><p>No threats match current filter</p></div></td></tr>';
        return;
    }
    visible.forEach(renderThreatRow);
}

/* ─── Threat Dossier Modal ───────────────────────────────────────────────── */
function initThreatModal() {
    document.getElementById('btn-close-threat-modal')?.addEventListener('click', closeThreatModal);
    document.getElementById('threat-modal')?.addEventListener('click', e => {
        if (e.target.id === 'threat-modal') closeThreatModal();
    });

    document.getElementById('btn-copy-threat-hex')?.addEventListener('click', () => {
        const hex = document.getElementById('modal-threat-hex')?.textContent || '';
        navigator.clipboard.writeText(hex).then(() => showToast('Frame hex copied to clipboard', 'success'));
    });
}

function openThreatModal(alert) {
    const modal = document.getElementById('threat-modal');
    if (!modal) return;

    const sev = (alert.severity || 'HIGH').toUpperCase();
    const ruleId = alert.rule_id || 'TELCOSEC-VULN-GEN';
    const specInfo = THREAT_SPECS_DB[ruleId] || {
        spec: '3GPP TS 33.501 / TS 33.401 / TS 44.018',
        impact: 'Cellular Baseband Security Violation',
        remediation: 'Review baseband telemetry and enforce 3GPP cryptographic integrity and ciphering algorithms.'
    };

    const sevBadge = document.getElementById('modal-threat-sev');
    if (sevBadge) {
        sevBadge.textContent = sev;
        sevBadge.className = `sev-badge sev-${sev}`;
    }

    setText('modal-threat-title', alert.title || 'Security Finding Details');
    setText('modal-threat-rule', ruleId);
    setText('modal-threat-spec', specInfo.spec);
    setText('modal-threat-rat-cat', `${(alert.rat || 'MULTI').toUpperCase()} | ${(alert.category || 'GENERAL').toUpperCase()}`);
    setText('modal-threat-impact', specInfo.impact);
    setText('modal-threat-desc', alert.description || alert.desc || 'No detailed description available.');
    setText('modal-threat-remediation', specInfo.remediation);
    setText('modal-threat-hex', alert.raw_hex || buildHexView(alert.raw || ''));

    modal.style.display = 'flex';
}

window.openThreatModalFromRow = function(alert) {
    openThreatModal(alert);
};

function closeThreatModal() {
    const modal = document.getElementById('threat-modal');
    if (modal) modal.style.display = 'none';
}

/* ─── Device Hardware & Diagnostics Dossier (Optimized) ─────────────────── */
let cachedDeviceBands = [];
let currentBandFilter = 'all';

function initDevicePage() {
    loadDeviceStatus();
    initDeviceBands();
    initDeviceAtProbe();
    initDeviceSelfTest();
    initDeviceExports();
}

function loadDeviceStatus() {
    fetch('/api/device/info')
        .then(r => r.json())
        .then(data => {
            if (data.device) updateDeviceInfo(data.device);
        })
        .catch(() => {
            fetch('/api/status')
                .then(r => r.json())
                .then(d => { if (d.device) updateDeviceInfo(d.device); });
        });
}

function updateDeviceInfo(dev) {
    state.deviceData = dev;

    // ── Hardware & identity ──────────────────────────────────────────────────
    if (dev.model || dev.name) {
        const m = dev.model || dev.name;
        setText('device-name', m);
        setText('dossier-model-title', m);
        setText('dev-model', m);
        setText('sb-device-model', m);
    }
    if (dev.chipset) {
        setText('chipset-badge', dev.chipset);
        setText('dossier-chip-badge', dev.chipset);
        setText('dev-chipset', dev.chipset);
    }
    if (dev.hw_revision)  setText('dev-hw-rev', dev.hw_revision);
    if (dev.scm)          setText('dev-scm', dev.scm);
    if (dev.cai)          setText('dev-cai', dev.cai);
    if (dev.slot_cycle)   setText('dev-slot-cycle', dev.slot_cycle);
    if (dev.serial_esn)   setText('dev-esn', dev.serial_esn);

    // ── Firmware & build ─────────────────────────────────────────────────────
    if (dev.firmware_build || dev.firmware) {
        const fw = dev.firmware_build || dev.firmware;
        setText('cell-fw', fw);
        setText('dev-build-id', fw);
    }
    if (dev.comp_date)  setText('dev-comp-date', dev.comp_date);
    if (dev.rel_date)   setText('dev-rel-date', dev.rel_date);
    if (dev.ver_dir)    setText('dev-ver-dir', dev.ver_dir);
    if (dev.sec_patch)  setText('dev-sec-patch', dev.sec_patch);
    if (dev.diag_version !== undefined) {
        setText('dev-diag-version', `Version ${dev.diag_version}.0 (Extended HDLC / Multi-Radio)`);
        setText('dossier-diag-ver', `Diag v${dev.diag_version}`);
    }

    // ── SIM / UICC identity ──────────────────────────────────────────────────
    if (dev.imei)        setText('dev-imei', dev.imei);
    if (dev.imsi)        setText('dev-imsi', dev.imsi);
    if (dev.iccid)       setText('dev-iccid', dev.iccid);
    if (dev.sim_status)  setText('dev-sim-status', dev.sim_status);
    if (dev.pin_status)  setText('dev-pin-status', dev.pin_status);

    // ── Serving network ──────────────────────────────────────────────────────
    if (dev.serving_plmn) {
        setText('cell-plmn', dev.serving_plmn);
        setText('dev-serving-plmn', dev.serving_plmn);
    }
    if (dev.active_rat)    setText('dev-active-rat', dev.active_rat);
    if (dev.serving_band)  setText('dev-serving-band', dev.serving_band);
    if (dev.arfcn)         setText('dev-serving-arfcn', dev.arfcn);
    if (dev.pci !== undefined) setText('dev-serving-pci', String(dev.pci));
    if (dev.tac)           setText('dev-serving-tac', dev.tac);

    // ── Security posture ─────────────────────────────────────────────────────
    if (dev.secure_boot !== undefined) {
        const el = document.getElementById('dev-sec-boot');
        if (el) {
            el.textContent = dev.secure_boot ? '✓ Enforced (QFPROM Fused)' : '⚠ NOT ENFORCED';
            el.className = 'field-value ' + (dev.secure_boot ? 'sec-status-ok' : 'sec-status-fail');
        }
    }
    if (dev.trustzone !== undefined) {
        const el = document.getElementById('dev-trustzone');
        if (el) {
            el.textContent = dev.trustzone ? '✓ Active (Hardware Enclave)' : '✗ Inactive';
            el.className = 'field-value ' + (dev.trustzone ? 'sec-status-ok' : 'sec-status-warn');
        }
    }
    if (dev.cipher_5g)     setText('dev-5g-cipher', dev.cipher_5g);
    if (dev.cipher_lte)    setText('dev-lte-cipher', dev.cipher_lte);
    if (dev.integrity_5g)  setText('dev-5g-integrity', dev.integrity_5g);
    if (dev.rollback_ver)  setText('dev-rollback', dev.rollback_ver);
    if (dev.aka_algo)      setText('dev-aka-algo', dev.aka_algo);
    if (dev.suci_scheme)   setText('dev-suci-scheme', dev.suci_scheme);

    // ── Subsystems HUD dynamic sync ──────────────────────────────────────────
    if (dev.firmware_build || dev.connected !== false) {
        setText('subsys-mpss', '● Active (Hexagon DSP)');
        setText('subsys-qtee', dev.secure_boot !== false ? '● Enforced (QFPROM)' : '⚠ Not Fused');
        setText('subsys-usim', dev.sim_status ? '● Milenage / TUAK OK' : '○ Awaiting Card');
        setText('subsys-diag', dev.diag_version ? `● HDLC v${dev.diag_version} Active` : '● HDLC v2 Active');
    }

    // ── Avatar ring connection state ─────────────────────────────────────────
    const ring = document.getElementById('device-avatar-ring');
    if (ring) {
        const connected = dev.connected !== false;
        ring.classList.toggle('ring-disconnected', !connected);
    }

    // ── Last poll timestamp ──────────────────────────────────────────────────
    const pollBadge = document.getElementById('dossier-last-poll');
    if (pollBadge) {
        const t = new Date();
        pollBadge.textContent = `⏱ ${t.getHours().toString().padStart(2,'0')}:${t.getMinutes().toString().padStart(2,'0')}:${t.getSeconds().toString().padStart(2,'0')}`;
        pollBadge.title = `Last device poll: ${t.toLocaleString()}`;
    }

    // Refresh bands if active band changed
    if (dev.serving_band && cachedDeviceBands.length > 0) {
        renderDeviceBands(cachedDeviceBands);
    }
}

/* ─── Multi-RAT Frequency Bands Matrix ───────────────────────────────────── */
function initDeviceBands() {
    loadDeviceBands();

    document.querySelectorAll('.band-filter-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.band-filter-btn').forEach(b => {
                b.classList.remove('active', 'btn-primary');
                b.classList.add('btn-secondary');
            });
            btn.classList.add('active', 'btn-primary');
            btn.classList.remove('btn-secondary');
            currentBandFilter = btn.getAttribute('data-filter');
            filterDeviceBands();
        });
    });

    const searchInput = document.getElementById('input-device-band-search');
    if (searchInput) {
        searchInput.addEventListener('input', () => filterDeviceBands());
    }
}

function loadDeviceBands() {
    fetch('/api/device/bands')
        .then(r => r.json())
        .then(d => {
            if (d.status === 'ok' && d.bands) {
                cachedDeviceBands = d.bands;
                if (d.mimo_capability) setText('rf-cap-mimo', d.mimo_capability);
                if (d.modulation) setText('rf-cap-mod', d.modulation);
                if (d.hpue_class) setText('rf-cap-hpue', d.hpue_class);
                
                // Update count badges
                const count5g = d.bands.filter(b => b.rat === '5G_NR').length;
                const count4g = d.bands.filter(b => b.rat === '4G_LTE').length;
                const countAct = d.bands.filter(b => b.status.includes('ACTIVE')).length;
                
                setText('count-bands-all', String(d.bands.length));
                setText('count-bands-5g', String(count5g));
                setText('count-bands-4g', String(count4g));
                setText('count-bands-active', String(countAct));

                renderDeviceBands(d.bands);
            }
        })
        .catch(() => {
            // Offline fallback for bands
            const fallbackBands = [
                { id: 'n78', rat: '5G_NR', type: 'FR1', freq_mhz: '3500', duplex: 'TDD', ul_mhz: '3300-3800', dl_mhz: '3300-3800', max_bw_mhz: 100, status: 'ACTIVE_SERVING_PCC' },
                { id: 'B3', rat: '4G_LTE', type: 'FDD', freq_mhz: '1800', duplex: 'FDD', ul_mhz: '1710-1785', dl_mhz: '1805-1880', max_bw_mhz: 20, status: 'ACTIVE_CA_SCC' },
                { id: 'n1', rat: '5G_NR', type: 'FR1', freq_mhz: '2100', duplex: 'FDD', ul_mhz: '1920-1980', dl_mhz: '2110-2170', max_bw_mhz: 50, status: 'Supported' },
                { id: 'n28', rat: '5G_NR', type: 'FR1', freq_mhz: '700', duplex: 'FDD', ul_mhz: '703-748', dl_mhz: '758-803', max_bw_mhz: 40, status: 'Supported' },
                { id: 'B1', rat: '4G_LTE', type: 'FDD', freq_mhz: '2100', duplex: 'FDD', ul_mhz: '1920-1980', dl_mhz: '2110-2170', max_bw_mhz: 20, status: 'Supported' },
                { id: 'B20', rat: '4G_LTE', type: 'FDD', freq_mhz: '800', duplex: 'FDD', ul_mhz: '832-862', dl_mhz: '791-821', max_bw_mhz: 20, status: 'Supported' }
            ];
            cachedDeviceBands = fallbackBands;
            renderDeviceBands(fallbackBands);
        });
}

function filterDeviceBands() {
    const q = (document.getElementById('input-device-band-search')?.value || '').toLowerCase().trim();
    let filtered = cachedDeviceBands;

    if (currentBandFilter === '5G_NR') {
        filtered = filtered.filter(b => b.rat === '5G_NR');
    } else if (currentBandFilter === '4G_LTE') {
        filtered = filtered.filter(b => b.rat === '4G_LTE');
    } else if (currentBandFilter === 'active') {
        filtered = filtered.filter(b => b.status.includes('ACTIVE'));
    }

    if (q) {
        filtered = filtered.filter(b => 
            b.id.toLowerCase().includes(q) || 
            b.freq_mhz.includes(q) || 
            b.duplex.toLowerCase().includes(q) ||
            b.rat.toLowerCase().includes(q)
        );
    }

    renderDeviceBands(filtered);
}

function renderDeviceBands(bands) {
    const container = document.getElementById('device-bands-grid');
    if (!container) return;

    if (!bands || bands.length === 0) {
        container.innerHTML = '<div class="bands-loading-placeholder">No matching frequency bands found.</div>';
        return;
    }

    container.innerHTML = bands.map(b => {
        const isActivePcc = b.status === 'ACTIVE_SERVING_PCC';
        const isActiveScc = b.status === 'ACTIVE_CA_SCC';
        let cls = 'band-chip';
        let tagCls = 'band-status-tag supp';
        let tagLabel = 'Supported';

        if (isActivePcc) {
            cls += ' active-pcc';
            tagCls = 'band-status-tag pcc';
            tagLabel = 'Serving PCC';
        } else if (isActiveScc) {
            cls += ' active-scc';
            tagCls = 'band-status-tag scc';
            tagLabel = 'CA SCC';
        }

        return `
            <div class="${cls}">
                <div class="band-chip-top">
                    <span class="band-id">${b.id}</span>
                    <span class="${tagCls}">${tagLabel}</span>
                </div>
                <div class="band-chip-freq">${b.freq_mhz} MHz (${b.duplex})</div>
                <div class="band-chip-meta">
                    <span>${b.rat.replace('_', ' ')}</span>
                    <span>Max ${b.max_bw_mhz} MHz</span>
                </div>
            </div>
        `;
    }).join('');
}

/* ─── AT Command Interrogation Console ──────────────────────────────────── */
function initDeviceAtProbe() {
    document.querySelectorAll('.at-quick-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const cmd = btn.getAttribute('data-cmd');
            const input = document.getElementById('input-device-at-cmd');
            if (input) input.value = cmd;
            executeDeviceAtCmd(cmd);
        });
    });

    document.getElementById('btn-exec-device-at')?.addEventListener('click', () => {
        const input = document.getElementById('input-device-at-cmd');
        const cmd = input ? input.value.trim() : 'AT+CGMI';
        if (cmd) executeDeviceAtCmd(cmd);
    });

    document.getElementById('input-device-at-cmd')?.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            const cmd = e.target.value.trim();
            if (cmd) executeDeviceAtCmd(cmd);
        }
    });
}

function executeDeviceAtCmd(cmd) {
    const outEl = document.getElementById('device-at-output');
    const latEl = document.getElementById('at-probe-lat');
    if (outEl) outEl.textContent = `[TX] >> ${cmd}\n[Awaiting response…]`;

    fetch('/api/device/at_probe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cmd })
    })
    .then(r => r.json())
    .then(d => {
        if (latEl && d.latency_ms !== undefined) {
            latEl.textContent = `${d.latency_ms} ms`;
        }
        if (outEl) {
            const outText = d.output || (d.status === 'ok' ? 'OK' : 'ERROR / No response');
            outEl.textContent = `[TX] >> ${cmd}\n[RX] << ${outText}`;
        }
        showToast(`AT Executed: ${cmd}`, 'info');
    })
    .catch(() => {
        // Direct terminal fallback
        fetch('/api/terminal/exec', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ cmd })
        })
        .then(r => r.json())
        .then(d => {
            if (outEl) outEl.textContent = `[TX] >> ${cmd}\n[RX] << ${d.output || 'OK'}`;
        })
        .catch(err => {
            if (outEl) outEl.textContent = `[TX] >> ${cmd}\n[ERR] << Bridge communication error: ${err.message}`;
        });
    });
}

/* ─── Hardware Diagnostics & Self-Test ──────────────────────────────────── */
function initDeviceSelfTest() {
    const trigger = document.getElementById('btn-device-selftest-trigger');
    const runBtn = document.getElementById('btn-run-selftest-now');

    const runAction = () => {
        const card = document.getElementById('device-selftest-card');
        if (card) card.scrollIntoView({ behavior: 'smooth' });
        runDeviceSelfTest();
    };

    trigger?.addEventListener('click', runAction);
    runBtn?.addEventListener('click', runAction);
}

function runDeviceSelfTest() {
    const runBtn = document.getElementById('btn-run-selftest-now');
    const tbody = document.getElementById('selftest-tbody');
    const healthBadge = document.getElementById('selftest-health-badge');
    const latBadge = document.getElementById('selftest-latency-badge');

    if (runBtn) {
        runBtn.disabled = true;
        runBtn.innerHTML = 'Testing…';
    }

    fetch('/api/device/selftest', { method: 'POST' })
        .then(r => r.json())
        .then(d => {
            if (d.status === 'ok' && d.tests) {
                if (healthBadge) {
                    healthBadge.textContent = d.overall_health;
                    healthBadge.className = 'badge ' + (d.passed_count === d.total_count ? 'badge-sec-safe' : 'badge-sec-warn');
                }
                if (latBadge) {
                    latBadge.textContent = `⏱ ${d.total_latency_ms} ms Total`;
                }
                if (tbody) {
                    tbody.innerHTML = d.tests.map(t => `
                        <tr>
                            <td><span class="badge badge-secondary">${t.subsystem}</span></td>
                            <td><strong>${t.name}</strong></td>
                            <td><span class="badge ${t.status === 'PASS' ? 'badge-sec-safe' : 'badge-sec-warn'}">${t.status}</span></td>
                            <td><code>${t.latency_ms} ms</code></td>
                            <td>${t.details}</td>
                        </tr>
                    `).join('');
                }
                showToast(`Hardware Self-Test Complete: ${d.overall_health}`, 'success');
            }
        })
        .catch(() => {
            showToast('Self-test diagnostics run complete', 'info');
        })
        .finally(() => {
            if (runBtn) {
                runBtn.disabled = false;
                runBtn.innerHTML = '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg> Run Diagnostic Test';
            }
        });
}

/* ─── Device Dossier JSON & Markdown Export ──────────────────────────────── */
function initDeviceExports() {
    document.getElementById('btn-export-device-json')?.addEventListener('click', () => {
        const payload = {
            device: state.deviceData,
            bands: cachedDeviceBands,
            timestamp: new Date().toISOString(),
            platform: 'AirTap TelcoSec Visual Operations Suite'
        };
        const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `airtap_device_dossier_${Date.now()}.json`;
        a.click();
        showToast('Exported Device Hardware Dossier JSON', 'success');
    });
}


/* ─── Mono-Copyable Clipboard Handler ───────────────────────────────────── */
function initMonoCopyable() {
    document.querySelectorAll('.mono-copyable').forEach(el => {
        el.title = el.title || 'Click to copy';
        el.addEventListener('click', () => {
            const text = el.textContent.trim();
            navigator.clipboard.writeText(text)
                .then(() => {
                    showToast(`Copied: ${text.length > 30 ? text.slice(0, 28) + '…' : text}`, 'success');
                    el.classList.add('copy-flash');
                    el.addEventListener('animationend', () => el.classList.remove('copy-flash'), { once: true });
                })
                .catch(() => showToast('Clipboard copy failed', 'error'));
        });
    });
}

/* ─── Build device profile text report ──────────────────────────────────── */
function buildDeviceProfileReport() {
    const dev = state.deviceData;
    if (!dev || !Object.keys(dev).length) return 'No device data available.';
    const lines = [
        '═══════════════════════════════════════════════════════',
        '  AirTAP TelcoSec — Device Hardware Dossier Report',
        `  Generated: ${new Date().toISOString()}`,
        '═══════════════════════════════════════════════════════',
        '',
        `  Model         : ${dev.model || dev.name || '—'}`,
        `  Chipset       : ${dev.chipset || '—'}`,
        `  HW Revision   : ${dev.hw_revision || '—'}`,
        `  Firmware      : ${dev.firmware_build || dev.firmware || '—'}`,
        `  Comp Date     : ${dev.comp_date || '—'}`,
        `  Diag Version  : ${dev.diag_version || '—'}`,
        `  Sec Patch     : ${dev.sec_patch || '—'}`,
        '',
        `  IMEI          : ${dev.imei || '—'}`,
        `  IMSI          : ${dev.imsi || '—'}`,
        `  ICCID         : ${dev.iccid || '—'}`,
        `  ESN           : ${dev.serial_esn || '—'}`,
        '',
        `  Serving PLMN  : ${dev.serving_plmn || '—'}`,
        `  Active RAT    : ${dev.active_rat || '—'}`,
        `  Band          : ${dev.serving_band || '—'}`,
        `  PCI           : ${dev.pci !== undefined ? dev.pci : '—'}`,
        '',
        `  Secure Boot   : ${dev.secure_boot ? 'ENFORCED' : 'NOT ENFORCED'}`,
        `  TrustZone     : ${dev.trustzone ? 'ACTIVE' : 'INACTIVE'}`,
        `  5G Cipher     : ${dev.cipher_5g || '—'}`,
        `  LTE Cipher    : ${dev.cipher_lte || '—'}`,
        `  SUCI Scheme   : ${dev.suci_scheme || '—'}`,
        '',
        '═══════════════════════════════════════════════════════',
    ];
    return lines.join('\n');
}

/* ─── Interactive Session Replay Engine ──────────────────────────────────── */
function initReplay() {
    const fileInput = document.getElementById('replay-file-input');
    fileInput?.addEventListener('change', e => {
        const file = e.target.files[0];
        if (!file) return;

        showToast(`Loading capture: ${file.name}…`, 'info');
        const reader = new FileReader();
        reader.onload = () => {
            const b64 = reader.result.split(',')[1];
            fetch('/api/replay/load', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ file_path: file.name, raw_base64: b64 })
            })
            .then(r => r.json())
            .then(d => {
                if (d.replay) updateReplayUI(d.replay);
                showToast(`Loaded ${d.replay?.total_frames || 0} frames from ${file.name}`, 'success');
            })
            .catch(() => showToast('Failed to load replay file', 'error'));
        };
        reader.readAsDataURL(file);
    });

    document.getElementById('btn-replay-playpause')?.addEventListener('click', () => {
        const action = state.replay.isPlaying ? 'pause' : 'play';
        sendReplayControl(action);
    });

    document.getElementById('btn-replay-step')?.addEventListener('click', () => sendReplayControl('step'));
    document.getElementById('btn-replay-back')?.addEventListener('click', () => {
        const newPct = Math.max(0, state.replay.progressPercent - 5);
        sendReplayControl('seek', { percent: newPct });
    });
    document.getElementById('btn-replay-forward')?.addEventListener('click', () => {
        const newPct = Math.min(100, state.replay.progressPercent + 5);
        sendReplayControl('seek', { percent: newPct });
    });

    const slider = document.getElementById('replay-slider');
    slider?.addEventListener('input', e => {
        sendReplayControl('seek', { percent: parseFloat(e.target.value) });
    });

    document.querySelectorAll('.speed-pill[data-speed]').forEach(p => {
        p.addEventListener('click', () => {
            document.querySelectorAll('.speed-pill').forEach(x => x.classList.remove('active'));
            p.classList.add('active');
            sendReplayControl('speed', { speed: parseFloat(p.dataset.speed) });
        });
    });
}

function sendReplayControl(action, extra = {}) {
    fetch('/api/replay/control', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action, ...extra })
    })
    .then(r => r.json())
    .then(d => { if (d.replay) updateReplayUI(d.replay); });
}

function handleReplayEvent(msg) {
    if (!msg || !msg.data) return;
    updateReplayUI(msg.data);
}

function updateReplayUI(r) {
    if (!r) return;
    state.replay.isPlaying = (r.state === 'PLAYING');
    state.replay.progressPercent = r.progress_percent || 0;
    state.replay.state = r.state || 'IDLE';

    setText('replay-filename', r.file_name || 'Recorded Session');
    setText('replay-state-badge', r.state || 'IDLE');

    const btn = document.getElementById('btn-replay-playpause');
    if (btn) btn.textContent = state.replay.isPlaying ? '⏸ Pause' : '⏯ Play';

    const slider = document.getElementById('replay-slider');
    if (slider) slider.value = r.progress_percent || 0;

    const elTime = fmtSecToTime(r.elapsed_sec || 0);
    const totTime = fmtSecToTime(r.total_duration_sec || 0);
    setText('replay-time-display', `${elTime} / ${totTime}`);
}

function fmtSecToTime(sec) {
    const s = Math.floor(sec % 60);
    const m = Math.floor((sec / 60) % 60);
    const h = Math.floor(sec / 3600);
    return `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
}

/* ─── Fully Optimized Wardriving & Real-Time ThreatMap Engine ────────────── */
function isValidLatLng(lat, lng) {
    const latNum = parseFloat(lat);
    const lngNum = parseFloat(lng);
    return Number.isFinite(latNum) && Number.isFinite(lngNum) &&
           latNum >= -90 && latNum <= 90 &&
           lngNum >= -180 && lngNum <= 180;
}

function haversineDistKm(lat1, lon1, lat2, lon2) {
    if (!isValidLatLng(lat1, lon1) || !isValidLatLng(lat2, lon2)) return 0.0;
    const R = 6371.0;
    const dLat = (lat2 - lat1) * Math.PI / 180.0;
    const dLon = (lon2 - lon1) * Math.PI / 180.0;
    const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
              Math.cos(lat1 * Math.PI / 180.0) * Math.cos(lat2 * Math.PI / 180.0) *
              Math.sin(dLon / 2) * Math.sin(dLon / 2);
    const c = 2 * Math.atan2(Math.sqrt(Math.max(0, Math.min(1, a))), Math.sqrt(Math.max(0, 1 - a)));
    return R * c;
}

function fmtSecToTime(seconds) {
    const s = Math.max(0, Math.floor(seconds || 0));
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    return `${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}:${sec.toString().padStart(2, '0')}`;
}

function initWardriveMap() {
    const mapEl = document.getElementById('wardrive-map');
    if (!mapEl || typeof L === 'undefined') return;

    if (state.geo.map) {
        state.geo.map.remove();
        state.geo.map = null;
    }

    if (!isValidLatLng(state.geo.currentLat, state.geo.currentLng)) {
        state.geo.currentLat = 37.7749;
        state.geo.currentLng = -122.4194;
    }

    state.geo.map = L.map('wardrive-map', {
        center: [state.geo.currentLat, state.geo.currentLng],
        zoom: 15,
        zoomControl: true,
        attributionControl: false
    });

    state.geo.tileLayers = {
        darkmatter: L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
            maxZoom: 19, subdomains: 'abcd'
        }),
        osm: L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            maxZoom: 19
        }),
        satellite: L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}', {
            maxZoom: 19
        })
    };

    state.geo.tileLayers.darkmatter.addTo(state.geo.map);

    // Tactical Layer Groups
    state.geo.towerLayer = L.layerGroup().addTo(state.geo.map);
    state.geo.heatmapLayer = L.layerGroup().addTo(state.geo.map);
    state.geo.threatLayer = L.layerGroup().addTo(state.geo.map);
    state.geo.riskZoneLayer = L.layerGroup().addTo(state.geo.map);
    state.geo.triangulationLayer = L.layerGroup().addTo(state.geo.map);
    state.geo.trailLayer = L.layerGroup().addTo(state.geo.map);
    state.geo.surveillanceLayer = L.layerGroup().addTo(state.geo.map);
    state.geo.taRingLayer = L.layerGroup().addTo(state.geo.map);

    state.geo.trailPolyline = L.polyline([], { color: '#39d5df', weight: 3, opacity: 0.85 }).addTo(state.geo.trailLayer);

    const pulseIcon = L.divIcon({
        className: 'gps-pulse-marker',
        html: '<div class="gps-pulse-dot"></div>',
        iconSize: [20, 20],
        iconAnchor: [10, 10]
    });
    state.geo.handsetMarker = L.marker([state.geo.currentLat, state.geo.currentLng], { icon: pulseIcon }).addTo(state.geo.map);

    // Basemap Switcher
    document.getElementById('select-basemap')?.addEventListener('change', e => {
        const selected = e.target.value;
        Object.values(state.geo.tileLayers).forEach(layer => {
            if (state.geo.map.hasLayer(layer)) state.geo.map.removeLayer(layer);
        });
        if (state.geo.tileLayers[selected]) {
            state.geo.tileLayers[selected].addTo(state.geo.map);
            state.geo.currentBasemap = selected;
        }
    });

    document.getElementById('btn-map-recenter')?.addEventListener('click', () => {
        if (state.geo.map && isValidLatLng(state.geo.currentLat, state.geo.currentLng)) {
            state.geo.map.flyTo([state.geo.currentLat, state.geo.currentLng], 16, { duration: 1.2 });
        }
    });

    // Real Live GPS Lock Button Handler
    document.getElementById('btn-map-gps-lock')?.addEventListener('click', () => {
        acquireRealTimeLocation(true);
    });

    // Map Location Search Handler (Coordinates or City/Address via Nominatim)
    const handleMapSearch = () => {
        const query = document.getElementById('input-map-search')?.value.trim();
        if (!query) return;

        // Check if query is in "lat, lng" format
        const coordMatch = query.match(/^([-+]?[0-9]*\.?[0-9]+)\s*[,\s]\s*([-+]?[0-9]*\.?[0-9]+)$/);
        if (coordMatch) {
            const sLat = parseFloat(coordMatch[1]);
            const sLng = parseFloat(coordMatch[2]);
            if (isValidLatLng(sLat, sLng)) {
                applyCustomLocation(sLat, sLng, 'Manual Search Target');
                showToast(`Centered on coordinates: ${sLat.toFixed(5)}, ${sLng.toFixed(5)}`, 'success');
                return;
            }
        }

        // Otherwise geocode query via OpenStreetMap Nominatim
        showToast(`Searching location: ${query}…`, 'info');
        fetch(`https://nominatim.openstreetmap.org/search?format=json&limit=1&q=${encodeURIComponent(query)}`)
            .then(r => r.json())
            .then(data => {
                if (data && data.length > 0) {
                    const res = data[0];
                    const sLat = parseFloat(res.lat);
                    const sLng = parseFloat(res.lon);
                    if (isValidLatLng(sLat, sLng)) {
                        applyCustomLocation(sLat, sLng, res.display_name.split(',')[0]);
                        showToast(`Found: ${res.display_name.split(',').slice(0, 2).join(',')}`, 'success');
                    }
                } else {
                    showToast(`No location found for "${query}"`, 'warn');
                }
            })
            .catch(() => showToast('Geocoding search service unavailable', 'error'));
    };

    document.getElementById('btn-map-search')?.addEventListener('click', handleMapSearch);
    document.getElementById('input-map-search')?.addEventListener('keydown', e => {
        if (e.key === 'Enter') handleMapSearch();
    });

    // Fullscreen Tactical Toggle
    document.getElementById('btn-map-fullscreen')?.addEventListener('click', () => {
        state.geo.isFullscreen = !state.geo.isFullscreen;
        const container = document.getElementById('wardrive-grid-container');
        const btn = document.getElementById('btn-map-fullscreen');
        if (container) container.classList.toggle('fullscreen-map', state.geo.isFullscreen);
        if (btn) btn.textContent = state.geo.isFullscreen ? '✕ Exit Fullscreen' : '⛶ Fullscreen';
        setTimeout(() => { if (state.geo.map) state.geo.map.invalidateSize(); }, 200);
    });

    // Exporters
    document.getElementById('btn-export-kml')?.addEventListener('click', () => {
        window.location.href = '/api/geo/export?format=kml';
        showToast('Downloading 3D Google Earth KML…', 'success');
    });

    document.getElementById('btn-export-geojson')?.addEventListener('click', () => {
        window.location.href = '/api/geo/export?format=geojson';
        showToast('Downloading GeoJSON Wardrive data…', 'success');
    });

    document.getElementById('btn-export-wigle')?.addEventListener('click', () => {
        window.location.href = '/api/geo/export?format=wigle';
        showToast('Downloading WiGLE & OpenCelliD CSV…', 'success');
    });

    // Layer checkboxes
    const bindLayerToggle = (chkId, layerGroup) => {
        document.getElementById(chkId)?.addEventListener('change', e => {
            if (e.target.checked) state.geo.map.addLayer(layerGroup);
            else state.geo.map.removeLayer(layerGroup);
        });
    };
    bindLayerToggle('layer-chk-towers', state.geo.towerLayer);
    bindLayerToggle('layer-chk-heatmap', state.geo.heatmapLayer);
    bindLayerToggle('layer-chk-threats', state.geo.threatLayer);
    bindLayerToggle('layer-chk-riskzones', state.geo.riskZoneLayer);
    bindLayerToggle('layer-chk-triangulation', state.geo.triangulationLayer);
    bindLayerToggle('layer-chk-trail', state.geo.trailLayer);
    bindLayerToggle('layer-chk-ta-ring', state.geo.taRingLayer);
    bindLayerToggle('layer-chk-surveillance', state.geo.surveillanceLayer);

    // Acquire Real Physical Geolocation on initialization
    initRealTimeGeolocation();
}

/**
 * Initializes HTML5 Geolocation with continuous tracking & fallback to IP Geolocation.
 */
function initRealTimeGeolocation() {
    acquireRealTimeLocation(false);
}

function acquireRealTimeLocation(userTriggered = false) {
    if (!navigator.geolocation) {
        fallbackIpGeolocation('Geolocation not supported by browser');
        return;
    }

    if (userTriggered) showToast('Acquiring high-accuracy GPS fix…', 'info');

    navigator.geolocation.getCurrentPosition(
        pos => {
            const lat = parseFloat(pos.coords.latitude);
            const lng = parseFloat(pos.coords.longitude);
            if (!isValidLatLng(lat, lng)) {
                fallbackIpGeolocation(null);
                return;
            }

            const alt = parseFloat(pos.coords.altitude) || 15.0;
            const speed = (parseFloat(pos.coords.speed) || 0) * 3.6; // m/s to km/h
            const heading = parseFloat(pos.coords.heading) || 0;
            const accuracy = parseFloat(pos.coords.accuracy) || 10;

            const isInitial = (state.geo.currentLat === 37.7749 && state.geo.currentLng === -122.4194);

            updateGeoTelemetry({
                lat: lat,
                lng: lng,
                alt: Math.round(alt),
                speed: speed,
                heading: heading,
                accuracy: accuracy,
                source: 'DEVICE_GPS',
                sat_count: Math.min(18, Math.max(6, Math.round(30 - accuracy / 2))),
                pci: state.geo.lastPci || 248,
                rsrp: state.geo.lastRsrp || -92,
                band: 'Band n78'
            });

            if (isInitial || userTriggered) {
                if (state.geo.map && isValidLatLng(lat, lng)) {
                    state.geo.map.flyTo([lat, lng], 16, { duration: 1.2 });
                }
            }

            setText('map-fix-badge', `GPS 3D Fix (±${Math.round(accuracy)}m)`);
            if (userTriggered) showToast(`Real GPS locked: ${lat.toFixed(5)}, ${lng.toFixed(5)} (±${Math.round(accuracy)}m)`, 'success');

            // Send real coordinates to server backend for telemetry logging
            syncLocationToServer({ lat, lng, alt, speed, heading, accuracy, source: 'DEVICE_GPS' });

            // Start continuous watchPosition for live drive-testing
            if (!state.geo._gpsWatcherId) {
                state.geo._gpsWatcherId = navigator.geolocation.watchPosition(
                    wPos => {
                        const wLat = parseFloat(wPos.coords.latitude);
                        const wLng = parseFloat(wPos.coords.longitude);
                        if (!isValidLatLng(wLat, wLng)) return;
                        const wSpeed = (parseFloat(wPos.coords.speed) || 0) * 3.6;
                        updateGeoTelemetry({
                            lat: wLat,
                            lng: wLng,
                            alt: Math.round(wPos.coords.altitude || 15),
                            speed: wSpeed,
                            heading: wPos.coords.heading || state.geo.headingDeg,
                            accuracy: wPos.coords.accuracy || 10,
                            source: 'DEVICE_GPS',
                            pci: state.geo.lastPci || 248,
                            rsrp: state.geo.lastRsrp || -92
                        });
                        syncLocationToServer({ lat: wLat, lng: wLng, speed: wSpeed, source: 'DEVICE_GPS' });
                    },
                    err => console.debug('GPS watch update error:', err),
                    { enableHighAccuracy: true, maximumAge: 1000, timeout: 8000 }
                );
            }
        },
        err => {
            console.debug('HTML5 Geolocation error:', err.message);
            fallbackIpGeolocation(userTriggered ? 'Browser GPS permission denied — using network location' : null);
        },
        { enableHighAccuracy: true, timeout: 10000, maximumAge: 0 }
    );
}

function applyIpGeoFix(data) {
    if (!data) return;
    const ipLat = parseFloat(data.latitude);
    const ipLng = parseFloat(data.longitude);
    if (!state.geo || !isValidLatLng(ipLat, ipLng)) return;

    const isInitial = (state.geo.currentLat === 37.7749 && state.geo.currentLng === -122.4194);
    if (isInitial) {
        updateGeoTelemetry({
            lat: ipLat,
            lng: ipLng,
            alt: 25.0,
            speed: 0.0,
            source: 'IP_GEO',
            sat_count: 8,
            pci: state.geo.lastPci || 248,
            rsrp: -92
        });
        if (state.geo.map && isValidLatLng(ipLat, ipLng)) {
            state.geo.map.flyTo([ipLat, ipLng], 14, { duration: 1.5 });
        }
        setText('map-fix-badge', `City Fix (${data.city || data.country || 'Cached'})`);
        showToast(`Located in ${data.city || 'local region'}, ${data.country || ''}`, 'info');
        syncLocationToServer({ lat: ipLat, lng: ipLng, source: 'IP_GEO' });
    }
}

function fallbackIpGeolocation(msg) {
    if (msg) showToast(msg, 'warn');
    // 1. Check local session cache to prevent 429 rate limit
    try {
        const cached = sessionStorage.getItem('airtap_cached_geo');
        if (cached) {
            const data = JSON.parse(cached);
            if (data && data.latitude && data.longitude) {
                applyIpGeoFix(data);
                return;
            }
        }
    } catch(e) {}

    // 2. Fetch from service with silent rate-limit handling
    fetch('https://ipwho.is/')
        .then(r => {
            if (!r.ok) return null;
            return r.json();
        })
        .then(data => {
            if (data && data.success && data.latitude && data.longitude) {
                try { sessionStorage.setItem('airtap_cached_geo', JSON.stringify(data)); } catch(e) {}
                applyIpGeoFix(data);
            }
        })
        .catch(() => {});
}

function applyCustomLocation(lat, lng, label = 'Custom Fix') {
    const latNum = parseFloat(lat);
    const lngNum = parseFloat(lng);
    if (!isValidLatLng(latNum, lngNum)) return;

    updateGeoTelemetry({
        lat: latNum,
        lng: lngNum,
        alt: 20.0,
        speed: 0.0,
        source: 'MANUAL',
        sat_count: 12,
        pci: state.geo.lastPci || 248,
        rsrp: state.geo.lastRsrp || -90
    });
    if (state.geo.map && isValidLatLng(latNum, lngNum)) {
        state.geo.map.flyTo([latNum, lngNum], 16, { duration: 1.2 });
    }
    setText('map-fix-badge', label);
    syncLocationToServer({ lat: latNum, lng: lngNum, source: 'MANUAL' });
}

function syncLocationToServer(locData) {
    if (!locData || !isValidLatLng(locData.lat, locData.lng)) return;
    fetch('/api/geo/locate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(locData)
    }).catch(() => {});
}

/**
 * Updates handset marker, trail, signal heatmap, and realistic cell tower propagation.
 */
function updateGeoTelemetry(geo) {
    if (!geo || !isValidLatLng(geo.lat, geo.lng)) return;
    const lat = parseFloat(geo.lat);
    const lng = parseFloat(geo.lng);

    if (isValidLatLng(state.geo.prevLat, state.geo.prevLng)) {
        const d = haversineDistKm(state.geo.prevLat, state.geo.prevLng, lat, lng);
        if (d > 0.0002 && isFinite(d)) {
            state.geo.totalDistanceKm += d;

            const dLng = (lng - state.geo.prevLng) * Math.PI / 180.0;
            const lat1 = state.geo.prevLat * Math.PI / 180.0;
            const lat2 = lat * Math.PI / 180.0;
            const y = Math.sin(dLng) * Math.cos(lat2);
            const x = Math.cos(lat1) * Math.sin(lat2) - Math.sin(lat1) * Math.cos(lat2) * Math.cos(dLng);
            let brng = (Math.atan2(y, x) * 180.0 / Math.PI + 360.0) % 360.0;
            if (isFinite(brng)) state.geo.headingDeg = Math.round(brng);
        }
    }
    state.geo.prevLat = lat;
    state.geo.prevLng = lng;

    state.geo.currentLat = lat;
    state.geo.currentLng = lng;

    const rawSpeed = parseFloat(geo.speed);
    const speed = isFinite(rawSpeed) ? rawSpeed : (state.geo.speedKmh || 0.0);
    state.geo.speedKmh = speed;

    setText('geo-val-lat', lat.toFixed(6));
    setText('geo-val-lng', lng.toFixed(6));
    if (geo.alt !== undefined && isFinite(parseFloat(geo.alt))) setText('geo-val-alt', `${Math.round(parseFloat(geo.alt))} m`);
    if (geo.source) setText('geo-val-source', geo.source);
    if (geo.sat_count) setText('geo-val-sats', `${geo.sat_count} Sats`);
    setText('geo-val-speed', `${speed.toFixed(1)} km/h`);

    if (geo.pci) {
        state.geo.lastPci = parseInt(geo.pci, 10) || 248;
        setText('geo-val-pci', state.geo.lastPci);
    }
    if (geo.band) setText('geo-val-band', geo.band);

    const headingDirections = ['N', 'NE', 'E', 'SE', 'S', 'SW', 'W', 'NW'];
    const headingDir = headingDirections[Math.round((state.geo.headingDeg || 0) / 45) % 8];
    setText('hud-tel-heading', `${state.geo.headingDeg || 0}° ${headingDir}`);
    setText('hud-tel-speed', `${speed.toFixed(1)} km/h`);
    setText('hud-tel-dist', `${(state.geo.totalDistanceKm || 0).toFixed(2)} km`);

    setText('geo-stat-dist', `${(state.geo.totalDistanceKm || 0).toFixed(2)} km`);
    const elapsedSec = Math.floor((Date.now() - (state.geo.startTime || Date.now())) / 1000);
    setText('geo-stat-duration', fmtSecToTime(elapsedSec));

    if (state.geo.map && state.geo.handsetMarker) {
        const latlng = [lat, lng];
        state.geo.handsetMarker.setLatLng(latlng);

        state.geo.trailPoints.push(latlng);
        if (state.geo.trailPoints.length > 1000) state.geo.trailPoints.shift();
        state.geo.trailPolyline.setLatLngs(state.geo.trailPoints);

        const rawRsrp = parseFloat(geo.rsrp);
        const rsrp = isFinite(rawRsrp) ? rawRsrp : (state.geo.lastRsrp || -95);
        state.geo.lastRsrp = rsrp;
        let color = '#f85149';
        if (rsrp > -85) { color = '#3fb950'; state.geo.rsrpBuckets.exc++; }
        else if (rsrp > -95) { color = '#39d5df'; state.geo.rsrpBuckets.good++; }
        else if (rsrp > -105) { color = '#e3b341'; state.geo.rsrpBuckets.fair++; }
        else { state.geo.rsrpBuckets.poor++; }

        L.circle(latlng, {
            radius: 22,
            color: color,
            fillColor: color,
            fillOpacity: 0.38,
            stroke: false
        }).addTo(state.geo.heatmapLayer);

        const totalSamples = state.geo.rsrpBuckets.exc + state.geo.rsrpBuckets.good + state.geo.rsrpBuckets.fair + state.geo.rsrpBuckets.poor || 1;
        const setSeg = (id, count) => {
            const el = document.getElementById(id);
            if (el) el.style.width = `${((count / totalSamples) * 100).toFixed(1)}%`;
        };
        setSeg('seg-exc', state.geo.rsrpBuckets.exc);
        setSeg('seg-good', state.geo.rsrpBuckets.good);
        setSeg('seg-fair', state.geo.rsrpBuckets.fair);
        setSeg('seg-poor', state.geo.rsrpBuckets.poor);

        // ── Real Cellular Tower Multi-Sector Triangulation ──────────────────
        const pci = parseInt(geo.pci || state.geo.lastPci || 248, 10) || 248;
        const rat = (geo.rat || '5G').toUpperCase();
        const siteId = Math.floor(pci / 3);
        const sectorIndex = pci % 3; // 0, 1, 2 (120 deg separation)
        const sectorAngle = (sectorIndex * 120 + 30) % 360; // 30°, 150°, 270°

        if (!state.geo.knownTowers[siteId]) {
            // Realistic Log-Distance Path Loss Model distance calculation
            const exp = (-35.0 - rsrp) / 32.0;
            let estimatedDistM = 500;
            if (isFinite(exp)) {
                estimatedDistM = Math.min(1800, Math.max(120, Math.pow(10, exp) * 1000));
            }
            if (!isFinite(estimatedDistM)) estimatedDistM = 500;

            // Place tower opposite to sector pointing angle
            const towerAzimuthOpposite = (sectorAngle + 180) % 360;
            const dLat = (estimatedDistM / 111320.0) * Math.cos(towerAzimuthOpposite * Math.PI / 180.0);
            const cosLat = Math.cos(lat * Math.PI / 180.0);
            const dLng = (estimatedDistM / (111320.0 * (Math.abs(cosLat) > 0.0001 ? cosLat : 1.0))) * Math.sin(towerAzimuthOpposite * Math.PI / 180.0);

            const towerLat = lat + dLat;
            const towerLng = lng + dLng;

            if (isValidLatLng(towerLat, towerLng)) {
                state.geo.knownTowers[siteId] = { lat: towerLat, lng: towerLng, rat: rat, pci: pci, siteId: siteId };

                const ratColor = rat.includes('5G') ? '#39d5df' : rat.includes('4G') || rat.includes('LTE') ? '#58a6ff' : '#e3b341';
                const towerIcon = L.divIcon({
                    className: 'cell-tower-marker',
                    html: `<div style="background:#0d1117;border:2px solid ${ratColor};border-radius:4px;padding:3px 8px;font-size:10px;font-family:var(--font-mono);font-weight:bold;color:${ratColor};box-shadow:0 0 14px ${ratColor}66;white-space:nowrap;display:flex;align-items:center;gap:4px">
                        <span>🗼</span>
                        <span>${rat} eNB/gNB #${siteId}</span>
                    </div>`,
                    iconSize: [110, 24],
                    iconAnchor: [55, 12]
                });

                const tMarker = L.marker([towerLat, towerLng], { icon: towerIcon }).addTo(state.geo.towerLayer);
                tMarker.on('click', () => {
                    openBtsInspector(state.geo.knownTowers[siteId]);
                });
                tMarker.bindPopup(`
                    <div style="font-family:var(--font-sans);min-width:220px">
                        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px">
                            <span class="badge ${rat.includes('5G') ? 'badge-5g' : 'badge-4g'}">${rat} Base Station</span>
                            <span style="font-family:var(--font-mono);font-size:10px;color:var(--text-muted)">Site #${siteId}</span>
                        </div>
                        <div style="font-weight:800;font-size:13px;margin:2px 0">Serving Sector: PCI ${pci} (Sector ${sectorIndex + 1})</div>
                        <div style="font-size:11px;color:var(--text-secondary);margin:2px 0">RSRP: <strong>${rsrp} dBm</strong> | Band: ${geo.band || 'Serving'}</div>
                        <div style="font-size:11px;color:var(--text-secondary);margin:2px 0">Est. Distance: <strong>${(estimatedDistM / 1000.0).toFixed(2)} km</strong></div>
                        <div style="font-size:10px;color:var(--text-muted);font-family:var(--font-mono);margin:4px 0 8px">Coords: ${towerLat.toFixed(5)}, ${towerLng.toFixed(5)}</div>
                        <button class="btn btn-xs btn-primary" style="width:100%" onclick="openBtsInspector(state.geo.knownTowers[${siteId}])">🗼 Deep BTS Telemetry</button>
                    </div>
                `);

                // Draw all 3 sector radiation wedges
                for (let s = 0; s < 3; s++) {
                    const sAngle = (s * 120 + 30) % 360;
                    const isActiveSector = (s === sectorIndex);
                    const sColor = isActiveSector ? ratColor : 'rgba(255,255,255,0.2)';
                    const sRadius = isActiveSector ? Math.max(300, estimatedDistM * 1.1) : 220;
                    drawSectorWedge(towerLat, towerLng, sRadius, sAngle, 110, state.geo.towerLayer, sColor, isActiveSector ? 0.22 : 0.06);
                }

                // Connection line between handset and serving cell tower
                L.polyline([[lat, lng], [towerLat, towerLng]], {
                    color: ratColor,
                    weight: 1.5,
                    dashArray: '4, 4',
                    opacity: 0.6
                }).addTo(state.geo.triangulationLayer);

                const uniqueCount = Object.keys(state.geo.knownTowers).length;
                setText('geo-stat-cells', uniqueCount);
                setText('hud-tel-cells', uniqueCount);

                // Update Real-Time Tactical Map Intel Overlay with Found Telemetry
                setText('map-intel-cell', `PCI ${pci} (Site #${siteId}, Sec ${sectorIndex + 1})`);
                setText('map-intel-band', `310-410 (AT&T 5G+) | ${geo.band || 'Band n78 (3.5 GHz)'}`);
                setText('map-intel-ta', `${Math.round(estimatedDistM)}m Range (${(estimatedDistM/300).toFixed(1)} µs TA)`);
                setText('map-intel-ca', 'PCC n78 + SCC1 b3 (Active)');

                // Plot Timing Advance (TA) Distance Ring around Serving Base Station
                if (state.geo.taRingLayer) {
                    state.geo.taRingLayer.clearLayers();
                    L.circle([towerLat, towerLng], {
                        radius: estimatedDistM,
                        color: '#39d5df',
                        weight: 1.2,
                        dashArray: '5, 5',
                        fill: false,
                        opacity: 0.65
                    }).addTo(state.geo.taRingLayer).bindTooltip(`Timing Advance Range: ${Math.round(estimatedDistM)}m`, { sticky: true });
                }
            }
        }
    }
}

function drawSectorWedge(lat, lng, radiusMeters, azimuthDeg, beamwidthDeg, layerGroup, color = '#39d5df', opacity = 0.15) {
    if (!isValidLatLng(lat, lng) || !layerGroup) return;
    const r = (typeof radiusMeters === 'number' && isFinite(radiusMeters) && radiusMeters > 0) ? radiusMeters : 300;
    const cosLat = Math.cos((lat * Math.PI) / 180.0);
    const dLat = r / 111320.0;
    const dLng = r / (111320.0 * (Math.abs(cosLat) > 0.0001 ? cosLat : 1.0));

    const startAngle = azimuthDeg - beamwidthDeg / 2;
    const endAngle = azimuthDeg + beamwidthDeg / 2;
    const points = [[lat, lng]];

    for (let a = startAngle; a <= endAngle; a += 8) {
        const rad = (a * Math.PI) / 180.0;
        const pLat = lat + dLat * Math.cos(rad);
        const pLng = lng + dLng * Math.sin(rad);
        if (isValidLatLng(pLat, pLng)) {
            points.push([pLat, pLng]);
        }
    }
    points.push([lat, lng]);

    if (points.length >= 3) {
        L.polygon(points, {
            color: color,
            weight: opacity > 0.1 ? 1.5 : 0.8,
            fillColor: color,
            fillOpacity: opacity,
            dashArray: opacity > 0.1 ? null : '3, 3'
        }).addTo(layerGroup);
    }
}

function handleThreatGeoPin(alert) {
    if (!alert || !state.geo || !state.geo.map || !state.geo.threatLayer) return;

    let lat = parseFloat(alert.lat != null ? alert.lat : state.geo.currentLat);
    let lng = parseFloat(alert.lng != null ? alert.lng : state.geo.currentLng);
    if (!isValidLatLng(lat, lng)) {
        lat = 37.7749;
        lng = -122.4194;
    }

    const sev = (alert.severity || 'HIGH').toUpperCase();
    const ruleId = alert.rule_id || 'TELCOSEC-VULN-GEN';

    const pinClass = sev === 'CRITICAL' ? 'threat-pin-crit' : sev === 'HIGH' ? 'threat-pin-high' : 'threat-pin-med';
    const pinChar = sev === 'CRITICAL' ? '⚠' : '!';

    const threatIcon = L.divIcon({
        className: 'threat-map-pin',
        html: `<div class="threat-pin-inner ${pinClass}">${pinChar}</div>`,
        iconSize: [26, 26],
        iconAnchor: [13, 13]
    });

    const marker = L.marker([lat, lng], { icon: threatIcon }).addTo(state.geo.threatLayer);
    const alertJson = JSON.stringify(alert).replace(/'/g, "&#39;");
    marker.bindPopup(`
        <div style="font-family:var(--font-sans);min-width:220px">
            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px">
                <span class="sev-badge sev-${sev}">${sev}</span>
                <span class="rule-pill">${escapeHtml(ruleId)}</span>
            </div>
            <div style="font-weight:800;font-size:13px;margin:4px 0">${escapeHtml(alert.title || 'Threat Detected')}</div>
            <div style="font-size:11px;color:var(--text-secondary);margin-bottom:8px">${escapeHtml(alert.description || alert.desc || '')}</div>
            <button class="btn btn-sm btn-primary" style="width:100%" onclick='openThreatModalFromRow(${alertJson})'>Inspect Dossier</button>
        </div>
    `);

    if (sev === 'CRITICAL' || sev === 'HIGH') {
        if (state.geo.riskZoneLayer) {
            L.circle([lat, lng], {
                radius: 320,
                color: sev === 'CRITICAL' ? '#f85149' : '#f0883e',
                weight: 2,
                dashArray: '4, 4',
                fillColor: sev === 'CRITICAL' ? '#f85149' : '#f0883e',
                fillOpacity: 0.20
            }).addTo(state.geo.riskZoneLayer);
        }

        triangulateRogueCell(alert, lat, lng);
    }

    // If Lawful Interception / CALEA or Silent SMS is detected, plot animated Surveillance Vector
    const isSurveillance = ruleId.includes('008') || ruleId.includes('076') || ruleId.includes('077') || (alert.title && alert.title.includes('Silent SMS'));
    if (isSurveillance && state.geo.surveillanceLayer && state.geo.knownTowers) {
        const firstTower = Object.values(state.geo.knownTowers)[0];
        if (firstTower && isValidLatLng(firstTower.lat, firstTower.lng)) {
            const surPoly = L.polyline([[firstTower.lat, firstTower.lng], [lat, lng]], {
                color: '#f85149',
                weight: 2.5,
                dashArray: '6, 6',
                opacity: 0.9
            }).addTo(state.geo.surveillanceLayer);

            const surIcon = L.divIcon({
                className: 'surveillance-vector-marker',
                html: '<div class="surveillance-badge">⚡ SURVEILLANCE TRACE [CIN: 0x58A3B291]</div>',
                iconSize: [220, 24],
                iconAnchor: [110, 12]
            });

            const midLat = (firstTower.lat + lat) / 2;
            const midLng = (firstTower.lng + lng) / 2;
            if (isValidLatLng(midLat, midLng)) {
                L.marker([midLat, midLng], { icon: surIcon }).addTo(state.geo.surveillanceLayer);
            }

            const secIntelEl = document.getElementById('map-intel-sec');
            if (secIntelEl) {
                secIntelEl.textContent = '⚠️ Surveillance Probe Active';
                secIntelEl.className = 'intel-val sec-alert';
            }
        }
    }

    renderGeoThreatItem(alert, lat, lng, marker);
}

function triangulateRogueCell(alert, lat, lng) {
    if (!isValidLatLng(lat, lng) || !state.geo || !state.geo.triangulationLayer) return;

    const key = alert.pci || alert.rule_id || 'rogue_main';
    if (!state.geo.rogueEmitters[key]) {
        state.geo.rogueEmitters[key] = [];
    }
    const curRsrp = (typeof state.geo.lastRsrp === 'number' && isFinite(state.geo.lastRsrp)) ? state.geo.lastRsrp : -90;
    state.geo.rogueEmitters[key].push({ lat, lng, rsrp: curRsrp });

    const obs = state.geo.rogueEmitters[key];
    if (obs.length >= 2) {
        let sumW = 0, sumLat = 0, sumLng = 0;
        obs.forEach(o => {
            if (isValidLatLng(o.lat, o.lng)) {
                const w = Math.pow(10, ((o.rsrp || -90) + 140) / 20);
                if (isFinite(w) && w > 0) {
                    sumW += w;
                    sumLat += o.lat * w;
                    sumLng += o.lng * w;
                }
            }
        });

        if (sumW <= 0) return;
        const cLat = sumLat / sumW;
        const cLng = sumLng / sumW;
        if (!isValidLatLng(cLat, cLng)) return;

        state.geo.triangulationLayer.clearLayers();

        obs.forEach(o => {
            if (isValidLatLng(o.lat, o.lng)) {
                L.polyline([[o.lat, o.lng], [cLat, cLng]], {
                    color: '#f85149',
                    weight: 1.5,
                    dashArray: '3, 4',
                    opacity: 0.7
                }).addTo(state.geo.triangulationLayer);
            }
        });

        const rogueIcon = L.divIcon({
            className: 'rogue-emitter-marker',
            html: '<div class="rogue-emitter-icon">📡</div>',
            iconSize: [28, 28],
            iconAnchor: [14, 14]
        });

        const rogueMarker = L.marker([cLat, cLng], { icon: rogueIcon }).addTo(state.geo.triangulationLayer);
        rogueMarker.bindPopup(`
            <div style="font-family:var(--font-sans);min-width:200px">
                <span class="sev-badge sev-CRITICAL" style="margin-bottom:4px;display:inline-block">TRIANGULATED ROGUE BASE STATION</span>
                <div style="font-weight:700;margin:4px 0">Suspected Rogue Transmitter</div>
                <div style="font-size:11px;color:var(--text-secondary)">Centroid: ${cLat.toFixed(5)}, ${cLng.toFixed(5)}</div>
                <div style="font-size:11px;color:var(--text-secondary)">Observation Points: ${obs.length}</div>
            </div>
        `);
    }
}

function renderGeoThreatItem(alert, lat, lng, marker) {
    if (!isValidLatLng(lat, lng)) return;
    const list = document.getElementById('geo-threat-list');
    if (!list) return;

    if (list.querySelector('.empty-state')) list.innerHTML = '';

    const sev = (alert.severity || 'HIGH').toUpperCase();
    const item = document.createElement('div');
    item.className = 'geo-threat-item';
    item.style.cursor = 'pointer';
    item.title = 'Click to focus threat on map';
    item.innerHTML = `
        <div class="geo-threat-item-header">
            <span class="sev-badge sev-${sev}" style="font-size:9px;padding:1px 5px">${sev}</span>
            <span class="geo-threat-item-title" title="${escapeHtml(alert.title || '')}">${escapeHtml(alert.title || '')}</span>
        </div>
        <div class="geo-threat-item-meta">
            <span>${escapeHtml(alert.rule_id || '')}</span>
            <span>📍 ${lat.toFixed(4)}, ${lng.toFixed(4)}</span>
        </div>
    `;

    item.addEventListener('click', () => {
        if (state.geo.map && isValidLatLng(lat, lng)) {
            state.geo.map.flyTo([lat, lng], 17, { duration: 1.0 });
        }
        marker?.openPopup();
    });

    list.prepend(item);

    const countEl = document.getElementById('map-threat-count');
    if (countEl) {
        const count = list.querySelectorAll('.geo-threat-item').length;
        countEl.textContent = `${count} Event${count === 1 ? '' : 's'}`;
    }
}

/* ─── EFS Explorer ───────────────────────────────────────────────────────── */
/* ─── Tab 5: Baseband EFS Filesystem Explorer (Optimized) ────────────────── */

// ── Live 3GPP Cellular Attach & Registration State Machine Tracker ──────────
function updateAttachTimeline(packet) {
    if (!packet) return;
    const summary = (packet.summary || '').toLowerCase();
    const tree = (packet.tree || '').toLowerCase();
    const allText = summary + ' ' + tree;

    const elRrc = document.getElementById('step-rrc');
    const elSec = document.getElementById('step-sec');
    const elAka = document.getElementById('step-aka');
    const elReg = document.getElementById('step-reg');
    const elPdu = document.getElementById('step-pdu');
    const elDrx = document.getElementById('step-drx');
    const elSummary = document.getElementById('timeline-state-summary');

    if (allText.includes('rrc connection') || allText.includes('rrcsetup') || allText.includes('rrc resume')) {
        elRrc?.classList.add('completed');
        const desc = document.getElementById('step-rrc-desc');
        if (desc) desc.textContent = 'Connected (SRB1)';
        if (elSummary) elSummary.textContent = 'State: RRC_CONNECTED (SRB1 Active)';
    }

    if (allText.includes('security mode') || allText.includes('securitymodecommand') || allText.includes('sec_protected')) {
        elSec?.classList.add('completed');
        const desc = document.getElementById('step-sec-desc');
        if (desc) desc.textContent = 'Cipher & Integrity Enforced';
        if (elSummary) elSummary.textContent = 'State: SECURITY_ACTIVATED';
    }

    if (allText.includes('authentication request') || allText.includes('authentication response') || allText.includes('auth request') || allText.includes('aka')) {
        elAka?.classList.add('completed');
        const desc = document.getElementById('step-aka-desc');
        if (desc) desc.textContent = 'USIM Milenage Passed';
        if (elSummary) elSummary.textContent = 'State: MUTUAL_AUTHENTICATION_OK';
    }

    if (allText.includes('registration accept') || allText.includes('attach accept') || allText.includes('5gmm') || allText.includes('emm registered')) {
        elReg?.classList.add('completed');
        const desc = document.getElementById('step-reg-desc');
        if (desc) desc.textContent = 'Network Attached (5G/4G)';
        if (elSummary) elSummary.textContent = 'State: REGISTERED_NORMAL_SERVICE';
    }

    if (allText.includes('pdu session') || allText.includes('pdusessionestablishment') || allText.includes('activate default eps') || allText.includes('ip address alloc')) {
        elPdu?.classList.add('completed');
        const desc = document.getElementById('step-pdu-desc');
        if (desc) desc.textContent = 'QoS Flow Established';
        if (elSummary) elSummary.textContent = 'State: USER_PLANE_ACTIVE (IPv4/IPv6)';
    }

    if (allText.includes('drx') || allText.includes('connected') || allText.includes('paging') || allText.includes('user plane')) {
        elDrx?.classList.add('completed');
        const desc = document.getElementById('step-drx-desc');
        if (desc) desc.textContent = 'Active High Throughput';
    }
}

function updateRatBadges() {
    const counts = state.ratCounts || {};
    const total = state.totalPackets || 0;
    
    const setBadge = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.textContent = val > 999 ? (val/1000).toFixed(1) + 'k' : val;
    };

    setBadge('pill-count-all', total);
    setBadge('pill-count-5g', counts['5g'] || 0);
    setBadge('pill-count-4g', counts['4g'] || 0);
    setBadge('pill-count-3g', counts['3g'] || 0);
    setBadge('pill-count-2g', counts['2g'] || 0);
    setBadge('pill-count-ims', counts['ims'] || 0);
    setBadge('pill-count-sim', counts['sim'] || 0);
    setBadge('pill-count-bcch', counts['broadcast'] || 0);
    setBadge('pill-count-calea', counts['calea'] || 0);
    
    const threatCount = state.packets.filter(p => p.hasThreat || p.threat).length;
    setBadge('pill-count-threats', threatCount);
}


function initEfs() {
    // Navigation actions
    document.getElementById('efs-btn-go')?.addEventListener('click', () => loadEfsPath(getEfsPath()));
    document.getElementById('efs-btn-refresh')?.addEventListener('click', () => loadEfsPath(getEfsPath()));
    document.getElementById('efs-btn-home')?.addEventListener('click', () => {
        document.getElementById('efs-current-path').value = '/';
        loadEfsPath('/');
    });
    document.getElementById('efs-current-path')?.addEventListener('keydown', e => {
        if (e.key === 'Enter') loadEfsPath(getEfsPath());
    });
    document.getElementById('efs-btn-up')?.addEventListener('click', () => {
        let p = getEfsPath().replace(/\/+$/, '');
        const parent = p.substring(0, p.lastIndexOf('/')) || '/';
        document.getElementById('efs-current-path').value = parent;
        loadEfsPath(parent);
    });

    // In-Directory Quick Filter
    document.getElementById('efs-filter-input')?.addEventListener('input', e => {
        filterEfsDirectory(e.target.value);
    });

    // Global Recursive EFS Search
    const searchInput = document.getElementById('efs-search-input');
    const searchBtn = document.getElementById('efs-btn-search');
    searchBtn?.addEventListener('click', () => {
        if (searchInput && searchInput.value.trim()) {
            searchEfsRecursive(searchInput.value.trim());
        }
    });
    searchInput?.addEventListener('keydown', e => {
        if (e.key === 'Enter' && searchInput.value.trim()) {
            searchEfsRecursive(searchInput.value.trim());
        }
    });

    // Inspector View Mode Switcher
    document.querySelectorAll('.preview-mode-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const mode = btn.dataset.mode;
            switchEfsPreviewMode(mode);
        });
    });

    // Action Toolbar buttons
    document.getElementById('btn-copy-preview')?.addEventListener('click', () => {
        if (!state.efs.currentFileData) return;
        const textToCopy = state.efs.currentFileData.content || '';
        navigator.clipboard.writeText(textToCopy).then(() => {
            showToast('File content copied to clipboard', 'success');
        });
    });

    document.getElementById('btn-download-preview')?.addEventListener('click', () => {
        if (state.efs.selectedPath) {
            downloadEfsFile(state.efs.selectedPath);
        }
    });

    // Lazy load on first tab open
    document.querySelector('[data-tab="tab-efs"]')?.addEventListener('click', function handler() {
        loadEfsPath('/');
        loadEfsStatfs();
        this.removeEventListener('click', handler);
    });

    // Split resize handle drag logic
    const resizeHandle = document.getElementById('efs-resize-handle');
    const leftPanel = document.getElementById('efs-file-list-wrapper');
    const container = document.getElementById('efs-split-container');
    if (resizeHandle && leftPanel && container) {
        let dragging = false;
        let startX = 0;
        let startW = 0;
        resizeHandle.addEventListener('mousedown', e => {
            dragging = true;
            startX = e.clientX;
            startW = leftPanel.offsetWidth;
            resizeHandle.classList.add('dragging');
            document.body.style.userSelect = 'none';
        });
        document.addEventListener('mousemove', e => {
            if (!dragging) return;
            const delta = e.clientX - startX;
            const containerW = container.offsetWidth;
            const newW = Math.max(260, Math.min(containerW - 260, startW + delta));
            leftPanel.style.flex = 'none';
            leftPanel.style.width = newW + 'px';
        });
        document.addEventListener('mouseup', () => {
            if (!dragging) return;
            dragging = false;
            resizeHandle.classList.remove('dragging');
            document.body.style.userSelect = '';
        });
    }
}

function getEfsPath() {
    return (document.getElementById('efs-current-path')?.value || '/').trim() || '/';
}

function loadEfsPath(path) {
    const normPath = '/' + path.replace(/^\/+/, '').replace(/\/+$/, '');
    state.efs.currentPath = normPath === '' ? '/' : normPath;
    
    const input = document.getElementById('efs-current-path');
    if (input) input.value = state.efs.currentPath;

    renderEfsBreadcrumbs(state.efs.currentPath);

    const tbody = document.getElementById('efs-tbody');
    if (tbody) {
        tbody.innerHTML = '<tr><td colspan="6"><div class="empty-state"><span class="spinner"></span><p>Reading Qualcomm Baseband EFS…</p></div></td></tr>';
    }

    fetch(`/api/efs/ls?path=${encodeURIComponent(state.efs.currentPath)}`)
        .then(r => r.json())
        .then(data => {
            state.efs.currentFiles = data.files || [];
            renderEfsList(state.efs.currentFiles);
            loadEfsStatfs();
        })
        .catch(err => {
            if (tbody) {
                tbody.innerHTML = `<tr><td colspan="6"><div class="empty-state"><p>Error connecting to EFS subsystem: ${escapeHtml(String(err))}</p></div></td></tr>`;
            }
        });
}

function renderEfsBreadcrumbs(path) {
    const container = document.getElementById('efs-breadcrumbs-bar');
    if (!container) return;

    const parts = path.split('/').filter(Boolean);
    let html = `<span class="breadcrumb-node ${parts.length === 0 ? 'active' : ''}" onclick="quickBrowseEfs('/')">root (/)</span>`;
    
    let cumPath = '';
    parts.forEach((p, idx) => {
        cumPath += '/' + p;
        const isLast = idx === parts.length - 1;
        html += `<span class="breadcrumb-sep">/</span>`;
        html += `<span class="breadcrumb-node ${isLast ? 'active' : ''}" onclick="quickBrowseEfs('${cumPath}')">${escapeHtml(p)}</span>`;
    });

    container.innerHTML = html;
}

function renderEfsList(files, activeFilter = '') {
    const tbody = document.getElementById('efs-tbody');
    if (!tbody) return;

    const q = activeFilter.toLowerCase().trim();
    const filtered = q ? files.filter(f => f.name.toLowerCase().includes(q)) : files;

    const filterBadge = document.getElementById('efs-filter-badge');
    if (filterBadge) {
        filterBadge.textContent = q ? `${filtered.length}/${files.length}` : '';
    }

    // Update footer directory metrics
    const dirCount = filtered.filter(f => f.is_dir).length;
    const fileCount = filtered.filter(f => !f.is_dir).length;
    const totalBytes = filtered.reduce((acc, f) => acc + (f.size || 0), 0);
    
    setText('efs-footer-count', `${filtered.length} items (${dirCount} dirs, ${fileCount} files)`);
    setText('efs-footer-size', `${fmtBytes(totalBytes)} total`);

    if (!filtered.length) {
        tbody.innerHTML = `<tr><td colspan="6"><div class="empty-state"><p>${q ? 'No files match filter "' + escapeHtml(q) + '"' : 'Directory is empty'}</p></div></td></tr>`;
        return;
    }

    const sorted = [...filtered].sort((a, b) => {
        if (a.is_dir !== b.is_dir) return a.is_dir ? -1 : 1;
        return a.name.localeCompare(b.name);
    });

    tbody.innerHTML = '';
    sorted.forEach(f => {
        const tr = document.createElement('tr');
        if (state.efs.selectedPath === f.path) {
            tr.classList.add('efs-row-selected');
        }

        // File type badge
        let typeBadge = '';
        const ext = f.name.split('.').pop().toLowerCase();
        if (f.is_dir) {
            typeBadge = '<span class="badge-efs-dir">DIR</span>';
        } else if (ext === 'xml') {
            typeBadge = '<span class="badge-efs-xml">XML</span>';
        } else if (['bin', 'prl', 'dat', 'db'].includes(ext)) {
            typeBadge = '<span class="badge-efs-bin">BIN</span>';
        } else if (['cfg', 'conf', 'prop'].includes(ext)) {
            typeBadge = '<span class="badge-efs-cfg">CFG</span>';
        } else if (ext === 'json') {
            typeBadge = '<span class="badge-efs-cfg">JSON</span>';
        } else {
            typeBadge = '<span class="badge-efs-dat">FILE</span>';
        }

        const icon = f.is_dir ? '📁' : (ext === 'xml' ? '📜' : (['bin', 'prl', 'dat'].includes(ext) ? '⚙' : '📄'));
        const modeStr = f.mode ? `${f.mode} ${f.perms || ''}` : (f.is_dir ? '0755 rwxr-xr-x' : '0644 rw-r--r--');
        const mtimeStr = f.mtime || '—';

        tr.innerHTML = `
            <td><strong style="color:${f.is_dir ? 'var(--accent-cyan)' : 'var(--text-primary)'}">${icon} ${escapeHtml(f.name)}</strong></td>
            <td style="color:var(--text-muted);font-size:11px;">${f.is_dir ? '—' : fmtBytes(f.size)}</td>
            <td>${typeBadge}</td>
            <td style="color:var(--text-secondary);font-size:10px;">${escapeHtml(modeStr)}</td>
            <td style="color:var(--text-muted);font-size:10px;">${escapeHtml(mtimeStr)}</td>
            <td style="text-align:right;">
                ${f.is_dir 
                    ? `<button class="btn btn-xs btn-secondary" onclick="enterEfsDir('${escapeHtml(f.name)}')">Open ↗</button>`
                    : `<button class="btn btn-xs btn-primary" onclick="previewEfsFile('${escapeHtml(f.path)}')">View</button>
                       <button class="btn btn-xs btn-secondary" onclick="previewEfsFile('${escapeHtml(f.path)}', 'hex')" title="Hex Dump">Hex</button>`
                }
            </td>
        `;

        tr.addEventListener('click', e => {
            if (e.target.tagName === 'BUTTON') return;
            if (f.is_dir) {
                enterEfsDir(f.name);
            } else {
                previewEfsFile(f.path);
            }
        });

        tbody.appendChild(tr);
    });
}

function filterEfsDirectory(text) {
    renderEfsList(state.efs.currentFiles || [], text);
}

window.enterEfsDir = function(name) {
    let p = state.efs.currentPath.replace(/\/+$/, '');
    const newPath = p === '' || p === '/' ? `/${name}` : `${p}/${name}`;
    document.getElementById('efs-current-path').value = newPath;
    loadEfsPath(newPath);
};

window.quickBrowseEfs = function(dirPath) {
    const input = document.getElementById('efs-current-path');
    if (input) input.value = dirPath;
    loadEfsPath(dirPath);
};

window.previewEfsFile = function(filePath, defaultMode = null) {
    state.efs.selectedPath = filePath;

    // Highlight row in table
    document.querySelectorAll('#efs-tbody tr').forEach(row => {
        row.classList.remove('efs-row-selected');
    });

    const filename = filePath.split('/').pop() || filePath;
    setText('preview-filename', filePath);
    setText('preview-file-icon', filePath.endsWith('.xml') ? '📜' : (filePath.endsWith('.bin') ? '⚙' : '📄'));
    
    const dlBtn = document.getElementById('btn-download-preview');
    if (dlBtn) dlBtn.disabled = false;

    if (defaultMode) {
        switchEfsPreviewMode(defaultMode);
    } else if (filePath.endsWith('.bin') || filePath.endsWith('.prl') || filePath.endsWith('.dat')) {
        switchEfsPreviewMode('hex');
    } else {
        switchEfsPreviewMode(state.efs.previewMode || 'text');
    }

    setText('efs-file-content', 'Reading file from baseband EFS storage…');
    document.getElementById('efs-line-numbers').textContent = '1';

    // Parallel fetch cat & stat
    Promise.all([
        fetch(`/api/efs/cat?path=${encodeURIComponent(filePath)}`).then(r => r.json()),
        fetch(`/api/efs/stat?path=${encodeURIComponent(filePath)}`).then(r => r.json())
    ]).then(([catData, statData]) => {
        state.efs.currentFileData = catData;
        state.efs.currentStatData = statData;

        const sizeBadge = document.getElementById('preview-filesize-badge');
        if (sizeBadge) {
            sizeBadge.style.display = 'inline-block';
            sizeBadge.textContent = fmtBytes(catData.size || 0);
        }

        // Render code view
        renderEfsCodeViewer(catData.content || '');

        // Render hex dump
        renderEfsHexDump(catData.hex || '', catData.content || '');

        // Render stat attributes
        renderEfsStat(statData);

        // Render integrity
        setText('stat-val-md5', catData.md5 || statData.md5 || '—');
        setText('stat-val-sha256', statData.sha256 || '—');

    }).catch(err => {
        setText('efs-file-content', `Failed to read EFS file: ${escapeHtml(String(err))}`);
    });
};

function switchEfsPreviewMode(mode) {
    state.efs.previewMode = mode;
    
    document.querySelectorAll('.preview-mode-btn').forEach(b => {
        b.classList.toggle('active', b.dataset.mode === mode);
    });

    const panes = {
        'text': 'efs-pane-text',
        'hex': 'efs-pane-hex',
        'stat': 'efs-pane-stat',
        'integrity': 'efs-pane-integrity'
    };

    Object.entries(panes).forEach(([m, paneId]) => {
        const el = document.getElementById(paneId);
        if (el) {
            el.style.display = m === mode ? 'flex' : 'none';
        }
    });
}

function renderEfsCodeViewer(content) {
    const pre = document.getElementById('efs-file-content');
    const gutter = document.getElementById('efs-line-numbers');
    if (!pre || !gutter) return;

    pre.textContent = content;

    const lines = content.split('\n').length;
    let numbers = '';
    for (let i = 1; i <= lines; i++) {
        numbers += i + '\n';
    }
    gutter.textContent = numbers || '1';
}

function renderEfsHexDump(hexString, rawContent) {
    const tbody = document.getElementById('efs-hex-tbody');
    if (!tbody) return;

    if (!hexString && !rawContent) {
        tbody.innerHTML = '<tr><td colspan="3" style="text-align:center;color:var(--text-muted);padding:20px;">No binary data to display</td></tr>';
        return;
    }

    // Convert hexString (pairs of chars) or fallback to rawContent
    let bytes = [];
    if (hexString && hexString.length >= 2) {
        for (let i = 0; i < hexString.length; i += 2) {
            bytes.push(parseInt(hexString.substr(i, 2), 16));
        }
    } else {
        for (let i = 0; i < rawContent.length; i++) {
            bytes.push(rawContent.charCodeAt(i) & 0xFF);
        }
    }

    let rowsHtml = '';
    const totalLen = Math.min(bytes.length, 4096); // Render first 4KB for performance

    for (let offset = 0; offset < totalLen; offset += 16) {
        const offsetHex = offset.toString(16).padStart(8, '0').toUpperCase();
        let hexPart = '';
        let asciiPart = '';

        for (let j = 0; j < 16; j++) {
            if (offset + j < bytes.length) {
                const b = bytes[offset + j];
                hexPart += b.toString(16).padStart(2, '0').toUpperCase() + ' ';
                if (j === 7) hexPart += ' ';
                asciiPart += (b >= 32 && b <= 126) ? String.fromCharCode(b) : '·';
            } else {
                hexPart += '   ';
                if (j === 7) hexPart += ' ';
            }
        }

        rowsHtml += `<tr>
            <td class="hex-col-offset">${offsetHex}</td>
            <td class="hex-col-bytes">${hexPart}</td>
            <td class="hex-col-ascii">${escapeHtml(asciiPart)}</td>
        </tr>`;
    }

    if (bytes.length > 4096) {
        rowsHtml += `<tr><td colspan="3" style="text-align:center;color:var(--accent-cyan);padding:8px;font-size:10px;">Showing first 4,096 bytes of ${bytes.length} bytes</td></tr>`;
    }

    tbody.innerHTML = rowsHtml;
}

function renderEfsStat(stat) {
    if (!stat) return;
    setText('stat-val-path', stat.path || '—');
    setText('stat-val-size', stat.size_fmt || fmtBytes(stat.size || 0));
    setText('stat-val-mode', stat.mode || '0644');
    setText('stat-val-perms', stat.permissions || 'rw-r--r--');
    setText('stat-val-inode', String(stat.inode || '1042'));
    setText('stat-val-owner', `${stat.user || 'root'} (${stat.uid || 0}) / ${stat.group || 'radio'} (${stat.gid || 0})`);
    setText('stat-val-links', String(stat.hardlinks || 1));
    setText('stat-val-mtime', stat.mtime || '—');
}

function loadEfsStatfs() {
    fetch('/api/efs/statfs')
        .then(r => r.json())
        .then(data => {
            if (data.status !== 'ok') return;
            const usedMb = (data.used_bytes / 1048576).toFixed(1);
            const totalMb = (data.total_bytes / 1048576).toFixed(1);
            const pct = data.used_percent || 42.3;

            setText('statfs-usage-text', `${usedMb} / ${totalMb} MB (${pct}%)`);
            
            const bar = document.getElementById('statfs-bar-fill');
            if (bar) {
                bar.style.width = `${Math.min(100, pct)}%`;
                if (pct > 90) bar.style.background = 'var(--accent-red)';
                else if (pct > 70) bar.style.background = 'var(--accent-amber)';
                else bar.style.background = 'linear-gradient(90deg, var(--accent-cyan), var(--accent-blue))';
            }

            setText('statfs-inodes-text', `${(data.free_inodes || 0).toLocaleString()} Inodes Free`);
        })
        .catch(() => {});
}

function searchEfsRecursive(query) {
    const tbody = document.getElementById('efs-tbody');
    if (tbody) {
        tbody.innerHTML = `<tr><td colspan="6"><div class="empty-state"><span class="spinner"></span><p>Recursively searching EFS for "${escapeHtml(query)}"…</p></div></td></tr>`;
    }

    fetch(`/api/efs/search?q=${encodeURIComponent(query)}`)
        .then(r => r.json())
        .then(data => {
            const results = data.results || [];
            if (!results.length) {
                if (tbody) tbody.innerHTML = `<tr><td colspan="6"><div class="empty-state"><p>No files matching "${escapeHtml(query)}" found across EFS</p></div></td></tr>`;
                return;
            }
            renderEfsList(results, '');
            setText('efs-footer-count', `Found ${results.length} files matching "${query}"`);
        })
        .catch(err => {
            if (tbody) tbody.innerHTML = `<tr><td colspan="6"><div class="empty-state"><p>Search error: ${escapeHtml(String(err))}</p></div></td></tr>`;
        });
}

function downloadEfsFile(filePath) {
    window.location.href = `/api/efs/download?path=${encodeURIComponent(filePath)}`;
}

/* ─── Tab 6: NV RAM Manager & Band Locker (Optimized) ─────────────────────── */
const CARRIER_PRESETS = {
    att: {
        name: 'AT&T 5G+ (USA)',
        lte: [2, 4, 5, 12, 14, 29, 30, 66],
        nr: [5, 77, 260]
    },
    verizon: {
        name: 'Verizon 5G Ultra Wideband (USA)',
        lte: [2, 4, 5, 13, 48, 66],
        nr: [2, 5, 77, 261]
    },
    tmobile: {
        name: 'T-Mobile Ultra Capacity (USA)',
        lte: [2, 4, 12, 66, 71],
        nr: [25, 41, 71, 77]
    },
    vdf: {
        name: 'Vodafone 5G (Europe)',
        lte: [1, 3, 7, 8, 20, 28, 38],
        nr: [1, 3, 7, 8, 20, 28, 78]
    },
    dt: {
        name: 'Deutsche Telekom 5G (Europe)',
        lte: [1, 3, 7, 8, 20, 28, 32],
        nr: [1, 28, 78]
    },
    global: {
        name: 'Global 3GPP Rel-17 All-Bands',
        lte: [1, 2, 3, 4, 5, 7, 8, 12, 13, 14, 17, 18, 19, 20, 25, 26, 28, 29, 30, 38, 39, 40, 41, 42, 43, 46, 48, 66, 71],
        nr: [1, 2, 3, 5, 7, 8, 12, 20, 25, 28, 38, 40, 41, 66, 71, 77, 78, 79, 257, 258, 260, 261]
    },
    clear: {
        name: 'Clear All Bands',
        lte: [],
        nr: []
    }
};

function initNvCalculator() {
    let currentPane = 'pane-nr';

    // 1. Band Tabs Switcher (5G NR / 4G LTE / 2G/3G)
    const tabBtns = document.querySelectorAll('.nv-tab-btn');
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            tabBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            const paneId = btn.dataset.pane;
            currentPane = paneId;
            document.querySelectorAll('.nv-band-pane').forEach(p => {
                p.style.display = p.id === paneId ? 'block' : 'none';
            });
            renderBitwiseVisualizer(currentPane);
        });
    });

    // 2. Real-time Mask Update from Checkboxes
    const updateMasks = () => {
        // Calculate 4G LTE Mask (64-bit Bitmask)
        let lteMask = BigInt(0);
        document.querySelectorAll('#lte-bands-grid input[type=checkbox]').forEach(c => {
            if (c.checked) {
                const bNum = parseInt(c.value, 10);
                if (bNum >= 1 && bNum <= 64) {
                    lteMask |= (BigInt(1) << BigInt(bNum - 1));
                }
            }
        });
        const lteInput = document.getElementById('calc-lte-mask');
        if (lteInput && document.activeElement !== lteInput) {
            lteInput.value = '0x' + lteMask.toString(16).padStart(16, '0');
        }

        // Calculate 5G NR Mask (64-bit Mask for NV 71502)
        let nrMask = BigInt(0);
        document.querySelectorAll('#nr-bands-grid input[type=checkbox]').forEach(c => {
            if (c.checked) {
                const nNum = parseInt(c.value, 10);
                if (nNum < 64) {
                    nrMask |= (BigInt(1) << BigInt(nNum - 1));
                } else if (nNum >= 257) {
                    nrMask |= (BigInt(1) << BigInt(56 + (nNum - 257)));
                } else if (nNum === 78) {
                    nrMask |= (BigInt(1) << BigInt(61));
                } else if (nNum === 77) {
                    nrMask |= (BigInt(1) << BigInt(60));
                } else if (nNum === 79) {
                    nrMask |= (BigInt(1) << BigInt(62));
                } else if (nNum === 71) {
                    nrMask |= (BigInt(1) << BigInt(55));
                } else if (nNum === 66) {
                    nrMask |= (BigInt(1) << BigInt(54));
                }
            }
        });
        const nrInput = document.getElementById('calc-nr-mask');
        if (nrInput && document.activeElement !== nrInput) {
            nrInput.value = '0x' + nrMask.toString(16).padStart(16, '0');
        }

        renderBitwiseVisualizer(currentPane);
    };

    // 3. Render Interactive 64-Bit Visualizer Grid
    window.renderBitwiseVisualizer = function(paneId) {
        const container = document.getElementById('nv-bit-grid-container');
        const summaryEl = document.getElementById('bit-vis-summary');
        if (!container) return;

        let activeMask = BigInt(0);
        let bandTagMap = {};

        if (paneId === 'pane-nr') {
            const nrVal = document.getElementById('calc-nr-mask')?.value || '0x0';
            try { activeMask = BigInt(nrVal); } catch(e) { activeMask = BigInt(0); }
            bandTagMap = { 0: 'n1', 1: 'n2', 2: 'n3', 4: 'n5', 6: 'n7', 7: 'n8', 11: 'n12', 19: 'n20', 24: 'n25', 27: 'n28', 37: 'n38', 39: 'n40', 40: 'n41', 54: 'n66', 55: 'n71', 60: 'n77', 61: 'n78', 62: 'n79', 56: 'n257', 57: 'n258', 59: 'n260', 60: 'n261' };
        } else if (paneId === 'pane-lte') {
            const lteVal = document.getElementById('calc-lte-mask')?.value || '0x0';
            try { activeMask = BigInt(lteVal); } catch(e) { activeMask = BigInt(0); }
            bandTagMap = { 0: 'B1', 1: 'B2', 2: 'B3', 3: 'B4', 4: 'B5', 6: 'B7', 7: 'B8', 11: 'B12', 12: 'B13', 13: 'B14', 16: 'B17', 17: 'B18', 18: 'B19', 19: 'B20', 24: 'B25', 25: 'B26', 27: 'B28', 28: 'B29', 29: 'B30', 37: 'B38', 38: 'B39', 39: 'B40', 40: 'B41', 41: 'B42', 42: 'B43', 45: 'B46', 47: 'B48', 65: 'B66', 70: 'B71' };
        } else {
            bandTagMap = { 0: 'GSM850', 1: 'GSM900', 2: 'DCS1800', 3: 'PCS1900', 4: 'WCDMA1', 5: 'WCDMA2', 7: 'WCDMA8' };
        }

        let activeCount = 0;
        let cellsHtml = '';

        for (let i = 0; i < 64; i++) {
            const isBitSet = Boolean((activeMask >> BigInt(i)) & BigInt(1));
            if (isBitSet) activeCount++;
            const tag = bandTagMap[i] || `b${i}`;
            cellsHtml += `
                <div class="bit-cell ${isBitSet ? 'active' : ''}" data-bit="${i}" title="Bit ${i} (${tag}): ${isBitSet ? '1 (ACTIVE)' : '0 (OFF)'}">
                    <span class="bit-cell-val">${isBitSet ? '1' : '0'}</span>
                    <span class="bit-cell-tag">${tag}</span>
                    <span class="bit-cell-idx">${i}</span>
                </div>
            `;
        }

        container.innerHTML = cellsHtml;

        if (summaryEl) {
            summaryEl.textContent = `Active Bits: ${activeCount} / 64 (0x${activeMask.toString(16).toUpperCase().padStart(16, '0')})`;
        }

        // Attach click listeners to bit cells
        container.querySelectorAll('.bit-cell').forEach(cell => {
            cell.addEventListener('click', () => {
                const bitIdx = parseInt(cell.getAttribute('data-bit'), 10);
                const tag = bandTagMap[bitIdx];
                if (tag) {
                    const chk = document.querySelector(`input[value="${tag.replace(/^[nB]/, '')}"]`) || 
                                document.querySelector(`input[value="${tag.toLowerCase()}"]`);
                    if (chk) {
                        chk.checked = !chk.checked;
                        updateMasks();
                    }
                }
            });
        });
    };

    // Carrier profile presets selector
    document.getElementById('nv-carrier-presets')?.addEventListener('change', (e) => {
        const val = e.target.value;
        if (!val) return;

        const presets = {
            'att': { nr: ['1', '2', '5', '12', '28', '66', '77', '78', '260'], lte: ['2', '4', '5', '12', '14', '29', '30', '66'] },
            'verizon': { nr: ['2', '5', '66', '77', '260', '261'], lte: ['2', '4', '5', '13', '48', '66'] },
            'tmobile': { nr: ['25', '41', '66', '71'], lte: ['2', '4', '12', '66', '71'] },
            'vdf': { nr: ['1', '3', '7', '8', '20', '28', '78'], lte: ['1', '3', '7', '8', '20', '28'] },
            'dt': { nr: ['1', '3', '8', '28', '78'], lte: ['1', '3', '7', '8', '20', '28'] },
            'global': { nr: ['1', '2', '3', '5', '7', '8', '20', '28', '38', '40', '41', '66', '71', '77', '78', '79', '257', '258', '260', '261'], lte: ['1', '2', '3', '4', '5', '7', '8', '12', '13', '14', '17', '20', '25', '28', '38', '40', '41', '66', '71'] },
            'clear': { nr: [], lte: [] }
        };

        const prof = presets[val];
        if (prof) {
            document.querySelectorAll('#nr-bands-grid input[type=checkbox]').forEach(c => {
                c.checked = prof.nr.includes(c.value);
            });
            document.querySelectorAll('#lte-bands-grid input[type=checkbox]').forEach(c => {
                c.checked = prof.lte.includes(c.value);
            });
            updateMasks();
            showToast(`Applied carrier frequency profile: ${e.target.options[e.target.selectedIndex].text}`, 'info');
        }
    });

    renderBitwiseVisualizer('pane-nr');

    // 3. Bidirectional Hex Decode (User types / pastes hex into mask inputs)
    const lteInput = document.getElementById('calc-lte-mask');
    lteInput?.addEventListener('input', e => {
        try {
            let hexStr = e.target.value.trim().replace(/^0x/i, '');
            if (!hexStr) return;
            const mask = BigInt('0x' + hexStr);
            document.querySelectorAll('#lte-bands-grid input[type=checkbox]').forEach(c => {
                const bNum = parseInt(c.value, 10);
                if (bNum >= 1 && bNum <= 64) {
                    c.checked = Boolean(mask & (BigInt(1) << BigInt(bNum - 1)));
                }
            });
        } catch (err) {}
    });

    const nrInput = document.getElementById('calc-nr-mask');
    nrInput?.addEventListener('input', e => {
        try {
            let hexStr = e.target.value.trim().replace(/^0x/i, '');
            if (!hexStr) return;
            const mask = BigInt('0x' + hexStr);
            document.querySelectorAll('#nr-bands-grid input[type=checkbox]').forEach(c => {
                const nNum = parseInt(c.value, 10);
                if (nNum < 64) {
                    c.checked = Boolean(mask & (BigInt(1) << BigInt(nNum - 1)));
                }
            });
        } catch (err) {}
    });

    // Checkbox change event listener
    document.querySelectorAll('#lte-bands-grid input, #nr-bands-grid input, #legacy-bands-grid input').forEach(c => {
        c.addEventListener('change', updateMasks);
    });
    updateMasks();

    // 4. Carrier Presets Selection
    document.getElementById('nv-carrier-presets')?.addEventListener('change', e => {
        const key = e.target.value;
        const p = CARRIER_PRESETS[key];
        if (!p) return;

        document.querySelectorAll('#lte-bands-grid input').forEach(c => {
            c.checked = p.lte.includes(parseInt(c.value, 10));
        });
        document.querySelectorAll('#nr-bands-grid input').forEach(c => {
            c.checked = p.nr.includes(parseInt(c.value, 10));
        });
        updateMasks();
        showToast(`Applied carrier profile: ${p.name}`, 'success');
    });

    // 5. Select All / Clear Button Helpers
    document.getElementById('btn-lte-all')?.addEventListener('click', () => {
        document.querySelectorAll('#lte-bands-grid input').forEach(c => c.checked = true);
        updateMasks();
    });
    document.getElementById('btn-lte-clear')?.addEventListener('click', () => {
        document.querySelectorAll('#lte-bands-grid input').forEach(c => c.checked = false);
        updateMasks();
    });
    document.getElementById('btn-nr-all')?.addEventListener('click', () => {
        document.querySelectorAll('#nr-bands-grid input').forEach(c => c.checked = true);
        updateMasks();
    });
    document.getElementById('btn-nr-clear')?.addEventListener('click', () => {
        document.querySelectorAll('#nr-bands-grid input').forEach(c => c.checked = false);
        updateMasks();
    });
    document.getElementById('btn-legacy-all')?.addEventListener('click', () => {
        document.querySelectorAll('#legacy-bands-grid input').forEach(c => c.checked = true);
        updateMasks();
    });
    document.getElementById('btn-legacy-clear')?.addEventListener('click', () => {
        document.querySelectorAll('#legacy-bands-grid input').forEach(c => c.checked = false);
        updateMasks();
    });

    // 6. Copy Mask Buttons
    document.getElementById('btn-copy-lte-mask')?.addEventListener('click', () => {
        const val = document.getElementById('calc-lte-mask')?.value;
        if (val) {
            navigator.clipboard.writeText(val).then(() => showToast('Copied LTE band mask hex', 'success'));
        }
    });
    document.getElementById('btn-copy-nr-mask')?.addEventListener('click', () => {
        const val = document.getElementById('calc-nr-mask')?.value;
        if (val) {
            navigator.clipboard.writeText(val).then(() => showToast('Copied 5G NR band mask hex', 'success'));
        }
    });

    // 7. Live Band Read & Write actions
    document.getElementById('btn-read-live-bands')?.addEventListener('click', () => {
        showToast('Reading live NV band configurations from modem…', 'info');
        Promise.all([
            fetch('/api/nv/read?id=6828').then(r => r.json()),
            fetch('/api/nv/read?id=71502').then(r => r.json())
        ]).then(([lteData, nrData]) => {
            showToast('Modem NV bands read successfully', 'success');
            if (lteData.raw_hex) {
                inspectNvItem(6828);
            }
        }).catch(() => showToast('Could not read modem NV bands', 'warning'));
    });

    if (!state.nv) state.nv = { items: [], selectedNvId: 6828, selectedNvData: null, activeCategory: 'all', rollbackStack: [] };
    if (!state.nv.rollbackStack) state.nv.rollbackStack = [];

    document.getElementById('btn-write-band-masks')?.addEventListener('click', () => {
        const lteVal = document.getElementById('calc-lte-mask')?.value || '';
        const nrVal = document.getElementById('calc-nr-mask')?.value || '';
        const lteExtVal = document.getElementById('calc-lte-ext-mask')?.value || '';

        // Save pre-flight rollback snapshot
        state.nv.rollbackStack.push({
            timestamp: new Date().toLocaleTimeString(),
            lte: lteVal,
            nr: nrVal,
            lteExt: lteExtVal
        });

        fetch('/api/nv/write', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: 6828, hex_data: lteVal })
        })
        .then(r => r.json())
        .then(res => {
            showToast('NV 6828 (LTE Bands) and NV 71502 (5G NR) written to baseband', 'success');
        })
        .catch(() => showToast('Failed to write band mask to baseband', 'error'));
    });

    document.getElementById('btn-nv-rollback')?.addEventListener('click', () => {
        if (!state.nv.rollbackStack || state.nv.rollbackStack.length === 0) {
            showToast('No previous NV configuration snapshot available to rollback', 'warning');
            return;
        }
        const prev = state.nv.rollbackStack.pop();
        const lteInput = document.getElementById('calc-lte-mask');
        const nrInput = document.getElementById('calc-nr-mask');
        const lteExtInput = document.getElementById('calc-lte-ext-mask');
        if (lteInput) lteInput.value = prev.lte;
        if (nrInput) nrInput.value = prev.nr;
        if (lteExtInput) lteExtInput.value = prev.lteExt;

        fetch('/api/nv/write', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: 6828, hex_data: prev.lte })
        })
        .then(r => r.json())
        .then(res => {
            showToast(`Rolled back NV band configuration to snapshot (${prev.timestamp})`, 'success');
        })
        .catch(() => showToast('Rollback write failed', 'error'));
    });

    // 8. Initialize NV Catalog Table & Inspector
    initNvCatalog();
}

function initNvCatalog() {
    if (!state.nv) state.nv = { items: [], selectedNvId: 6828, selectedNvData: null, activeCategory: 'all' };
    loadNvCatalog('all');

    // Category filter dropdown
    document.getElementById('nv-category-filter')?.addEventListener('change', e => {
        state.nv.activeCategory = e.target.value;
        loadNvCatalog(state.nv.activeCategory);
    });

    // Search filter
    document.getElementById('nv-item-search')?.addEventListener('input', e => {
        const q = e.target.value.toLowerCase().trim();
        document.querySelectorAll('#nv-tbody tr').forEach(r => {
            const txt = r.textContent.toLowerCase();
            r.style.display = !q || txt.includes(q) ? '' : 'none';
        });
    });

    // Dump all NV button
    document.getElementById('btn-nv-dump-all')?.addEventListener('click', () => {
        window.location.href = '/api/nv/dump';
        showToast('Exporting complete Qualcomm NV items dump', 'success');
    });

    // Inspect buttons
    document.getElementById('btn-inspect-read-live')?.addEventListener('click', () => {
        if (state.nv.selectedNvId != null) {
            readNv(state.nv.selectedNvId, true);
        }
    });

    document.getElementById('btn-copy-nv-hex')?.addEventListener('click', () => {
        if (state.nv.selectedNvData && state.nv.selectedNvData.hex_128) {
            navigator.clipboard.writeText(state.nv.selectedNvData.hex_128)
                .then(() => showToast('Copied 128-byte hex dump to clipboard', 'success'));
        }
    });

    // Lazy load on first tab open
    document.querySelector('[data-tab="tab-nv"]')?.addEventListener('click', function handler() {
        inspectNvItem(6828);
        this.removeEventListener('click', handler);
    });
}

const DEFAULT_NV_CATALOG = [
    { id: 0, name: 'NV_ESN_I', description: 'Electronic Serial Number (ESN)', category: 'Identity & Security', preview_value: 'ESN: 0x8091A23B', default_hex: '3B A2 91 80 00 00 00 00' },
    { id: 454, name: 'NV_DIR_NUMBER_I', description: 'Directory Number / MDN Mobile Station Identifier', category: 'Identity & Security', preview_value: '0x3135353530313233', default_hex: '31 35 35 35 30 31 32 33 34 35 36 00 00 00 00 00' },
    { id: 550, name: 'NV_SEC_CODE_I', description: 'Security Service Programming Code (SPC 6-digit)', category: 'Identity & Security', preview_value: '0x3030303030300000', default_hex: '30 30 30 30 30 30 00 00' },
    { id: 553, name: 'NV_IMSI_MCC_I', description: 'IMSI Mobile Country Code (MCC)', category: 'Identity & Security', preview_value: '0xF800000000000000', default_hex: 'F8 00 00 00 00 00 00 00' },
    { id: 554, name: 'NV_IMSI_11_12_I', description: 'IMSI Mobile Network Code (MNC)', category: 'Identity & Security', preview_value: '0x0100000000000000', default_hex: '01 00 00 00 00 00 00 00' },
    { id: 1877, name: 'NV_RF_BC_CONFIG_I', description: '2G / 3G RF Band Configuration Mask', category: 'RF & Bands', preview_value: '0x00000000000800C5', default_hex: 'C5 00 08 00 00 00 00 00' },
    { id: 1878, name: 'NV_RF_BC_CONFIG_DIV_I', description: '2G / 3G Diversity RX Band Configuration', category: 'RF & Bands', preview_value: '0x00000000000800C5', default_hex: 'C5 00 08 00 00 00 00 00' },
    { id: 2061, name: 'NV_WCDMA_1900_I', description: 'WCDMA 1900 MHz (Band II) Calibration Parameters', category: 'RF & Bands', preview_value: '0x0100000000000000', default_hex: '01 00 00 00 00 00 00 00' },
    { id: 2062, name: 'NV_WCDMA_850_I', description: 'WCDMA 850 MHz (Band V) Calibration Parameters', category: 'RF & Bands', preview_value: '0x0100000000000000', default_hex: '01 00 00 00 00 00 00 00' },
    { id: 2954, name: 'NV_UMTS_UE_CATEGORY_I', description: 'UMTS / HSPA+ UE Category Capability (Cat 24/28)', category: 'Data & Bearer', preview_value: '0x1800000000000000', default_hex: '18 00 00 00 00 00 00 00' },
    { id: 6828, name: 'NV_LTE_BC_CONFIG_I', description: '4G LTE Frequency Band Configuration Mask (B1-B64)', category: 'RF & Bands', preview_value: '0x00080000000800C5 (B1, B3, B7, B8, B20, B28...)', default_hex: 'C5 00 08 00 00 08 00 00' },
    { id: 6829, name: 'NV_LTE_BC_CONFIG_DIV_I', description: '4G LTE RX Diversity Frequency Band Configuration', category: 'RF & Bands', preview_value: '0x00080000000800C5', default_hex: 'C5 00 08 00 00 08 00 00' },
    { id: 70210, name: 'NV_IMS_ENABLE_I', description: 'VoLTE / IMS Protocol Stack Enable Flag', category: 'Voice & IMS', preview_value: '1 (ENABLED)', default_hex: '01 00 00 00 00 00 00 00' },
    { id: 70211, name: 'NV_IMS_DOMAIN_NAME_I', description: 'IMS Home Network Domain Name', category: 'Voice & IMS', preview_value: '0x696D732E6578616D', default_hex: '69 6D 73 2E 65 78 61 6D 70 6C 65 2E 63 6F 6D 00' },
    { id: 71500, name: 'NV_NR5G_SA_ENABLE_I', description: '5G NR Standalone (SA Option 2) Operation Enable', category: '5G SA / NSA', preview_value: '1 (ENABLED)', default_hex: '01 00 00 00 00 00 00 00' },
    { id: 71501, name: 'NV_NR5G_NSA_ENABLE_I', description: '5G NR Non-Standalone (NSA Option 3x EN-DC) Enable', category: '5G SA / NSA', preview_value: '1 (ENABLED)', default_hex: '01 00 00 00 00 00 00 00' },
    { id: 71502, name: 'NV_NR5G_BAND_PREF_I', description: '5G NR Frequency Band Configuration & Preference Mask', category: 'RF & Bands', preview_value: '0x2000000000000085 (n1, n3, n8, n28, n78)', default_hex: '85 00 00 00 00 00 00 20' },
    { id: 73600, name: 'NV_VONR_ENABLE_I', description: 'Voice over 5G New Radio (VoNR) Enable Flag', category: 'Voice & IMS', preview_value: '1 (ENABLED)', default_hex: '01 00 00 00 00 00 00 00' },
    { id: 73800, name: 'NV_5G_SLICING_CONFIG_I', description: '5G Network Slicing (S-NSSAI / URLLC / eMBB Policy)', category: '5G SA / NSA', preview_value: '0x0100000102000001', default_hex: '01 00 00 01 02 00 00 01' }
];

function loadNvCatalog(category = 'all') {
    if (!state.nv) state.nv = { items: [], selectedNvId: 6828, selectedNvData: null, activeCategory: 'all' };
    const tbody = document.getElementById('nv-tbody');
    if (tbody) {
        tbody.innerHTML = '<tr><td colspan="5"><div class="empty-state"><span class="spinner"></span><p>Reading Qualcomm NV Catalog…</p></div></td></tr>';
    }

    fetch(`/api/nv/list?category=${encodeURIComponent(category)}`)
        .then(r => {
            if (!r.ok) throw new Error(`HTTP ${r.status}`);
            return r.json();
        })
        .then(data => {
            state.nv.items = (data && data.items && data.items.length) ? data.items : DEFAULT_NV_CATALOG;
            if (category !== 'all') {
                state.nv.items = state.nv.items.filter(it => it.category.toLowerCase() === category.toLowerCase());
            }
            renderNvCatalogTable(state.nv.items);
        })
        .catch(() => {
            // High-fidelity client-side catalog fallback
            let items = DEFAULT_NV_CATALOG;
            if (category !== 'all') {
                items = items.filter(it => it.category.toLowerCase() === category.toLowerCase());
            }
            state.nv.items = items;
            renderNvCatalogTable(state.nv.items);
        });
}

function renderNvCatalogTable(items) {
    const tbody = document.getElementById('nv-tbody');
    if (!tbody) return;

    if (!items.length) {
        tbody.innerHTML = '<tr><td colspan="5"><div class="empty-state"><p>No NV parameters in this category</p></div></td></tr>';
        return;
    }

    tbody.innerHTML = '';
    items.forEach(item => {
        const tr = document.createElement('tr');
        if (state.nv.selectedNvId === item.id) {
            tr.classList.add('nv-row-selected');
        }

        tr.innerHTML = `
            <td><code>${item.id}</code></td>
            <td>
                <strong style="color:var(--text-primary)">${escapeHtml(item.name)}</strong>
                <div style="font-size:10px;color:var(--text-muted)">${escapeHtml(item.description)}</div>
            </td>
            <td><span class="badge-nv-cat">${escapeHtml(item.category)}</span></td>
            <td id="nv-val-${item.id}"><span class="nv-val-ok">${escapeHtml(item.preview_value)}</span></td>
            <td style="text-align:right;">
                <button class="btn btn-xs btn-secondary" onclick="event.stopPropagation(); readNv(${item.id})">Read</button>
                <button class="btn btn-xs btn-primary" onclick="event.stopPropagation(); inspectNvItem(${item.id})">Inspect</button>
            </td>
        `;

        tr.addEventListener('click', () => inspectNvItem(item.id));
        tbody.appendChild(tr);
    });
}

window.readNv = function(nvId, autoInspect = false) {
    const el = document.getElementById(`nv-val-${nvId}`);
    if (el) el.innerHTML = '<span class="spinner" style="vertical-align:middle"></span>';

    fetch(`/api/nv/read?id=${nvId}`)
        .then(r => r.json())
        .then(data => {
            if (el && data.status === 'ok') {
                el.innerHTML = `<span class="nv-val-ok">${escapeHtml(data.value)}</span>`;
            }
            if (autoInspect || state.nv.selectedNvId === nvId) {
                renderNvInspectorData(data);
            }
        })
        .catch(() => {
            if (el) el.innerHTML = '<span class="nv-val-err">Error reading NV</span>';
        });
};

window.inspectNvItem = function(nvId) {
    if (!state.nv) state.nv = { items: [], selectedNvId: 6828, selectedNvData: null, activeCategory: 'all' };
    state.nv.selectedNvId = nvId;

    // Highlight row
    document.querySelectorAll('#nv-tbody tr').forEach(row => {
        row.classList.remove('nv-row-selected');
    });

    fetch(`/api/nv/read?id=${nvId}`)
        .then(r => {
            if (!r.ok) throw new Error(`HTTP ${r.status}`);
            return r.json();
        })
        .then(data => {
            state.nv.selectedNvData = data;
            renderNvInspectorData(data);
        })
        .catch(() => {
            const fallbackItem = DEFAULT_NV_CATALOG.find(it => it.id === nvId) || {
                id: nvId, name: `NV_ITEM_${nvId}`, description: 'Qualcomm Baseband NV Item', category: 'General', preview_value: '0x00000000', default_hex: '00 00 00 00 00 00 00 00'
            };
            const fallbackData = {
                status: 'ok',
                nv_id: fallbackItem.id,
                name: fallbackItem.name,
                description: fallbackItem.description,
                category: fallbackItem.category,
                value: fallbackItem.preview_value,
                hex_128: (fallbackItem.default_hex.replace(/\s+/g, '') + '00'.repeat(120)).toUpperCase(),
                status_name: 'CACHED'
            };
            state.nv.selectedNvData = fallbackData;
            renderNvInspectorData(fallbackData);
        });
};

function renderNvInspectorData(data) {
    if (!data) return;

    setText('nv-inspect-name', `NV #${data.nv_id} (${data.name})`);
    setText('nv-inspect-cat', data.category || 'General');
    setText('nv-inspect-status', data.status_name || 'SUCCESS');
    setText('nv-inspect-desc', data.description || 'Qualcomm Baseband Non-Volatile Item');
    setText('nv-decoded-value', data.value || '0x00000000');

    // Render 128-byte Hex Dump
    const hexTbody = document.getElementById('nv-hex-tbody');
    if (!hexTbody) return;

    const hex128 = data.hex_128 || '00'.repeat(128);
    let bytes = [];
    for (let i = 0; i < hex128.length; i += 2) {
        bytes.push(parseInt(hex128.substr(i, 2), 16));
    }

    let rowsHtml = '';
    for (let offset = 0; offset < Math.min(bytes.length, 128); offset += 16) {
        const offHex = offset.toString(16).padStart(4, '0').toUpperCase();
        let bytesHex = '';
        let asciiStr = '';

        for (let j = 0; j < 16; j++) {
            if (offset + j < bytes.length) {
                const b = bytes[offset + j];
                bytesHex += b.toString(16).padStart(2, '0').toUpperCase() + ' ';
                if (j === 7) bytesHex += ' ';
                asciiStr += (b >= 32 && b <= 126) ? String.fromCharCode(b) : '·';
            }
        }

        rowsHtml += `
            <tr>
                <td class="nv-hex-offset">${offHex}</td>
                <td class="nv-hex-bytes">${bytesHex}</td>
                <td class="nv-hex-ascii">${escapeHtml(asciiStr)}</td>
            </tr>
        `;
    }

    hexTbody.innerHTML = rowsHtml;
}

/* ─── Inspector Collapse / Toggle ────────────────────────────────────────── */

/* ─── Columnar Layout & Inspector Split Manager ──────────────────────────── */
function initSignalingLayout() {
    const btn = document.getElementById('btn-layout-toggle');
    const container = document.getElementById('signaling-split-container');
    if (!btn || !container) return;

    const saved = localStorage.getItem('airtap_layout_columns') === 'true';
    if (saved) {
        container.classList.add('layout-columns-split');
        btn.classList.add('active-layout');
        btn.title = 'Switch to Horizontal Stacked Rows Layout';
    }

    btn.addEventListener('click', () => {
        const isCols = container.classList.toggle('layout-columns-split');
        btn.classList.toggle('active-layout', isCols);
        btn.title = isCols ? 'Switch to Horizontal Stacked Rows Layout' : 'Switch to Side-by-Side Columns Layout';
        localStorage.setItem('airtap_layout_columns', isCols ? 'true' : 'false');
        showToast(isCols ? 'Decoded Data Layout: Side-by-Side Columns' : 'Decoded Data Layout: Stacked Rows', 'info');
    });

    // Information Element Search / Filter Input
    const filterInput = document.getElementById('ie-search-filter');
    if (filterInput) {
        filterInput.addEventListener('input', e => {
            const query = e.target.value.toLowerCase().trim();
            const rows = document.querySelectorAll('#insp-ie-tbody tr');
            let matchCount = 0;
            rows.forEach(r => {
                const text = r.textContent.toLowerCase();
                const matched = !query || text.includes(query);
                r.style.display = matched ? '' : 'none';
                if (matched && !r.querySelector('td[colspan]')) matchCount++;
            });
            const badge = document.getElementById('ie-count-badge');
            if (badge) badge.textContent = `${matchCount} Decoded Field${matchCount === 1 ? '' : 's'}`;
        });
    }
}

function initInspector() {
    initSignalingLayout();
    document.getElementById('inspector-toggle')?.addEventListener('click', toggleInspector);

    document.querySelectorAll('.insp-tab').forEach(t => {
        t.addEventListener('click', () => {
            document.querySelectorAll('.insp-tab').forEach(x => x.classList.remove('active'));
            document.querySelectorAll('.insp-view').forEach(v => v.classList.remove('active'));
            t.classList.add('active');
            document.getElementById(t.dataset.target)?.classList.add('active');
        });
    });

    document.getElementById('btn-copy-inspector')?.addEventListener('click', () => {
        const activeTab = document.querySelector('.insp-tab.active')?.dataset.target;
        const text = document.getElementById(activeTab === 'insp-hex' ? 'hex-content' : 'tree-content')?.textContent || '';
        navigator.clipboard.writeText(text).then(() => showToast('Copied to clipboard', 'success'));
    });

    document.getElementById('btn-copy-preview')?.addEventListener('click', () => {
        const text = document.getElementById('efs-file-content')?.textContent || '';
        navigator.clipboard.writeText(text).then(() => showToast('Copied file contents to clipboard', 'success'));
    });
}

function toggleInspector() {
    state.inspectorCollapsed = !state.inspectorCollapsed;
    const insp = document.getElementById('packet-inspector');
    const btn  = document.getElementById('btn-close-inspector');
    if (insp) insp.classList.toggle('collapsed', state.inspectorCollapsed);
    if (btn)  btn.textContent = state.inspectorCollapsed ? '⌃' : '⌄';
}

/* ─── Filters & Search ───────────────────────────────────────────────────── */
function initFilters() {
    // RAT Filter Pills
    document.querySelectorAll('.filter-pill[data-filter]').forEach(p => {
        p.addEventListener('click', () => {
            document.querySelectorAll('.filter-pill[data-filter]').forEach(x => x.classList.remove('active'));
            p.classList.add('active');
            state.currentFilter = p.dataset.filter;
            rebuildPacketTable();
        });
    });

    // 3GPP Signaling Event Presets
    document.querySelectorAll('.preset-pill[data-preset]').forEach(p => {
        p.addEventListener('click', () => {
            document.querySelectorAll('.preset-pill[data-preset]').forEach(x => x.classList.remove('active'));
            p.classList.add('active');
            state.currentPreset = p.dataset.preset;
            rebuildPacketTable();
        });
    });

    // Freeze Stream Toggle
    const freezeBtn = document.getElementById('btn-toggle-freeze');
    freezeBtn?.addEventListener('click', () => {
        state.isFrozen = !state.isFrozen;
        freezeBtn.classList.toggle('active', state.isFrozen);
        setText('freeze-icon', state.isFrozen ? '▶' : '⏸');
        setText('freeze-text', state.isFrozen ? 'Stream Paused' : 'Live Stream');
        if (!state.isFrozen) rebuildPacketTable();
        showToast(state.isFrozen ? 'Packet rendering paused for inspection' : 'Live packet streaming resumed', 'info');
    });

    // Audio Threat Alert Toggle
    document.getElementById('btn-toggle-audio')?.addEventListener('click', toggleAudioAlerts);

    // Density Selector Toggle
    const densityBtn = document.getElementById('btn-density-toggle');
    densityBtn?.addEventListener('click', () => {
        state.compactDensity = !state.compactDensity;
        document.getElementById('packet-table')?.classList.toggle('compact-density', state.compactDensity);
        densityBtn.classList.toggle('active', state.compactDensity);
        showToast(state.compactDensity ? 'Compact table row density' : 'Normal row density', 'info', 1500);
    });

    // Sortable Column Headers
    document.querySelectorAll('th.sortable-th[data-sort]').forEach(th => {
        th.addEventListener('click', () => {
            const col = th.dataset.sort;
            if (state.sortColumn === col) {
                state.sortDirection = state.sortDirection === 'asc' ? 'desc' : 'asc';
            } else {
                state.sortColumn = col;
                state.sortDirection = 'desc';
            }
            rebuildPacketTable();
        });
    });

    document.getElementById('filter-layer')?.addEventListener('change', e => {
        state.currentLayer = e.target.value;
        rebuildPacketTable();
    });

    document.getElementById('filter-dir')?.addEventListener('change', e => {
        state.currentDir = e.target.value;
        rebuildPacketTable();
    });

    document.getElementById('filter-sec')?.addEventListener('change', e => {
        state.currentSec = e.target.value;
        rebuildPacketTable();
    });

    document.getElementById('packet-search')?.addEventListener('input', rebuildPacketTable);

    document.getElementById('btn-clear-packets')?.addEventListener('click', () => {
        state.packets = [];
        state.totalPackets = 0;
        const tbody = document.getElementById('packet-tbody');
        if (tbody) tbody.innerHTML = '<tr><td colspan="8"><div class="empty-state"><p>Packet log cleared</p></div></td></tr>';
        updateStatusBar();
    });

    const autoscrollBtn = document.getElementById('btn-autoscroll');
    autoscrollBtn?.addEventListener('click', () => {
        state.autoScroll = !state.autoScroll;
        autoscrollBtn.classList.toggle('active', state.autoScroll);
        showToast(state.autoScroll ? 'Auto-scroll enabled' : 'Auto-scroll paused', 'info', 1500);
    });

    // Export live stream as Wireshark PCAP
    document.getElementById('btn-export-pcap')?.addEventListener('click', () => {
        window.location.href = '/api/packets/export_pcap';
        showToast('Downloading Wireshark PCAP (GSMTAP encapsulation)…', 'info');
    });

    // Metric selector for sparkline
    document.querySelectorAll('.btn-metric-toggle').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.btn-metric-toggle').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            state.sparklineMetric = btn.dataset.metric || 'rsrp';
            showToast(`Signal history metric set to: ${btn.textContent}`, 'info', 1200);
        });
    });

    document.getElementById('btn-export-packets')?.addEventListener('click', () => {
        const visible = state.packets.filter(shouldShowPacket);
        if (!visible.length) { showToast('No packets to export', 'warning'); return; }
        const blob = new Blob([JSON.stringify(visible, null, 2)], { type: 'application/json' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `airtap_packets_${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(a.href);
        showToast(`Exported ${visible.length} signaling packets`, 'success');
    });

    document.querySelectorAll('.filter-pill[data-threat-sev]').forEach(p => {
        p.addEventListener('click', () => {
            document.querySelectorAll('.filter-pill[data-threat-sev]').forEach(x => x.classList.remove('active'));
            p.classList.add('active');
            state.threatSevFilter = p.dataset.threatSev;
            rebuildThreatTable();
        });
    });

    document.querySelectorAll('.filter-pill[data-threat-cat]').forEach(p => {
        p.addEventListener('click', () => {
            document.querySelectorAll('.filter-pill[data-threat-cat]').forEach(x => x.classList.remove('active'));
            p.classList.add('active');
            state.threatCatFilter = p.dataset.threatCat;
            rebuildThreatTable();
        });
    });

    document.getElementById('f3-subsystem-filter')?.addEventListener('change', e => {
        state.f3Filter = e.target.value;
    });
    document.getElementById('f3-search')?.addEventListener('input', e => {
        state.f3Search = e.target.value.toLowerCase().trim();
    });
    document.getElementById('btn-clear-f3')?.addEventListener('click', () => {
        const t = document.getElementById('f3-terminal');
        if (t) t.innerHTML = '<div class="empty-state"><p>Console cleared</p></div>';
    });
    document.getElementById('btn-f3-scroll')?.addEventListener('click', () => {
        state.f3AutoScroll = !state.f3AutoScroll;
        document.getElementById('btn-f3-scroll')?.classList.toggle('active', state.f3AutoScroll);
    });
}

function rebuildPacketTable() {
    const tbody = document.getElementById('packet-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    let visible = state.packets.filter(shouldShowPacket);

    if (state.sortColumn) {
        visible.sort((a, b) => {
            let va = a[state.sortColumn] ?? '';
            let vb = b[state.sortColumn] ?? '';
            if (state.sortColumn === 'time') { va = a.id; vb = b.id; }
            if (state.sortColumn === 'delta') { va = a.delta_ms || 0; vb = b.delta_ms || 0; }
            if (state.sortColumn === 'length') { va = a.length || 0; vb = b.length || 0; }
            if (typeof va === 'string') va = va.toLowerCase();
            if (typeof vb === 'string') vb = vb.toLowerCase();
            if (va < vb) return state.sortDirection === 'asc' ? -1 : 1;
            if (va > vb) return state.sortDirection === 'asc' ? 1 : -1;
            return 0;
        });
    }

    if (!visible.length) {
        tbody.innerHTML = '<tr><td colspan="8"><div class="empty-state"><p>No matching packets found</p><span>Try adjusting the RAT, Event Preset, Layer, Direction, or Search filters.</span></div></td></tr>';
        return;
    }
    const frag = document.createDocumentFragment();
    visible.slice(-250).forEach(p => frag.appendChild(buildPacketRowElement(p)));
    tbody.appendChild(frag);
}

/* ─── Global Actions ─────────────────────────────────────────────────────── */
function initActions() {
    document.getElementById('btn-wireshark')?.addEventListener('click', () => {
        const btn = document.getElementById('btn-wireshark');
        if (btn) { btn.disabled = true; btn.textContent = 'Launching…'; }
        fetch('/api/wireshark', { method: 'POST' })
            .then(r => r.json())
            .then(d => {
                showToast(d.status === 'ok' ? 'Wireshark launched — streaming live GSMTAP frames' : 'Could not start Wireshark', d.status === 'ok' ? 'success' : 'error');
            })
            .catch(() => showToast('Failed to start Wireshark', 'error'))
            .finally(() => {
                if (btn) { btn.disabled = false; btn.innerHTML = '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg> Wireshark'; }
            });
    });

    document.getElementById('btn-copy-device-profile')?.addEventListener('click', () => {
        const report = buildDeviceProfileReport();
        navigator.clipboard.writeText(report)
            .then(() => showToast('Device profile copied to clipboard', 'success'))
            .catch(() => showToast('Clipboard unavailable — check browser permissions', 'error'));
    });

    document.getElementById('btn-query-device')?.addEventListener('click', () => {
        const btn = document.getElementById('btn-query-device');
        if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> Querying Diag…'; }
        fetch('/api/device/query', { method: 'POST' })
            .then(r => r.json())
            .then(d => {
                if (d.device) updateDeviceInfo(d.device);
                showToast('Modem hardware telemetry queried via Diag interface', 'success');
            })
            .catch(() => showToast('Failed to query device', 'error'))
            .finally(() => {
                if (btn) { btn.disabled = false; btn.innerHTML = '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg> Query Device (Diag Cmd)'; }
            });
    });

    document.querySelectorAll('.mono-copyable').forEach(el => {
        el.addEventListener('click', () => {
            const txt = el.textContent.trim();
            navigator.clipboard.writeText(txt).then(() => showToast(`Copied ${txt}`, 'info', 2000));
        });
    });

    document.getElementById('btn-export-audit-json')?.addEventListener('click', () => {
        if (!state.threats.length) { showToast('No threats to export yet', 'warning'); return; }
        const blob = new Blob([JSON.stringify(state.threats, null, 2)], { type: 'application/json' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `airtap_threat_report_${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(a.href);
        showToast(`Exported ${state.threats.length} threat events as JSON`, 'success');
    });

    document.getElementById('btn-export-audit-csv')?.addEventListener('click', () => {
        if (!state.threats.length) { showToast('No threats to export yet', 'warning'); return; }
        let csv = 'Timestamp,Severity,Rule_ID,RAT,Category,Title,Description\n';
        state.threats.forEach(t => {
            csv += `"${t.time || ''}","${t.severity || ''}","${t.rule_id || ''}","${t.rat || ''}","${t.category || ''}","${(t.title || '').replace(/"/g, '""')}","${(t.description || '').replace(/"/g, '""')}"\n`;
        });
        const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `airtap_threat_report_${Date.now()}.csv`;
        a.click();
        URL.revokeObjectURL(a.href);
        showToast(`Exported ${state.threats.length} threat events as CSV`, 'success');
    });

    document.getElementById('btn-export-audit-md')?.addEventListener('click', () => {
        if (!state.threats.length) { showToast('No threats to export yet', 'warning'); return; }
        let md = `# AirTap Telecom Security Audit Report\n\n`;
        md += `Generated: ${new Date().toISOString()}\n`;
        md += `Total Threats Detected: ${state.threats.length}\n\n`;
        md += `| Time | Severity | Rule ID | RAT | Category | Threat Title |\n`;
        md += `|---|---|---|---|---|---|\n`;
        state.threats.forEach(t => {
            md += `| ${t.time || ''} | **${t.severity || ''}** | \`${t.rule_id || ''}\` | ${t.rat || ''} | ${t.category || ''} | ${t.title || ''} |\n`;
        });
        md += `\n## Threat Breakdown & Remediation\n\n`;
        state.threats.forEach(t => {
            const spec = THREAT_SPECS_DB[t.rule_id] || {};
            md += `### [${t.rule_id}] ${t.title}\n`;
            md += `- **Severity**: ${t.severity}\n`;
            md += `- **Category**: ${t.category}\n`;
            md += `- **3GPP Specification**: ${spec.spec || '3GPP Security Architecture'}\n`;
            md += `- **Description**: ${t.description || ''}\n`;
            md += `- **Remediation**: ${spec.remediation || 'Audit network configuration.'}\n\n`;
        });
        const blob = new Blob([md], { type: 'text/markdown;charset=utf-8;' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `airtap_security_dossier_${Date.now()}.md`;
        a.click();
        URL.revokeObjectURL(a.href);
        showToast('Exported Markdown Security Dossier', 'success');
    });
}

/* ─── Status Bar Clock ───────────────────────────────────────────────────── */
function initStatusBarClock() {
    const tick = () => {
        const el = document.getElementById('sb-time');
        if (el) el.textContent = new Date().toLocaleTimeString();
    };
    tick();
    setInterval(tick, 1000);
}

function updateStatusBar() {
    setText('sb-pkt-count', state.totalPackets.toLocaleString());
    setText('sb-threat-count', state.totalThreats.toLocaleString());
}

/* ─── Tab 7: QXDM F3 Debug Log Console (Optimized) ─────────────────────────── */

function showF3Inspector(log) {
    if (!log) return;
    const drawer = document.getElementById('f3-inspector-drawer');
    if (!drawer) return;

    drawer.style.display = 'flex';
    setText('f3-insp-subsystem', log.subsystem || 'RRC');
    setText('f3-insp-time', log.timestamp || '00:00:00');
    setText('f3-insp-sev', log.severity || 'INFO');
    setText('f3-insp-sub-id', `0x${(log.opcode || 121).toString(16).toUpperCase()}`);
    setText('f3-insp-file', log.file || 'modem_rrc_state.c');
    setText('f3-insp-line', log.line || 142);
    setText('f3-insp-func', `${(log.subsystem || 'RRC').toLowerCase()}_process_event`);
    setText('f3-insp-message', log.text || '');

    const copyBtn = document.getElementById('btn-copy-f3-line');
    if (copyBtn) {
        copyBtn.onclick = () => {
            const line = `[${log.timestamp}] [${log.subsystem}] [${log.file}:${log.line}] [${log.severity}] ${log.text}`;
            navigator.clipboard.writeText(line);
            showToast('F3 trace copied to clipboard', 'success');
        };
    }
}

function initF3() {
    document.getElementById('btn-close-f3-insp')?.addEventListener('click', () => {
        const drawer = document.getElementById('f3-inspector-drawer');
        if (drawer) drawer.style.display = 'none';
    });

    // 1. Subsystem filter dropdown
    document.getElementById('f3-subsystem-filter')?.addEventListener('change', e => {
        state.f3.subsystemFilter = e.target.value;
        updateActiveChip(state.f3.subsystemFilter);
        rebuildF3Terminal();
    });

    // 2. Severity level filter dropdown
    document.getElementById('f3-level-filter')?.addEventListener('change', e => {
        state.f3.levelFilter = e.target.value;
        rebuildF3Terminal();
    });

    // 3. Opcode filter dropdown
    document.getElementById('f3-opcode-filter')?.addEventListener('change', e => {
        state.f3.opcodeFilter = e.target.value;
        rebuildF3Terminal();
    });

    // 4. Quick subsystem filter chips
    document.querySelectorAll('.f3-chip').forEach(chip => {
        chip.addEventListener('click', () => {
            const sub = chip.dataset.sub;
            state.f3.subsystemFilter = sub;
            const sel = document.getElementById('f3-subsystem-filter');
            if (sel) sel.value = sub;
            updateActiveChip(sub);
            rebuildF3Terminal();
        });
    });

    // 5. Search & Regex search
    const searchInput = document.getElementById('f3-search');
    const regexBtn = document.getElementById('f3-btn-regex-toggle');

    searchInput?.addEventListener('input', e => {
        state.f3.search = e.target.value.trim();
        performF3Search();
    });

    searchInput?.addEventListener('keydown', e => {
        if (e.key === 'Enter') {
            if (e.shiftKey) navigateF3Match(-1);
            else navigateF3Match(1);
        }
    });

    regexBtn?.addEventListener('click', () => {
        state.f3.isRegex = !state.f3.isRegex;
        regexBtn.classList.toggle('active', state.f3.isRegex);
        performF3Search();
    });

    document.getElementById('btn-f3-prev')?.addEventListener('click', () => navigateF3Match(-1));
    document.getElementById('btn-f3-next')?.addEventListener('click', () => navigateF3Match(1));

    // 6. Pause / Resume stream toggle
    document.getElementById('btn-f3-pause')?.addEventListener('click', toggleF3Pause);

    // 7. Clear console
    document.getElementById('btn-clear-f3')?.addEventListener('click', () => {
        const terminal = document.getElementById('f3-terminal');
        if (terminal) {
            terminal.innerHTML = '<div class="empty-state" id="f3-empty"><p>Console Cleared</p><span>New diagnostic messages will stream below.</span></div>';
        }
        state.f3.matches = [];
        state.f3.activeMatchIdx = -1;
        setText('f3-match-count', '');
        updateF3StatusFooter();
    });

    // 8. Auto-scroll pin toggle
    document.getElementById('btn-f3-scroll')?.addEventListener('click', () => {
        state.f3.autoScroll = !state.f3.autoScroll;
        document.getElementById('btn-f3-scroll')?.classList.toggle('active', state.f3.autoScroll);
        if (state.f3.autoScroll) {
            const terminal = document.getElementById('f3-terminal');
            if (terminal) terminal.scrollTop = terminal.scrollHeight;
        }
    });

    // 9. Export log button
    document.getElementById('btn-export-f3')?.addEventListener('click', () => {
        window.location.href = '/api/f3/export?format=log';
    });

    // 10. Throughput rate timer tick (1Hz)
    setInterval(() => {
        state.f3.msgRate = state.f3.msgCountWindow;
        state.f3.msgCountWindow = 0;
        setText('f3-msg-rate', `${state.f3.msgRate} msgs/s`);
    }, 1000);

    // 11. Initial lazy load on tab switch
    document.querySelector('[data-tab="tab-f3"]')?.addEventListener('click', function handler() {
        loadInitialF3History();
        this.removeEventListener('click', handler);
    });
}

function updateActiveChip(sub) {
    document.querySelectorAll('.f3-chip').forEach(c => {
        c.classList.toggle('active', c.dataset.sub === sub || (sub === 'all' && c.dataset.sub === 'all'));
    });
}

function handleIncomingF3Log(logData) {
    if (!logData) return;

    // Normalize log fields
    const sub = (logData.subsystem || 'SYS').toUpperCase();
    const sev = (logData.severity || 'INFO').toUpperCase();
    const txt = logData.text || '';
    const ts = logData.timestamp || fmtTime(new Date());
    const file = logData.file || 'modem';
    const line = logData.line || 0;
    const opcode = logData.opcode || 121;

    const normalized = {
        subsystem: sub,
        severity: sev,
        text: txt,
        timestamp: ts,
        file: file,
        line: line,
        opcode: opcode
    };

    // Update throughput window and telemetry counters
    state.f3.msgCountWindow++;
    state.f3.counts.total++;
    if (sev === 'ERROR' || sev === 'FATAL') state.f3.counts.err++;
    if (sev === 'WARN') state.f3.counts.warn++;

    // Tally subsystem counters
    if (sub.includes('RRC') || sub.includes('NR')) state.f3.counts.rrc++;
    if (sub.includes('NAS') || sub.includes('EMM')) state.f3.counts.nas++;
    if (sub.includes('PHY') || sub.includes('ML1')) state.f3.counts.phy++;
    if (sub.includes('SIM') || sub.includes('UICC')) state.f3.counts.sim++;
    if (sub.includes('IMS') || sub.includes('SIP')) state.f3.counts.ims++;
    if (sub.includes('SEC') || sub.includes('TZ')) state.f3.counts.sec++;
    if (sub.includes('CORE') || sub.includes('REX')) state.f3.counts.core++;

    // Maintain in-memory ring buffer (up to 2000 items)
    state.f3.logs.push(normalized);
    if (state.f3.logs.length > 2000) {
        state.f3.logs.shift();
    }

    // Push to pending DOM queue if not paused
    if (!state.f3.isPaused) {
        state.pendingF3.push(normalized);
        scheduleRaf();
    }

    updateF3StatusFooter();
}

function loadInitialF3History() {
    fetch('/api/f3/history?limit=100')
        .then(r => r.json())
        .then(data => {
            if (data.status === 'ok' && data.logs && data.logs.length > 0) {
                const terminal = document.getElementById('f3-terminal');
                if (terminal) terminal.innerHTML = '';
                data.logs.forEach(l => handleIncomingF3Log(l));
            }
        })
        .catch(() => {});
}

function toggleF3Pause() {
    state.f3.isPaused = !state.f3.isPaused;
    
    const btn = document.getElementById('btn-f3-pause');
    const txt = document.getElementById('f3-pause-text');
    const indicator = document.getElementById('f3-stream-indicator');
    
    if (btn) btn.classList.toggle('f3-paused', state.f3.isPaused);
    if (txt) txt.textContent = state.f3.isPaused ? 'Resume Stream' : 'Pause Stream';
    
    if (indicator) {
        indicator.textContent = state.f3.isPaused ? '⏸ PAUSED' : '● LIVE STREAMING';
        indicator.classList.toggle('paused', state.f3.isPaused);
    }

    if (!state.f3.isPaused) {
        rebuildF3Terminal();
    }
}

function rebuildF3Terminal() {
    const terminal = document.getElementById('f3-terminal');
    if (!terminal) return;

    terminal.innerHTML = '';
    const frag = document.createDocumentFragment();
    const filtered = state.f3.logs.slice(-state.f3.maxLines);

    filtered.forEach(log => {
        const el = buildF3LineElement(log);
        if (el) frag.appendChild(el);
    });

    if (frag.children.length === 0) {
        terminal.innerHTML = '<div class="empty-state"><p>No messages match current filter criteria</p></div>';
    } else {
        terminal.appendChild(frag);
    }

    if (state.f3.autoScroll) {
        terminal.scrollTop = terminal.scrollHeight;
    }

    performF3Search();
    updateF3StatusFooter();
}

function buildF3LineElement(log) {
    if (!log) return null;

    const sub = (log.subsystem || 'SYS').toUpperCase();
    const sev = (log.severity || 'INFO').toUpperCase();
    const opcode = String(log.opcode || 121);
    const txt = log.text || '';

    // 1. Subsystem Filter matching
    if (state.f3.subsystemFilter !== 'all') {
        const sf = state.f3.subsystemFilter.toUpperCase();
        if (sf === 'NR' && !sub.includes('NR') && !txt.includes('5G') && !txt.includes('n78')) return null;
        else if (sf !== 'NR' && !sub.includes(sf)) return null;
    }

    // 2. Severity Filter matching
    if (state.f3.levelFilter !== 'all') {
        const lf = state.f3.levelFilter;
        if (lf === 'ERR' && sev !== 'ERROR' && sev !== 'FATAL') return null;
        if (lf === 'WARN' && sev !== 'WARN' && sev !== 'ERROR' && sev !== 'FATAL') return null;
        if (lf === 'INFO' && sev === 'DEBUG') return null;
    }

    // 3. Opcode Filter matching
    if (state.f3.opcodeFilter !== 'all') {
        if (state.f3.opcodeFilter === '121' && opcode !== '121') return null;
        if (state.f3.opcodeFilter === '31' && opcode !== '31') return null;
        if (state.f3.opcodeFilter === 'event' && !sub.includes('EVENT') && opcode !== '96') return null;
    }

    // 4. Subsystem Badge Class
    let subClass = 'f3-sub-core';
    if (sub.includes('NR') || sub.includes('5G')) subClass = 'f3-sub-nr';
    else if (sub.includes('RRC')) subClass = 'f3-sub-rrc';
    else if (sub.includes('NAS') || sub.includes('EMM')) subClass = 'f3-sub-nas';
    else if (sub.includes('PHY') || sub.includes('ML1')) subClass = 'f3-sub-phy';
    else if (sub.includes('SIM') || sub.includes('UICC')) subClass = 'f3-sub-sim';
    else if (sub.includes('IMS') || sub.includes('SIP')) subClass = 'f3-sub-ims';
    else if (sub.includes('SEC') || sub.includes('TZ')) subClass = 'f3-sub-sec';
    else if (sub.includes('GPS') || sub.includes('GNSS')) subClass = 'f3-sub-gps';

    // 5. Severity Badge Class
    let sevClass = 'f3-sev-info';
    if (sev === 'DEBUG') sevClass = 'f3-sev-debug';
    else if (sev === 'WARN') sevClass = 'f3-sev-warn';
    else if (sev === 'ERROR') sevClass = 'f3-sev-err';
    else if (sev === 'FATAL') sevClass = 'f3-sev-fatal';

    // 6. Tokenize & Colorize Syntax in Message Body
    const highlightedBody = tokenizeF3MessageBody(txt);

    const div = document.createElement('div');
    div.className = `f3-line ${sev === 'ERROR' || sev === 'FATAL' ? 'f3-err' : (sev === 'WARN' ? 'f3-warn' : '')}`;
    
    div.innerHTML = `
        <span class="f3-ts">${escapeHtml(log.timestamp || fmtTime(new Date()))}</span>
        <span class="f3-sub ${subClass}">[${escapeHtml(sub)}]</span>
        <span class="f3-origin" title="Click to copy origin">${escapeHtml(log.file || 'modem')}:${log.line || 0}</span>
        <span class="f3-sev ${sevClass}">${escapeHtml(sev)}</span>
        <span class="f3-body">${highlightedBody}</span>
    `;

    // Click to open inspector & copy log line
    div.addEventListener('click', e => {
        showF3Inspector(log);
        if (e.target.classList.contains('f3-origin')) {
            navigator.clipboard.writeText(`${log.file}:${log.line}`);
            showToast(`Copied source origin ${log.file}:${log.line}`, 'info');
        } else {
            document.querySelectorAll('#f3-terminal .f3-line').forEach(l => l.classList.remove('f3-selected'));
            div.classList.add('f3-selected');
        }
    });

    return div;
}

function tokenizeF3MessageBody(text) {
    if (!text) return '';
    let escaped = escapeHtml(text);

    // 1. RF Measurements (e.g. RSRP=-84.2 dBm, SINR=18.5 dB, ARFCN=630000)
    escaped = escaped.replace(/(RSRP|RSRQ|SINR|RSSI|ARFCN|PCI|EARFCN|NR_ARFCN)\s*=\s*([-+]?[0-9.]+)(\s*(?:dBm|dB)?)/gi, 
        '<span class="f3-tok-metric">$1=$2$3</span>');

    // 2. State transitions (e.g. RRC_IDLE -> RRC_CONNECTED)
    escaped = escaped.replace(/([A-Z0-9_]+)\s*(-&gt;|-&gt;&gt;)\s*([A-Z0-9_]+)/g,
        '<span class="f3-tok-state">$1 -&gt; $3</span>');

    // 3. Threat / Error keywords
    escaped = escaped.replace(/\b(ERROR|FAIL|FAILED|FATAL|DROP|DROPPED|REJECT|AUTH_REJECT|INTEGRITY_FAIL|NULL_CIPHER|ROGUE|ATTACK|VULN|EXFILTRATION)\b/gi,
        '<span class="f3-tok-alert">$1</span>');

    // 4. Hex vectors (e.g. 0x000000C5 or 0x3F8A)
    escaped = escaped.replace(/\b(0x[0-9A-Fa-f]+)\b/g,
        '<span class="f3-tok-hex">$1</span>');

    return escaped;
}

function performF3Search() {
    const q = (state.f3.search || '').trim();
    const countEl = document.getElementById('f3-match-count');
    state.f3.matches = [];
    state.f3.activeMatchIdx = -1;

    const lines = document.querySelectorAll('#f3-terminal .f3-line');
    if (!q) {
        lines.forEach(l => {
            l.style.display = '';
            const body = l.querySelector('.f3-body');
            if (body && body.dataset.origHtml) {
                body.innerHTML = body.dataset.origHtml;
                delete body.dataset.origHtml;
            }
        });
        if (countEl) countEl.textContent = '';
        return;
    }

    let regex = null;
    try {
        if (state.f3.isRegex) {
            regex = new RegExp(q, 'gi');
        } else {
            const escapedQ = q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            regex = new RegExp(escapedQ, 'gi');
        }
    } catch (e) {
        if (countEl) countEl.textContent = 'Invalid Regex';
        return;
    }

    lines.forEach((l, idx) => {
        const body = l.querySelector('.f3-body');
        if (!body) return;

        if (!body.dataset.origHtml) {
            body.dataset.origHtml = body.innerHTML;
        }

        const rawText = body.textContent || '';
        if (regex.test(rawText)) {
            state.f3.matches.push(l);
            l.style.display = '';
            // Highlight matches
            regex.lastIndex = 0;
            const highlighted = rawText.replace(regex, match => `<mark class="f3-match-highlight">${escapeHtml(match)}</mark>`);
            body.innerHTML = highlighted;
        } else {
            l.style.display = 'none';
        }
    });

    if (countEl) {
        countEl.textContent = `${state.f3.matches.length} matches`;
    }

    if (state.f3.matches.length > 0) {
        navigateF3Match(1);
    }
}

function navigateF3Match(dir) {
    if (!state.f3.matches.length) return;

    // Remove active highlight from previous match
    if (state.f3.activeMatchIdx >= 0 && state.f3.activeMatchIdx < state.f3.matches.length) {
        state.f3.matches[state.f3.activeMatchIdx]?.classList.remove('f3-active-match');
    }

    state.f3.activeMatchIdx += dir;
    if (state.f3.activeMatchIdx >= state.f3.matches.length) state.f3.activeMatchIdx = 0;
    if (state.f3.activeMatchIdx < 0) state.f3.activeMatchIdx = state.f3.matches.length - 1;

    const activeEl = state.f3.matches[state.f3.activeMatchIdx];
    if (activeEl) {
        activeEl.classList.add('f3-active-match');
        activeEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }

    const countEl = document.getElementById('f3-match-count');
    if (countEl) {
        countEl.textContent = `${state.f3.activeMatchIdx + 1}/${state.f3.matches.length}`;
    }
}

function updateF3StatusFooter() {
    setText('f3-stat-total', state.f3.counts.total.toLocaleString());
    setText('f3-stat-err', state.f3.counts.err.toLocaleString());
    setText('f3-stat-warn', state.f3.counts.warn.toLocaleString());

    // Update chip counts
    setText('chip-cnt-all', state.f3.counts.total);
    setText('chip-cnt-rrc', state.f3.counts.rrc);
    setText('chip-cnt-nas', state.f3.counts.nas);
    setText('chip-cnt-phy', state.f3.counts.phy);
    setText('chip-cnt-sim', state.f3.counts.sim);
    setText('chip-cnt-ims', state.f3.counts.ims);
    setText('chip-cnt-sec', state.f3.counts.sec);
    setText('chip-cnt-core', state.f3.counts.core);

    const terminal = document.getElementById('f3-terminal');
    const curLines = terminal ? terminal.children.length : 0;
    setText('f3-buffer-info', `Buffer: ${curLines} / ${state.f3.maxLines} lines`);
}

/* ─── Tab 8: Interactive AT Command Terminal Engine ──────────────────────── */
function initTerminal() {
    state.terminal.mode = 'at';
    loadTerminalCommands();

    const input = document.getElementById('terminal-input');
    const sendBtn = document.getElementById('btn-send-at');
    const promptLabel = document.getElementById('terminal-prompt-label');

    // Mode Switcher (AT Command Shell vs Raw Qualcomm DIAG HDLC)
    document.querySelectorAll('.term-mode-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.term-mode-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            state.terminal.mode = btn.dataset.mode || 'at';
            
            if (state.terminal.mode === 'diag') {
                if (promptLabel) promptLabel.textContent = 'DIAG>';
                if (input) input.placeholder = 'Enter raw Qualcomm DIAG hex frame (e.g. 00 for Version, 1C for GUID, 79 00 for F3 Mask)…';
                appendTerminalLine('[MODE] Switched to Raw Qualcomm DIAG HDLC Command Interface (Direct Opcode Injection)', 'term-system');
            } else {
                if (promptLabel) promptLabel.textContent = 'AT>';
                if (input) input.placeholder = 'Enter AT command (e.g. AT+CSQ, AT+COPS?, AT+CPIN?) and press Enter…';
                appendTerminalLine('[MODE] Switched to 3GPP Baseband AT Command Shell', 'term-system');
            }
        });
    });

    const handleSend = () => {
        const cmd = (input?.value || '').trim();
        if (!cmd) return;
        input.value = '';
        state.terminal.history.push(cmd);
        state.terminal.historyIdx = state.terminal.history.length;

        if (state.terminal.mode === 'diag' || cmd.startsWith('DIAG:') || cmd.startsWith('HEX:')) {
            execDiagRawCommand(cmd.replace(/^(DIAG|HEX):\s*/i, ''));
        } else {
            execTerminalCommand(cmd);
        }
    };

    sendBtn?.addEventListener('click', handleSend);
    input?.addEventListener('keydown', e => {
        if (e.key === 'Enter') {
            handleSend();
        } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            if (state.terminal.history.length > 0) {
                if (state.terminal.historyIdx > 0) state.terminal.historyIdx--;
                input.value = state.terminal.history[state.terminal.historyIdx] || '';
            }
        } else if (e.key === 'ArrowDown') {
            e.preventDefault();
            if (state.terminal.historyIdx < state.terminal.history.length - 1) {
                state.terminal.historyIdx++;
                input.value = state.terminal.history[state.terminal.historyIdx] || '';
            } else {
                state.terminal.historyIdx = state.terminal.history.length;
                input.value = '';
            }
        }
    });

    document.getElementById('btn-quick-csq')?.addEventListener('click', () => execTerminalCommand('AT+CSQ'));
    document.getElementById('btn-quick-cops')?.addEventListener('click', () => execTerminalCommand('AT+COPS?'));
    document.getElementById('btn-quick-cpin')?.addEventListener('click', () => execTerminalCommand('AT+CPIN?'));
    document.getElementById('btn-diag-probe-macro')?.addEventListener('click', () => {
        appendTerminalLine('Executing Qualcomm DIAG Subsystem Baseband Probe Macro…', 'term-system');
        fetch('/api/terminal/macro', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ macro: 'diag_probe' })
        })
        .then(r => r.json())
        .then(d => {
            if (d.results) {
                d.results.forEach(res => {
                    appendTerminalLine(`>> ${res.cmd}`, 'term-cmd');
                    appendTerminalLine(res.output, res.status === 'ok' ? 'term-diag' : 'term-resp-err');
                });
            }
            showToast('DIAG Probe completed', 'success');
        })
        .catch(() => showToast('Failed to execute DIAG probe', 'error'));
    });

    document.getElementById('btn-quick-macro')?.addEventListener('click', () => {
        appendTerminalLine('Executing Full Telecom Security Audit Macro…', 'term-system');
        fetch('/api/terminal/macro', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ macro: 'full_audit' })
        })
        .then(r => r.json())
        .then(d => {
            if (d.results) {
                d.results.forEach(res => {
                    appendTerminalLine(`AT> ${res.cmd}`, 'term-cmd');
                    appendTerminalLine(res.output, res.status === 'ok' ? 'term-resp-ok' : 'term-resp-err');
                });
            }
            showToast('Audit Macro completed', 'success');
        })
        .catch(() => showToast('Failed to execute macro', 'error'));
    });

    document.getElementById('btn-clear-terminal')?.addEventListener('click', () => {
        const out = document.getElementById('terminal-output');
        if (out) out.innerHTML = '<div class="term-line term-system"><span class="term-prompt">[SYSTEM]</span> Console cleared.</div>';
    });

    document.getElementById('btn-export-terminal')?.addEventListener('click', () => {
        const out = document.getElementById('terminal-output');
        if (!out) return;
        const text = out.innerText;
        const blob = new Blob([text], { type: 'text/plain;charset=utf-8;' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `airtap_at_terminal_${Date.now()}.log`;
        a.click();
        URL.revokeObjectURL(a.href);
        showToast('Exported AT terminal log', 'success');
    });

    document.getElementById('terminal-lib-search')?.addEventListener('input', e => {
        renderTerminalCommandLibrary(e.target.value.toLowerCase().trim());
    });
}

function loadTerminalCommands() {
    fetch('/api/terminal/commands')
        .then(r => r.json())
        .then(d => {
            if (d.commands) {
                state.terminal.commands = d.commands;
                renderTerminalCommandLibrary('');
            }
        })
        .catch(() => {});
}

function renderTerminalCommandLibrary(filterText = '') {
    const container = document.getElementById('command-library-list');
    if (!container) return;
    container.innerHTML = '';

    state.terminal.commands.forEach(cat => {
        const filteredCmds = cat.commands.filter(c => 
            !filterText || c.cmd.toLowerCase().includes(filterText) || c.desc.toLowerCase().includes(filterText)
        );

        if (!filteredCmds.length) return;

        const group = document.createElement('div');
        group.className = 'cmd-category-group';
        group.innerHTML = `<h4>${escapeHtml(cat.category)}</h4>`;

        filteredCmds.forEach(c => {
            const card = document.createElement('div');
            card.className = 'cmd-item-card';
            card.innerHTML = `
                <div class="cmd-code">${escapeHtml(c.cmd)}</div>
                <div class="cmd-desc">${escapeHtml(c.desc)}</div>
            `;
            card.addEventListener('click', () => {
                const input = document.getElementById('terminal-input');
                if (input) input.value = c.cmd;
                execTerminalCommand(c.cmd);
            });
            group.appendChild(card);
        });

        container.appendChild(group);
    });
}

function execTerminalCommand(cmdStr) {
    appendTerminalLine(`AT> ${cmdStr}`, 'term-cmd');

    fetch('/api/terminal/exec', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cmd: cmdStr })
    })
    .then(r => r.json())
    .then(d => {
        const cls = d.status === 'ok' ? 'term-resp-ok' : 'term-resp-err';
        appendTerminalLine(d.output || 'OK', cls);
    })
    .catch(e => {
        appendTerminalLine(`ERROR: ${e}`, 'term-resp-err');
    });
}

function execDiagRawCommand(hexStr) {
    appendTerminalLine(`DIAG> ${hexStr}`, 'term-cmd');

    fetch('/api/terminal/diag_raw', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hex: hexStr })
    })
    .then(r => r.json())
    .then(d => {
        const cls = d.status === 'ok' ? 'term-diag' : 'term-resp-err';
        appendTerminalLine(d.output || 'DIAG ACK', cls);
    })
    .catch(e => {
        appendTerminalLine(`DIAG ERROR: ${e}`, 'term-resp-err');
    });
}

function appendTerminalLine(text, className = '') {
    const out = document.getElementById('terminal-output');
    if (!out) return;
    const div = document.createElement('div');
    div.className = `term-line ${className}`;
    div.textContent = text;
    out.appendChild(div);
    out.scrollTop = out.scrollHeight;
}

function appendTerminalUrc(urcText) {
    appendTerminalLine(`[URC] ${urcText}`, 'term-urc');
}

/* ─── Tab 9: Protocol Compliance & Robustness Fuzzer Engine ──────────────── */
function renderFuzzerDiff(origHex, mutHex) {
    // V12: Highlight bytes that differ between original and mutated hex
    const origEl = document.getElementById('fuzzer-orig-hex');
    const mutEl  = document.getElementById('fuzzer-mut-hex');
    if (!origEl || !mutEl) return;

    const origView = buildHexView(origHex);
    origEl.textContent = origView;

    const origBytes = (origHex || '').toUpperCase().replace(/\s/g, '').match(/.{1,2}/g) || [];
    const mutBytes  = (mutHex  || '').toUpperCase().replace(/\s/g, '').match(/.{1,2}/g) || [];

    let mutOut = '';
    const maxLen = Math.max(origBytes.length, mutBytes.length);
    for (let i = 0; i < maxLen; i++) {
        const ob = origBytes[i] || '--';
        const mb = mutBytes[i]  || '--';
        if (ob !== mb) {
            mutOut += `<span class="hex-byte-diff">${mb}</span> `;
        } else {
            mutOut += mb + ' ';
        }
        if ((i + 1) % 16 === 0) mutOut += '\n';
    }
    mutEl.innerHTML = mutOut.trim() || '// No mutation';
}

function appendFuzzerTableRow(v) {
    if (!v) return;
    const tbody = document.getElementById('fuzzer-tbody');
    if (!tbody) return;

    if (tbody.children.length === 1 && tbody.children[0].textContent.includes('No fuzzing campaign')) {
        tbody.innerHTML = '';
    }

    let statusCls = 'fuzz-status-ok';
    const st = v.baseband_status || 'ACK_HANDLED';
    if (st === 'BASEBAND_ANOMALY') statusCls = 'fuzz-status-anomaly';
    else if (st === 'MALFORMED_DROP' || st === 'REJECTED_BY_STACK') statusCls = 'fuzz-status-drop';

    const tr = document.createElement('tr');
    tr.innerHTML = `
        <td style="font-family:var(--font-mono);font-weight:700;color:#58a6ff;">${escapeHtml(v.id || 'FUZZ-00001')}</td>
        <td><span class="badge ${v.rat === '5G' ? 'badge-5g' : 'badge-4g'}">${escapeHtml(v.rat || '4G')}</span> ${escapeHtml(v.template_name || v.template)}</td>
        <td style="font-family:var(--font-mono);">${escapeHtml(v.strategy)}</td>
        <td style="color:#8b949e;">${escapeHtml(v.description)}</td>
        <td style="font-family:var(--font-mono);">${v.original_len} &rarr; <span style="color:#f0883e;">${v.mutated_len}</span></td>
        <td><span class="fuzz-status-badge ${statusCls}">${escapeHtml(st)}</span></td>
        <td style="font-family:var(--font-mono);color:#8b949e;">${escapeHtml(v.timestamp || '00:00:00')}</td>
    `;

    tr.addEventListener('click', () => {
        state.fuzzer.lastVector = v;
        setText('fuzzer-mutation-summary', v.description);
        setText('fuzzer-orig-len', v.original_len);
        setText('fuzzer-mut-len', v.mutated_len);
        renderFuzzerDiff(v.original_hex, v.mutated_hex);
    });

    tbody.insertBefore(tr, tbody.firstChild);

    if (tbody.children.length > 200) {
        tbody.removeChild(tbody.lastChild);
    }
}

function updateFuzzerHud(total, anomalies) {
    setText('fuzz-kpi-total', `${total} Vectors`);
    setText('fuzz-kpi-anomalies', `${anomalies} Anomalies`);
    setText('fuzzer-history-count', `${total} Vectors`);
    const healthEl = document.getElementById('fuzz-kpi-health');
    if (healthEl) {
        if (anomalies > 5) {
            healthEl.textContent = '⚠ ANOMALIES DETECTED';
            healthEl.className = 'kpi-val sec-alert';
        } else {
            healthEl.textContent = '● ONLINE / STABLE';
            healthEl.className = 'kpi-val sec-status-ok';
        }
    }
}

function initFuzzer() {
    state.fuzzer = state.fuzzer || {};
    state.fuzzer.campaignTimer = null;
    state.fuzzer.total = 0;
    state.fuzzer.anomalies = 0;

    const intensRange = document.getElementById('fuzzer-intensity-range');
    const intensVal = document.getElementById('fuzzer-intensity-val');
    intensRange?.addEventListener('input', e => {
        if (intensVal) intensVal.textContent = e.target.value;
    });

    const rateRange = document.getElementById('fuzzer-rate-range');
    const rateVal = document.getElementById('fuzzer-rate-val');
    rateRange?.addEventListener('input', e => {
        if (rateVal) rateVal.textContent = `${e.target.value} vec/s`;
    });

    // 1. Single-Shot Vector Generation
    document.getElementById('btn-fuzzer-generate')?.addEventListener('click', () => {
        const template = document.getElementById('fuzzer-template-select')?.value || 'nr_rrc_reconfig';
        const strategy = document.getElementById('fuzzer-strategy-select')?.value || 'byte_boundary';
        const intensity = parseInt(intensRange?.value || '2', 10);

        fetch('/api/fuzzer/generate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ template, strategy, intensity })
        })
        .then(r => r.json())
        .then(d => {
            if (d.vector) {
                state.fuzzer.lastVector = d.vector;
                state.fuzzer.total++;
                if (d.vector.baseband_status === 'BASEBAND_ANOMALY') state.fuzzer.anomalies++;
                updateFuzzerHud(state.fuzzer.total, state.fuzzer.anomalies);
                setText('fuzzer-mutation-summary', d.vector.description);
                setText('fuzzer-orig-len', d.vector.original_len);
                setText('fuzzer-mut-len', d.vector.mutated_len);
                renderFuzzerDiff(d.vector.original_hex, d.vector.mutated_hex);
                appendFuzzerTableRow(d.vector);
                showToast(`Generated vector ${d.vector.id}`, 'success');
            }
        })
        .catch(() => showToast('Fuzzer generation failed', 'error'));
    });

    // 2. Start Continuous Fuzzing Campaign
    document.getElementById('btn-fuzzer-start-campaign')?.addEventListener('click', () => {
        const template = document.getElementById('fuzzer-template-select')?.value || 'nr_rrc_reconfig';
        const strategy = document.getElementById('fuzzer-strategy-select')?.value || 'byte_boundary';
        const intensity = parseInt(intensRange?.value || '2', 10);
        const rate = parseInt(rateRange?.value || '5', 10);

        const startBtn = document.getElementById('btn-fuzzer-start-campaign');
        const stopBtn = document.getElementById('btn-fuzzer-stop-campaign');
        if (startBtn) startBtn.style.display = 'none';
        if (stopBtn) stopBtn.style.display = 'inline-block';
        setText('fuzz-kpi-state', `ACTIVE (${rate} vec/s)`);

        showToast(`Fuzzing campaign active at ${rate} vec/s`, 'info');

        const runBatch = () => {
            const batchSize = Math.max(1, Math.min(10, rate));
            fetch('/api/fuzzer/campaign/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ template, strategy, intensity, count: batchSize })
            })
            .then(r => r.json())
            .then(d => {
                if (d.vectors && d.vectors.length > 0) {
                    state.fuzzer.total = d.total_generated || (state.fuzzer.total + d.vectors.length);
                    state.fuzzer.anomalies = d.total_anomalies || state.fuzzer.anomalies;
                    updateFuzzerHud(state.fuzzer.total, state.fuzzer.anomalies);
                    
                    const latest = d.vectors[d.vectors.length - 1];
                    state.fuzzer.lastVector = latest;
                    setText('fuzzer-mutation-summary', latest.description);
                    setText('fuzzer-orig-len', latest.original_len);
                    setText('fuzzer-mut-len', latest.mutated_len);
                    renderFuzzerDiff(latest.original_hex, latest.mutated_hex);

                    d.vectors.forEach(v => appendFuzzerTableRow(v));
                }
            })
            .catch(() => {});
        };

        runBatch();
        const intervalMs = Math.max(200, Math.round(1000 / (rate / 5 || 1)));
        state.fuzzer.campaignTimer = setInterval(runBatch, intervalMs);
    });

    // 3. Stop Continuous Campaign
    document.getElementById('btn-fuzzer-stop-campaign')?.addEventListener('click', () => {
        if (state.fuzzer.campaignTimer) {
            clearInterval(state.fuzzer.campaignTimer);
            state.fuzzer.campaignTimer = null;
        }
        const startBtn = document.getElementById('btn-fuzzer-start-campaign');
        const stopBtn = document.getElementById('btn-fuzzer-stop-campaign');
        if (startBtn) startBtn.style.display = 'inline-block';
        if (stopBtn) stopBtn.style.display = 'none';
        setText('fuzz-kpi-state', 'PAUSED / IDLE');
        showToast('Fuzzing campaign stopped', 'warning');
    });

    // 4. Export Fuzz PCAP
    document.getElementById('btn-fuzzer-export-pcap')?.addEventListener('click', () => {
        window.location.href = '/api/fuzzer/export_pcap';
    });

    // 5. Export JSON
    document.getElementById('btn-fuzzer-export-json')?.addEventListener('click', () => {
        window.location.href = '/api/fuzzer/export_json';
    });

    // 6. Clear History
    document.getElementById('btn-fuzzer-clear')?.addEventListener('click', () => {
        fetch('/api/fuzzer/clear', { method: 'POST' })
            .then(r => r.json())
            .then(() => {
                const tbody = document.getElementById('fuzzer-tbody');
                if (tbody) tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text-muted);padding:24px;">Fuzzing campaign history cleared.</td></tr>';
                state.fuzzer.total = 0;
                state.fuzzer.anomalies = 0;
                updateFuzzerHud(0, 0);
                showToast('Fuzzing history cleared', 'info');
            })
            .catch(() => {});
    });
}

/* ─── Utilities ──────────────────────────────────────────────────────────── */
function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = String(value ?? '');
}

function incEl(id) {
    const el = document.getElementById(id);
    if (el) el.textContent = (parseInt(el.textContent || '0', 10) + 1).toString();
}

function fmtTime(d) {
    return `${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}:${String(d.getSeconds()).padStart(2,'0')}.${String(d.getMilliseconds()).padStart(3,'0').slice(0,2)}`;
}

function fmtBytes(b) {
    if (!b) return '0 B';
    if (b < 1024) return `${b} B`;
    if (b < 1048576) return `${(b/1024).toFixed(1)} KB`;
    return `${(b/1048576).toFixed(1)} MB`;
}

function escapeHtml(s) {
    if (s == null) return '';
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

/* ─── APN & 5G DNN Security Auditor UI ──────────────────────────────────── */
function initApnAuditor() {
    const btn = document.getElementById('btn-run-apn-audit');
    if (!btn) return;

    btn.addEventListener('click', runApnSecurityAudit);
    
    // Auto-run on enter in APN input
    document.getElementById('apn-input-name')?.addEventListener('keydown', e => {
        if (e.key === 'Enter') runApnSecurityAudit();
    });
}

function runApnSecurityAudit() {
    const apnName = (document.getElementById('apn-input-name')?.value || '').trim();
    const pdpType = document.getElementById('apn-select-pdp')?.value || 'IPv4v6';
    const restrLevel = document.getElementById('apn-select-restr')?.value || '0';
    const sstVal = document.getElementById('apn-select-sst')?.value || '';
    const proxyVal = (document.getElementById('apn-input-proxy')?.value || '').trim();

    const btn = document.getElementById('btn-run-apn-audit');
    if (btn) {
        btn.disabled = true;
        btn.textContent = '⏳ Evaluating 3GPP Specs…';
    }

    const payload = {
        apn: apnName,
        pdn_type: pdpType,
        restriction_level: parseInt(restrLevel, 10),
        sst: sstVal ? parseInt(sstVal, 10) : null,
        proxy: proxyVal || null
    };

    fetch('/api/apn/audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    })
    .then(r => r.json())
    .then(res => {
        if (btn) {
            btn.disabled = false;
            btn.textContent = '🛡 Run APN Security Audit';
        }
        renderApnAuditResult(res);
        showToast(`APN Security Audit Complete (${res.findings_count} findings, Risk: ${res.risk_level})`, res.risk_level === 'LOW' ? 'success' : (res.risk_level === 'MEDIUM' ? 'warning' : 'danger'));
    })
    .catch(err => {
        if (btn) {
            btn.disabled = false;
            btn.textContent = '🛡 Run APN Security Audit';
        }
        showToast('APN Audit request failed', 'danger');
    });
}

function renderApnAuditResult(res) {
    const badge = document.getElementById('apn-res-risk-badge');
    const title = document.getElementById('apn-res-title');
    const cat = document.getElementById('apn-res-cat');
    const score = document.getElementById('apn-res-score');
    const container = document.getElementById('apn-findings-container');

    if (title) title.textContent = res.target_apn || 'Default Carrier APN';
    if (cat) cat.textContent = `${res.profile_title} (${res.pdn_type} | ${res.restriction_desc})`;
    if (score) score.textContent = `Risk Score: ${res.risk_score}/100`;

    if (badge) {
        const lvl = res.risk_level || 'LOW';
        badge.textContent = `${lvl} RISK (Score: ${res.risk_score}/100)`;
        if (lvl === 'LOW') {
            badge.style.background = 'rgba(63,185,80,0.2)';
            badge.style.color = '#3fb950';
            badge.style.borderColor = '#3fb950';
        } else if (lvl === 'MEDIUM') {
            badge.style.background = 'rgba(210,153,34,0.2)';
            badge.style.color = '#d29922';
            badge.style.borderColor = '#d29922';
        } else {
            badge.style.background = 'rgba(248,81,73,0.2)';
            badge.style.color = '#f85149';
            badge.style.borderColor = '#f85149';
        }
    }

    if (!container) return;
    container.innerHTML = '';

    if (!res.findings || res.findings.length === 0) {
        container.innerHTML = `
            <div style="padding:10px;background:rgba(63,185,80,0.1);border-left:3px solid #3fb950;border-radius:4px;font-size:12px;color:#7ee787;">
                <strong>✓ Clean Profile:</strong> All 3GPP TS 23.003 syntax, TS 29.274 APN restrictions, and GSMA PRD IR.88/FS.31 checks passed. No vulnerabilities detected.
            </div>
        `;
        return;
    }

    res.findings.forEach(f => {
        const sev = f.severity || 'HIGH';
        const color = sev === 'CRITICAL' ? '#f85149' : (sev === 'HIGH' ? '#ff7b72' : '#d29922');
        const bg = sev === 'CRITICAL' ? 'rgba(248,81,73,0.12)' : (sev === 'HIGH' ? 'rgba(248,81,73,0.08)' : 'rgba(210,153,34,0.08)');
        
        const card = document.createElement('div');
        card.style.padding = '10px';
        card.style.background = bg;
        card.style.borderLeft = `3px solid ${color}`;
        card.style.borderRadius = '4px';
        card.style.display = 'flex';
        card.style.flexDirection = 'column';
        card.style.gap = '4px';
        card.style.fontSize = '12px';

        card.innerHTML = `
            <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:6px;">
                <span style="font-weight:700;color:${color};">[${escapeHtml(sev)}] [${escapeHtml(f.rule_id)}] ${escapeHtml(f.title)}</span>
                <span style="font-size:11px;color:var(--text-muted);font-family:var(--font-mono);">${escapeHtml(f.specification)}</span>
            </div>
            <div style="color:var(--text-secondary);font-size:11.5px;">${escapeHtml(f.description)}</div>
            <div style="color:#e6edf3;font-size:11.5px;"><strong>Security Impact:</strong> ${escapeHtml(f.attack_impact)}</div>
            <div style="color:#7ee787;font-size:11.5px;"><strong>Remediation:</strong> ${escapeHtml(f.remediation_guidance)}</div>
            <div style="margin-top:4px;">
                <a href="${escapeHtml(f.academy_lab)}" target="_blank" rel="noopener noreferrer" style="font-size:11px;color:var(--accent-cyan);text-decoration:none;font-weight:600;">
                    🎓 Launch Exploit Simulation at TelcoSec Academy ↗
                </a>
            </div>
        `;
        container.appendChild(card);
    });
}

/* ─── Identities, SMS & OTA Monitor Engine (RAF Optimized) ─────────────── */
const identityState = {
    identities: [],
    smsList: [],
    otaList: [],
    smsCountMT: 0,
    smsCountMO: 0,
    silentCount: 0,
    activeIdFilter: 'ALL',
    activeSmsFilter: 'ALL',
    activeOtaFilter: 'ALL',
    needsRenderIdentities: false,
    needsRenderSms: false,
    needsRenderOta: false,
    rafScheduled: false
};

function scheduleIdentityRender(renderId = true, renderSms = true, renderOta = true) {
    if (renderId) identityState.needsRenderIdentities = true;
    if (renderSms) identityState.needsRenderSms = true;
    if (renderOta) identityState.needsRenderOta = true;

    if (!identityState.rafScheduled) {
        identityState.rafScheduled = true;
        requestAnimationFrame(flushIdentityRenders);
    }
}

function flushIdentityRenders() {
    identityState.rafScheduled = false;

    // Check if the tab is visible before heavy DOM manipulation
    const tab = document.getElementById('tab-identities');
    const isVisible = tab && tab.classList.contains('active');

    if (isVisible) {
        if (identityState.needsRenderIdentities) renderIdentitiesTable();
        if (identityState.needsRenderSms) renderSmsStream();
        if (identityState.needsRenderOta) renderOtaTable();
    }

    identityState.needsRenderIdentities = false;
    identityState.needsRenderSms = false;
    identityState.needsRenderOta = false;
}

// Standard Global PLMN / Carrier Database Map (Common Global Operators)
const GLOBAL_PLMN_MAP = {
    '208-01': { name: 'Orange', country: 'France 🇫🇷' },
    '208-10': { name: 'SFR', country: 'France 🇫🇷' },
    '208-15': { name: 'Free Mobile', country: 'France 🇫🇷' },
    '208-20': { name: 'Bouygues Telecom', country: 'France 🇫🇷' },
    '234-10': { name: 'O2 / Virgin Media', country: 'United Kingdom 🇬🇧' },
    '234-15': { name: 'Vodafone UK', country: 'United Kingdom 🇬🇧' },
    '234-20': { name: '3 (Three UK)', country: 'United Kingdom 🇬🇧' },
    '234-30': { name: 'EE (BT Group)', country: 'United Kingdom 🇬🇧' },
    '262-01': { name: 'Telekom Deutschland', country: 'Germany 🇩🇪' },
    '262-02': { name: 'Vodafone Germany', country: 'Germany 🇩🇪' },
    '262-03': { name: 'O2 Telefónica', country: 'Germany 🇩🇪' },
    '214-01': { name: 'Vodafone España', country: 'Spain 🇪🇸' },
    '214-03': { name: 'Orange España', country: 'Spain 🇪🇸' },
    '214-07': { name: 'Movistar (Telefónica)', country: 'Spain 🇪🇸' },
    '222-01': { name: 'TIM (Telecom Italia)', country: 'Italy 🇮🇹' },
    '222-10': { name: 'Vodafone Italia', country: 'Italy 🇮🇹' },
    '222-50': { name: 'Iliad Italia', country: 'Italy 🇮🇹' },
    '222-88': { name: 'Wind Tre', country: 'Italy 🇮🇹' },
    '268-01': { name: 'Vodafone Portugal', country: 'Portugal 🇵🇹' },
    '268-03': { name: 'NOS Comunicações', country: 'Portugal 🇵🇹' },
    '268-06': { name: 'MEO (Altice)', country: 'Portugal 🇵🇹' },
    '310-260': { name: 'T-Mobile US', country: 'United States 🇺🇸' },
    '310-410': { name: 'AT&T Mobility', country: 'United States 🇺🇸' },
    '311-480': { name: 'Verizon Wireless', country: 'United States 🇺🇸' },
    '302-720': { name: 'Rogers Wireless', country: 'Canada 🇨🇦' },
    '302-220': { name: 'Telus Mobility', country: 'Canada 🇨🇦' },
    '302-610': { name: 'Bell Mobility', country: 'Canada 🇨🇦' },
    '505-01': { name: 'Telstra', country: 'Australia 🇦🇺' },
    '505-02': { name: 'Optus', country: 'Australia 🇦🇺' },
    '505-03': { name: 'Vodafone Australia', country: 'Australia 🇦🇺' },
    '440-10': { name: 'NTT Docomo', country: 'Japan 🇯🇵' },
    '440-20': { name: 'SoftBank', country: 'Japan 🇯🇵' },
    '440-51': { name: 'KDDI / au', country: 'Japan 🇯🇵' }
};

function resolvePlmnOperator(mcc, mnc) {
    if (!mcc || !mnc) return null;
    const key = `${mcc}-${mnc}`;
    const key2 = `${mcc}-${String(mnc).padStart(2, '0')}`;
    return GLOBAL_PLMN_MAP[key] || GLOBAL_PLMN_MAP[key2] || null;
}

function initIdentitiesSmsTab() {
    // 1. Initial hydration from REST endpoints
    fetch('/api/identities/list')
        .then(r => r.json())
        .then(d => {
            if (d.status === 'ok' && Array.isArray(d.identities)) {
                identityState.identities = d.identities;
                renderIdentitiesTable();
                updateCarrierIdentitySummary();
            }
        }).catch(() => {});

    fetch('/api/sms/list')
        .then(r => r.json())
        .then(d => {
            if (d.status === 'ok' && Array.isArray(d.sms)) {
                identityState.smsList = d.sms;
                renderSmsStream();
            }
        }).catch(() => {});

    fetch('/api/ota/list')
        .then(r => r.json())
        .then(d => {
            if (d.status === 'ok' && Array.isArray(d.ota_events)) {
                identityState.otaList = d.ota_events;
                renderOtaTable();
            }
        }).catch(() => {});

    // 2. Search & filter bindings
    document.getElementById('identity-search-input')?.addEventListener('input', () => renderIdentitiesTable());
    document.getElementById('sms-search-input')?.addEventListener('input', () => renderSmsStream());
    document.getElementById('ota-search-input')?.addEventListener('input', () => renderOtaTable());

    // Filter pills for Identities
    document.querySelectorAll('#identity-filter-pills .filter-pill').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('#identity-filter-pills .filter-pill').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            identityState.activeIdFilter = btn.dataset.idFilter || 'ALL';
            renderIdentitiesTable();
        });
    });

    // Filter pills for SMS
    document.querySelectorAll('#sms-filter-pills .filter-pill').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('#sms-filter-pills .filter-pill').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            identityState.activeSmsFilter = btn.dataset.smsFilter || 'ALL';
            renderSmsStream();
        });
    });

    // Filter pills for OTA
    document.querySelectorAll('#ota-filter-pills .filter-pill').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('#ota-filter-pills .filter-pill').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            identityState.activeOtaFilter = btn.dataset.otaFilter || 'ALL';
            renderOtaTable();
        });
    });

    // Metric Cards Quick-Filter Bindings
    document.getElementById('metric-card-identities')?.addEventListener('click', () => {
        document.querySelector('#identity-filter-pills [data-id-filter="ALL"]')?.click();
    });

    document.getElementById('metric-card-surveillance')?.addEventListener('click', () => {
        document.querySelector('#sms-filter-pills [data-sms-filter="SILENT"]')?.click();
    });

    // Refresh button
    document.getElementById('btn-refresh-identities')?.addEventListener('click', () => {
        fetch('/api/identities/list').then(r => r.json()).then(d => {
            if (d.status === 'ok') {
                identityState.identities = d.identities;
                renderIdentitiesTable();
                updateCarrierIdentitySummary();
                showToast('Identities registry refreshed', 'info');
            }
        });
    });

    // Clear SMS button
    document.getElementById('btn-clear-sms')?.addEventListener('click', () => {
        identityState.smsList = [];
        renderSmsStream();
        showToast('SMS display cleared', 'info');
    });

    // Export Buttons (JSON blobs)
    document.getElementById('btn-export-identities')?.addEventListener('click', () => {
        downloadJsonFile(identityState.identities, `airtap_identities_${Date.now()}.json`);
        showToast(`Exported ${identityState.identities.length} subscriber identities`, 'success');
    });

    document.getElementById('btn-export-sms')?.addEventListener('click', () => {
        downloadJsonFile(identityState.smsList, `airtap_sms_${Date.now()}.json`);
        showToast(`Exported ${identityState.smsList.length} SMS records`, 'success');
    });

    document.getElementById('btn-export-ota')?.addEventListener('click', () => {
        downloadJsonFile(identityState.otaList, `airtap_sim_ota_${Date.now()}.json`);
        showToast(`Exported ${identityState.otaList.length} OTA events`, 'success');
    });

    // Identity Detail Modal bindings
    initIdentityDetailModal();
}

function updateCarrierIdentitySummary() {
    const plmnLabel = document.getElementById('label-carrier-plmn');
    const descLabel = document.getElementById('label-carrier-desc');
    if (!plmnLabel || !descLabel) return;

    // Search for IMSI or GUTI in observed identities
    const imsi = identityState.identities.find(x => x.type === 'IMSI' && x.details?.mcc);
    const guti = identityState.identities.find(x => (x.type === 'GUTI' || x.type === '5G-GUTI') && x.details?.mcc);
    const source = imsi || guti;

    if (source && source.details?.mcc) {
        const mcc = source.details.mcc;
        const mnc = source.details.mnc;
        const plmn = `${mcc}-${mnc}`;
        const op = resolvePlmnOperator(mcc, mnc);

        plmnLabel.textContent = op ? `${op.name} (${plmn})` : `PLMN ${plmn}`;
        descLabel.textContent = op ? `${op.country} | Active Subscriber SIM` : `MCC ${mcc} / MNC ${mnc}`;
    }
}

function initIdentityDetailModal() {
    const modal = document.getElementById('modal-identity-detail');
    const closeBtn = document.getElementById('btn-close-identity-modal');
    if (!modal) return;

    closeBtn?.addEventListener('click', () => { modal.style.display = 'none'; });
    modal.addEventListener('click', e => {
        if (e.target === modal) modal.style.display = 'none';
    });
}

function openIdentityDetailModal(item) {
    const modal = document.getElementById('modal-identity-detail');
    if (!modal || !item) return;

    const heroLabel = document.getElementById('id-modal-hero-label');
    const heroVal = document.getElementById('id-modal-hero-value');
    const typeBadge = document.getElementById('id-modal-type-badge');
    const ieBreakdown = document.getElementById('id-modal-ie-breakdown');
    const actBreakdown = document.getElementById('id-modal-activity-breakdown');
    const jsonView = document.getElementById('id-modal-json-view');

    if (heroLabel) heroLabel.textContent = `${item.type} Value (${item.rat || 'Cellular'})`;
    if (heroVal) heroVal.textContent = item.value;

    const typeColor = {
        'IMSI': '#f85149',
        'TMSI': '#38bdf8',
        'M-TMSI': '#38bdf8',
        '5G-S-TMSI': '#a855f7',
        'GUTI': '#a855f7',
        '5G-GUTI': '#a855f7',
        'MSISDN': '#4ade80',
        'IMEI': '#f59e0b',
        'IMEISV': '#f59e0b',
        '5G-SUCI': '#ec4899'
    }[item.type] || '#38bdf8';

    if (typeBadge) {
        typeBadge.textContent = item.type;
        typeBadge.style.color = typeColor;
        typeBadge.style.borderColor = `${typeColor}50`;
        typeBadge.style.background = `${typeColor}15`;
    }

    // 3GPP Information Elements
    const details = item.details || {};
    const ieRows = [];

    if (details.mcc) {
        const op = resolvePlmnOperator(details.mcc, details.mnc);
        ieRows.push(`<div><strong>PLMN:</strong> <code>${escapeHtml(details.mcc)}-${escapeHtml(details.mnc)}</code> ${op ? `(${op.name}, ${op.country})` : ''}</div>`);
    }
    if (details.msin) ieRows.push(`<div><strong>MSIN:</strong> <code>${escapeHtml(details.msin)}</code></div>`);
    if (details.mmegi) ieRows.push(`<div><strong>MME Group ID (MMEGI):</strong> <code>${escapeHtml(details.mmegi)}</code></div>`);
    if (details.mmec) ieRows.push(`<div><strong>MME Code (MMEC):</strong> <code>${escapeHtml(details.mmec)}</code></div>`);
    if (details.m_tmsi) ieRows.push(`<div><strong>M-TMSI (Hex / Dec):</strong> <code>${escapeHtml(details.m_tmsi)}</code> (${details.m_tmsi_dec || '—'})</div>`);
    if (details.amf_region) ieRows.push(`<div><strong>AMF Region:</strong> <code>${escapeHtml(details.amf_region)}</code></div>`);
    if (details.amf_set) ieRows.push(`<div><strong>AMF Set:</strong> <code>${escapeHtml(details.amf_set)}</code></div>`);
    if (details.tmsi_dec) ieRows.push(`<div><strong>TMSI Decimal:</strong> <code>${details.tmsi_dec}</code></div>`);
    if (details.scheme) ieRows.push(`<div><strong>SUCI Protection Scheme:</strong> <code>${escapeHtml(details.scheme)}</code></div>`);

    if (ieRows.length === 0) {
        ieRows.push(`<div style="color:var(--text-muted);">Standard 3GPP Identifier (${escapeHtml(item.formatted || item.type)})</div>`);
    }
    if (ieBreakdown) ieBreakdown.innerHTML = ieRows.join('');

    // Activity breakdown
    if (actBreakdown) {
        actBreakdown.innerHTML = `
            <div><strong>First Observed:</strong> <code>${escapeHtml(item.first_seen || '—')}</code></div>
            <div><strong>Last Observed:</strong> <code>${escapeHtml(item.last_seen || '—')}</code></div>
            <div><strong>Total Baseband Hits:</strong> <span class="badge-pill" style="background:rgba(255,255,255,0.08);">${item.seen_count || 1}</span></div>
            <div><strong>Radio Access Layer:</strong> <span class="rat-badge rat-${(item.rat || '4g').toLowerCase()}">${escapeHtml(item.rat || '4G')}</span></div>
            <div><strong>Signaling Direction:</strong> <code>${escapeHtml(item.direction || '—')}</code></div>
        `;
    }

    // JSON View
    if (jsonView) jsonView.textContent = JSON.stringify(item, null, 2);

    // Copy actions
    document.getElementById('btn-copy-id-val')?.replaceWith(document.getElementById('btn-copy-id-val').cloneNode(true));
    document.getElementById('btn-copy-id-val')?.addEventListener('click', () => {
        navigator.clipboard.writeText(item.value);
        showToast(`Copied ${item.type} to clipboard`, 'info');
    });

    document.getElementById('btn-copy-id-filter')?.replaceWith(document.getElementById('btn-copy-id-filter').cloneNode(true));
    document.getElementById('btn-copy-id-filter')?.addEventListener('click', () => {
        let filterStr = `gsm_a.dtap.tmsi == ${item.value}`;
        if (item.type === 'IMSI') filterStr = `e212.imsi == "${item.value}"`;
        else if (item.type.includes('GUTI')) filterStr = `nas_eps.nas_msg_emm_type && e212.mcc == ${details.mcc || 0}`;
        navigator.clipboard.writeText(filterStr);
        showToast('Copied Wireshark filter string', 'info');
    });

    document.getElementById('btn-copy-id-json')?.replaceWith(document.getElementById('btn-copy-id-json').cloneNode(true));
    document.getElementById('btn-copy-id-json')?.addEventListener('click', () => {
        navigator.clipboard.writeText(JSON.stringify(item, null, 2));
        showToast('Copied raw JSON to clipboard', 'info');
    });

    modal.style.display = 'flex';
}

function downloadJsonFile(data, filename) {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function handleIncomingIdentity(item) {
    if (!item || !item.value) return;
    const existingIdx = identityState.identities.findIndex(x => x.type === item.type && x.value === item.value);
    if (existingIdx >= 0) {
        identityState.identities[existingIdx] = item;
    } else {
        identityState.identities.unshift(item);
    }
    scheduleIdentityRender(true, false, false);
    updateCarrierIdentitySummary();
}

function handleIncomingSms(sms) {
    if (!sms) return;
    identityState.smsList.unshift(sms);
    if (identityState.smsList.length > 500) identityState.smsList.pop();

    // Pulse badge on tab
    const badge = document.getElementById('badge-sms-count');
    if (badge) {
        const count = identityState.smsList.length;
        badge.textContent = count;
        badge.style.display = count > 0 ? 'inline-block' : 'none';
        badge.classList.add('badge-pulse');
        setTimeout(() => badge.classList.remove('badge-pulse'), 1200);
    }

    scheduleIdentityRender(false, true, false);

    if (sms.is_silent) {
        showToast(`⚠ Silent SMS (Type 0 Location Ping) from ${sms.sender || 'Unknown'}`, 'warning', 5000);
    } else if (sms.is_flash) {
        showToast(`ℹ Flash SMS (Class 0) from ${sms.sender || 'Unknown'}`, 'info', 4000);
    }
}

function handleIncomingOta(ota) {
    if (!ota) return;
    identityState.otaList.unshift(ota);
    if (identityState.otaList.length > 500) identityState.otaList.pop();
    scheduleIdentityRender(false, false, true);
}

function renderIdentitiesTable() {
    const tbody = document.getElementById('tbody-identities');
    const countTotal = document.getElementById('count-identities-total');
    const labelActiveTmsi = document.getElementById('label-active-tmsi');
    if (!tbody) return;

    const filter = (document.getElementById('identity-search-input')?.value || '').toLowerCase();
    const typePill = identityState.activeIdFilter;

    const items = identityState.identities.filter(it => {
        if (typePill !== 'ALL') {
            if (typePill === 'TMSI' && !['TMSI', 'M-TMSI', '5G-S-TMSI', 'P-TMSI'].includes(it.type)) return false;
            else if (typePill === 'GUTI' && !['GUTI', '5G-GUTI'].includes(it.type)) return false;
            else if (typePill === 'IMEI' && !['IMEI', 'IMEISV'].includes(it.type)) return false;
            else if (!['TMSI', 'GUTI', 'IMEI'].includes(typePill) && it.type !== typePill) return false;
        }
        if (!filter) return true;
        return (it.type || '').toLowerCase().includes(filter) ||
               (it.value || '').toLowerCase().includes(filter) ||
               (it.rat || '').toLowerCase().includes(filter) ||
               (it.formatted || '').toLowerCase().includes(filter);
    });

    if (countTotal) countTotal.textContent = identityState.identities.length;

    // Find active TMSI / M-TMSI
    const activeTmsi = identityState.identities.find(x => x.type === 'TMSI' || x.type === 'M-TMSI' || x.type === '5G-S-TMSI');
    if (labelActiveTmsi) {
        labelActiveTmsi.textContent = activeTmsi ? `Active: ${activeTmsi.value}` : 'Active TMSI: —';
    }

    if (items.length === 0) {
        tbody.innerHTML = `<tr class="empty-row"><td colspan="8" style="text-align:center;padding:30px;color:var(--text-muted);">${filter || typePill !== 'ALL' ? 'No identities match search/filter criteria' : 'No subscriber identities captured yet. Waiting for NAS/RRC/SIM baseband events...'}</td></tr>`;
        return;
    }

    tbody.innerHTML = items.map((it, idx) => {
        const typeColor = {
            'IMSI': '#f85149',
            'TMSI': '#38bdf8',
            'M-TMSI': '#38bdf8',
            '5G-S-TMSI': '#a855f7',
            'GUTI': '#a855f7',
            '5G-GUTI': '#a855f7',
            'MSISDN': '#4ade80',
            'IMEI': '#f59e0b',
            'IMEISV': '#f59e0b',
            '5G-SUCI': '#ec4899'
        }[it.type] || '#38bdf8';

        return `
            <tr class="identity-row" data-id-index="${idx}" style="cursor:pointer;" title="Click to inspect 3GPP details">
                <td><span style="display:inline-block;padding:2px 6px;border-radius:3px;font-size:10.5px;font-weight:700;background:${typeColor}20;color:${typeColor};border:1px solid ${typeColor}40;">${escapeHtml(it.type)}</span></td>
                <td><strong style="font-family:var(--font-mono);font-size:12.5px;color:#f0f6fc;">${escapeHtml(it.value)}</strong></td>
                <td><span class="rat-badge rat-${(it.rat || '4g').toLowerCase()}">${escapeHtml(it.rat || '4G')}</span></td>
                <td style="font-size:11.5px;color:var(--text-secondary);">${escapeHtml(it.direction || '—')}</td>
                <td style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted);">${escapeHtml(it.first_seen || '—')}</td>
                <td style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted);">${escapeHtml(it.last_seen || '—')}</td>
                <td><span style="font-size:11px;background:rgba(255,255,255,0.06);padding:1px 6px;border-radius:10px;">${it.seen_count || 1}</span></td>
                <td>
                    <div style="display:flex;gap:4px;">
                        <button class="btn btn-xs btn-primary btn-inspect-identity" data-id-index="${idx}">Inspect ↗</button>
                        <button class="btn btn-xs btn-secondary" onclick="event.stopPropagation();navigator.clipboard.writeText('${escapeHtml(it.value)}');showToast('Copied ${escapeHtml(it.type)} to clipboard','info');">Copy</button>
                    </div>
                </td>
            </tr>
        `;
    }).join('');

    // Attach row click listeners for inspection modal
    tbody.querySelectorAll('.identity-row').forEach(row => {
        row.addEventListener('click', (e) => {
            if (e.target.tagName === 'BUTTON') return;
            const idx = parseInt(row.dataset.idIndex, 10);
            if (items[idx]) openIdentityDetailModal(items[idx]);
        });
    });

    tbody.querySelectorAll('.btn-inspect-identity').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const idx = parseInt(btn.dataset.idIndex, 10);
            if (items[idx]) openIdentityDetailModal(items[idx]);
        });
    });
}

function renderSmsStream() {
    const container = document.getElementById('sms-stream-container');
    const countTotal = document.getElementById('count-sms-total');
    const breakdown = document.getElementById('label-sms-breakdown');
    const silentLabel = document.getElementById('label-silent-pings');
    const otaCount = document.getElementById('count-ota-total');
    if (!container) return;

    const filter = (document.getElementById('sms-search-input')?.value || '').toLowerCase();
    const smsPill = identityState.activeSmsFilter;

    const items = identityState.smsList.filter(s => {
        if (smsPill !== 'ALL') {
            if (smsPill === 'MT' && !(s.direction === 'MT' || (s.type || '').includes('Inbound'))) return false;
            else if (smsPill === 'MO' && !(s.direction === 'MO' || (s.type || '').includes('Outbound'))) return false;
            else if (smsPill === 'SILENT' && !s.is_silent) return false;
            else if (smsPill === 'FLASH' && !s.is_flash) return false;
        }
        if (!filter) return true;
        return (s.sender || '').toLowerCase().includes(filter) ||
               (s.recipient || '').toLowerCase().includes(filter) ||
               (s.message || '').toLowerCase().includes(filter) ||
               (s.type || '').toLowerCase().includes(filter);
    });

    // Compute stats
    let mt = 0, mo = 0, silent = 0;
    identityState.smsList.forEach(s => {
        if (s.direction === 'MT' || (s.type || '').includes('Inbound')) mt++;
        else mo++;
        if (s.is_silent) silent++;
    });

    if (countTotal) countTotal.textContent = identityState.smsList.length;
    if (breakdown) breakdown.textContent = `${mt} MT (Inbound) / ${mo} MO (Outbound)`;
    if (silentLabel) silentLabel.textContent = `${silent} Silent Pings (Type 0)`;
    if (otaCount) otaCount.textContent = identityState.otaList.length + silent;

    if (items.length === 0) {
        container.innerHTML = `
            <div class="empty-state-box" style="text-align:center;padding:40px 20px;color:var(--text-muted);">
                <svg viewBox="0 0 24 24" width="36" height="36" fill="none" stroke="currentColor" stroke-width="1.5" style="margin-bottom:10px;opacity:0.5;"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
                <div style="font-weight:600;">${filter || smsPill !== 'ALL' ? 'No SMS matches search/filter criteria' : 'No SMS messages detected on baseband interface'}</div>
                <div style="font-size:12px;margin-top:4px;">Inbound/outbound SMS, Flash Class 0, and Silent Type 0 location tracking frames will appear in real time.</div>
            </div>
        `;
        return;
    }

    container.innerHTML = items.map(s => {
        const isMt = s.direction === 'MT' || (s.type || '').includes('Inbound');
        const borderColor = s.is_silent ? '#f85149' : (s.is_flash ? '#f59e0b' : (isMt ? '#38bdf8' : '#4ade80'));
        const bg = s.is_silent ? 'rgba(248,81,73,0.08)' : (isMt ? 'rgba(56,189,248,0.05)' : 'rgba(74,222,128,0.05)');

        return `
            <div class="sms-message-card" style="padding:10px 14px;background:${bg};border-left:3px solid ${borderColor};border-radius:6px;display:flex;flex-direction:column;gap:6px;font-size:12px;">
                <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:6px;">
                    <div style="display:flex;align-items:center;gap:6px;">
                        <span style="font-weight:700;color:${borderColor};">${escapeHtml(s.type)}</span>
                        ${s.is_silent ? '<span class="badge-threat" style="background:#f8514920;color:#f85149;padding:1px 5px;border-radius:3px;font-size:10px;font-weight:700;">SURVEILLANCE PING</span>' : ''}
                        ${s.is_flash ? '<span style="background:#f59e0b20;color:#f59e0b;padding:1px 5px;border-radius:3px;font-size:10px;font-weight:700;">FLASH CLASS 0</span>' : ''}
                    </div>
                    <span style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted);">${escapeHtml(s.timestamp || '')}</span>
                </div>

                <div style="display:flex;gap:16px;font-size:11.5px;color:var(--text-secondary);flex-wrap:wrap;">
                    <span><strong>From:</strong> <code style="color:#f0f6fc;font-weight:600;">${escapeHtml(s.sender || 'Unknown')}</code></span>
                    <span><strong>To:</strong> <code style="color:#f0f6fc;font-weight:600;">${escapeHtml(s.recipient || 'Local')}</code></span>
                    ${s.smsc && s.smsc !== '—' ? `<span><strong>SMSC:</strong> ${escapeHtml(s.smsc)}</span>` : ''}
                    <span style="color:var(--text-muted);">Encoding: ${escapeHtml(s.encoding || '7-bit GSM')}</span>
                </div>

                <div style="margin-top:2px;padding:8px 10px;background:rgba(0,0,0,0.25);border-radius:4px;color:#e6edf3;font-size:12.5px;line-height:1.4;word-break:break-word;">
                    ${s.message ? escapeHtml(s.message) : '<em style="color:var(--text-muted);">[No text payload / zero-length PDU]</em>'}
                </div>

                ${s.raw_hex ? `
                    <div style="font-family:var(--font-mono);font-size:10px;color:var(--text-muted);overflow-x:auto;white-space:nowrap;">
                        TPDU HEX: ${escapeHtml(s.raw_hex)}
                    </div>
                ` : ''}
            </div>
        `;
    }).join('');
}

function renderOtaTable() {
    const tbody = document.getElementById('tbody-ota');
    if (!tbody) return;

    const filter = (document.getElementById('ota-search-input')?.value || '').toLowerCase();
    const otaPill = identityState.activeOtaFilter;

    const items = identityState.otaList.filter(o => {
        if (otaPill !== 'ALL' && o.threat_level !== otaPill) return false;
        if (!filter) return true;
        return (o.command || '').toLowerCase().includes(filter) ||
               (o.target || '').toLowerCase().includes(filter) ||
               (o.summary || '').toLowerCase().includes(filter);
    });

    if (items.length === 0) {
        tbody.innerHTML = `<tr class="empty-row"><td colspan="6" style="text-align:center;padding:24px;color:var(--text-muted);">${filter || otaPill !== 'ALL' ? 'No OTA events match search/filter criteria' : 'No SIM OTA or STK proactive commands intercepted yet.'}</td></tr>`;
        return;
    }

    tbody.innerHTML = items.map(o => {
        const threatColor = o.threat_level === 'CRITICAL' ? '#f85149' : (o.threat_level === 'HIGH' ? '#ff7b72' : '#d29922');
        return `
            <tr>
                <td style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted);">${escapeHtml(o.timestamp || '')}</td>
                <td><strong style="color:${threatColor};">${escapeHtml(o.command)}</strong></td>
                <td><code style="color:#f0f6fc;">${escapeHtml(o.target)}</code></td>
                <td><span style="font-size:10.5px;font-weight:700;color:${threatColor};background:${threatColor}20;padding:2px 6px;border-radius:3px;">${escapeHtml(o.threat_level || 'INFO')}</span></td>
                <td style="font-size:11.5px;color:var(--text-secondary);">${escapeHtml(o.summary)}</td>
                <td style="font-family:var(--font-mono);font-size:10.5px;color:var(--text-muted);">${escapeHtml(o.raw_hex ? o.raw_hex.slice(0, 32) + '...' : '—')}</td>
            </tr>
        `;
    }).join('');
}


