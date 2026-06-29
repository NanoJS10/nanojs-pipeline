import os
import time
import json
import requests
from datetime import datetime
from dotenv import load_dotenv
load_dotenv()

"""
NanoJS Master Pipeline — Integration Patch
===========================================
Drop these functions directly into nanojs_master.py.

HOW TO INTEGRATE:
─────────────────
1. Add the imports block at the TOP of nanojs_master.py
2. Add the new Phase 1 functions alongside your existing Phase 1 code
3. Add the new Phase 2 functions alongside your existing Phase 2 code
4. Call run_phase1_enrichment() inside your existing Phase 1 block
5. Call run_phase2_enrichment() inside your existing Phase 2 block
6. Update score_phase1() to include new signal weights
7. Update your Telegram alert function with new fields

Each section is clearly marked with WHERE TO ADD IT.
"""

# ═══════════════════════════════════════════════════════════════
# SECTION 1 — ADD THESE IMPORTS TO THE TOP OF nanojs_master.py
# (alongside your existing imports)
# ═══════════════════════════════════════════════════════════════

import re
import hashlib
import difflib
import xml.etree.ElementTree as ET

# OFAC cache file path (local, no subscription needed)
OFAC_CACHE_FILE = "/tmp/nanojs_ofac_cache.json"
OFAC_CACHE_TTL_HOURS = 24
OFAC_SDN_URL = "https://www.treasury.gov/ofac/downloads/sdn.xml"

# Chainabuse (free, no key required for basic lookups)
CHAINABUSE_API_KEY = os.getenv("CHAINABUSE_API_KEY", "")


# ═══════════════════════════════════════════════════════════════
# SECTION 2 — OFAC SDN SCREENING
# ADD THESE FUNCTIONS before your Phase 1 block
# ═══════════════════════════════════════════════════════════════

def _load_ofac_cache():
    """Load OFAC addresses from local cache if still fresh."""
    if os.path.exists(OFAC_CACHE_FILE):
        try:
            with open(OFAC_CACHE_FILE) as f:
                cache = json.load(f)
            age_hours = (time.time() - cache.get("fetched_at", 0)) / 3600
            if age_hours < OFAC_CACHE_TTL_HOURS:
                return set(cache.get("addresses", []))
        except Exception:
            pass
    return None


def _fetch_and_cache_ofac():
    """Download OFAC SDN XML and extract crypto addresses. Cached 24h locally."""
    print("[OFAC] Fetching SDN list from treasury.gov...")
    try:
        resp = requests.get(OFAC_SDN_URL, timeout=30)
        resp.raise_for_status()
        root = ET.fromstring(resp.content)

        # OFAC XML namespace
        ns = {"ns": "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/XML"}
        addresses = set()

        for entry in root.findall(".//ns:sdnEntry", ns):
            for id_elem in entry.findall(".//ns:id", ns):
                id_type = id_elem.findtext("ns:idType", namespaces=ns) or ""
                id_number = id_elem.findtext("ns:idNumber", namespaces=ns) or ""
                if "Digital Currency" in id_type and id_number:
                    # Strip chain prefix e.g. "ETH 0x123..." → "0x123..."
                    clean = re.sub(r'^[A-Z]+ ', '', id_number.strip()).lower()
                    addresses.add(clean)

        # Save cache
        with open(OFAC_CACHE_FILE, "w") as f:
            json.dump({"fetched_at": time.time(), "addresses": list(addresses)}, f)

        print(f"[OFAC] {len(addresses)} sanctioned crypto addresses loaded")
        return addresses

    except Exception as e:
        print(f"[OFAC] Fetch failed: {e} — skipping OFAC check")
        return set()


def check_ofac(address: str) -> bool:
    """
    Returns True if address appears on OFAC SDN list.
    Plug this into Phase 1 for deployer + known attacker wallets.
    """
    cached = _load_ofac_cache()
    addresses = cached if cached is not None else _fetch_and_cache_ofac()
    result = address.lower() in addresses
    if result:
        print(f"[OFAC] ⚠️  MATCH — {address} is on OFAC SDN list")
    return result


# ═══════════════════════════════════════════════════════════════
# SECTION 3 — CHAINABUSE LOOKUP
# ADD THESE FUNCTIONS before your Phase 1 block
# ═══════════════════════════════════════════════════════════════

def check_chainabuse(address: str) -> dict:
    """
    Query Chainabuse for scam/fraud reports on an address.
    Free tier works without API key.
    Returns dict with found (bool), report_count (int), categories (list).
    """
    url = "https://www.chainabuse.com/api/reports/search"
    headers = {"Content-Type": "application/json"}
    if CHAINABUSE_API_KEY:
        headers["Authorization"] = f"Bearer {CHAINABUSE_API_KEY}"

    try:
        resp = requests.get(url, params={"address": address}, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            reports = data.get("reports", [])
            result = {
                "found": len(reports) > 0,
                "report_count": len(reports),
                "categories": list(set(r.get("category", "unknown") for r in reports))
            }
            if result["found"]:
                print(f"[Chainabuse] ⚠️  {result['report_count']} report(s) for {address}: {result['categories']}")
            return result
    except Exception as e:
        print(f"[Chainabuse] Lookup failed for {address}: {e}")

    return {"found": False, "report_count": 0, "categories": []}


# ═══════════════════════════════════════════════════════════════
# SECTION 4 — PHASE 1 ENRICHMENT (WALLET RECON UPGRADES)
# CALL run_phase1_enrichment() inside your existing Phase 1 block
# Pass in the deployer_address your pipeline already extracts
# ═══════════════════════════════════════════════════════════════

def run_phase1_enrichment(deployer_address: str, attacker_address: str = None) -> dict:
    """
    Enriched Phase 1 checks — plugs into your existing wallet recon.

    HOW TO CALL in your existing Phase 1:
    ──────────────────────────────────────
    # After you extract deployer_address, add:
    phase1_enrichment = run_phase1_enrichment(
        deployer_address=deployer_address,
        attacker_address=attacker_address  # if known, else None
    )
    # Then pass phase1_enrichment into your scoring function

    Returns dict of new findings to merge into your existing Phase 1 results.
    """
    findings = {
        "ofac": {},
        "chainabuse": {},
        "chain_activity": {}
    }

    # ── OFAC check on deployer ──
    print(f"\n[Phase 1 Enrichment] OFAC check: {deployer_address}")
    findings["ofac"]["deployer_hit"] = check_ofac(deployer_address)

    # ── OFAC check on attacker if known ──
    if attacker_address:
        print(f"[Phase 1 Enrichment] OFAC check: {attacker_address}")
        findings["ofac"]["attacker_hit"] = check_ofac(attacker_address)

    # ── Chainabuse check on deployer ──
    print(f"[Phase 1 Enrichment] Chainabuse check: {deployer_address}")
    findings["chainabuse"]["deployer"] = check_chainabuse(deployer_address)

    # ── Chainabuse check on attacker if known ──
    if attacker_address:
        print(f"[Phase 1 Enrichment] Chainabuse check: {attacker_address}")
        findings["chainabuse"]["attacker"] = check_chainabuse(attacker_address)

    # ── Multi-chain activity check ──
    # Uses your existing Etherscan V2 key — just loops chainids
    print(f"[Phase 1 Enrichment] Multi-chain scan: {deployer_address}")
    findings["chain_activity"] = _scan_wallet_all_chains(deployer_address)

    return findings


def _scan_wallet_all_chains(address: str) -> dict:
    """
    Check wallet activity across all Etherscan V2 supported chains.
    Uses your existing ETHERSCAN_API_KEY from .env — no new keys needed.
    """
    # All chains available under your single Etherscan V2 key
    CHAIN_IDS = {
        "ethereum":  1,
        "base":      8453,
        "arbitrum":  42161,
        "optimism":  10,
        "bnb":       56,
        "polygon":   137,
        "linea":     59144,
        "scroll":    534352,
        "zksync":    324,
    }

    active_chains = {}
    api_key = os.getenv("ETHERSCAN_API_KEY")

    for chain_name, chain_id in CHAIN_IDS.items():
        try:
            resp = requests.get(
                "https://api.etherscan.io/v2/api",
                params={
                    "chainid": chain_id,
                    "module": "account",
                    "action": "txlist",
                    "address": address,
                    "startblock": 0,
                    "endblock": 99999999,
                    "sort": "asc",
                    "apikey": api_key
                },
                timeout=15
            )
            data = resp.json()
            txs = data.get("result", [])
            if isinstance(txs, list) and txs:
                active_chains[chain_name] = {
                    "tx_count": len(txs),
                    "first_tx_ts": txs[0].get("timeStamp"),
                    "last_tx_ts": txs[-1].get("timeStamp"),
                    "funded_by": txs[0].get("from")
                }
                print(f"  [{chain_name}] {len(txs)} txs found")
            time.sleep(0.2)  # respect rate limit
        except Exception as e:
            print(f"  [{chain_name}] scan failed: {e}")

    return active_chains


# ═══════════════════════════════════════════════════════════════
# SECTION 5 — BYTECODE FINGERPRINTING + OWNERSHIP TIMING
# ADD THESE FUNCTIONS before your Phase 2 block
# ═══════════════════════════════════════════════════════════════

# Known dangerous function selectors found in scam bytecode
DANGEROUS_SELECTORS = {
    "a9059cbb": "transfer()",
    "23b872dd": "transferFrom()",
    "f2fde38b": "transferOwnership()",
    "715018a6": "renounceOwnership()",
    # Rug/drain patterns
    "setFee":        "fee_setter_function",
    "blacklist":     "blacklist_function",
    "excludeFromFee":"fee_exclusion",
    "setMaxTx":      "max_tx_limiter",
    "setTaxFee":     "dynamic_tax",
    "swapAndLiquify":"auto_liquidity_trap",
}

def fingerprint_bytecode(bytecode: str) -> dict:
    """
    Analyze contract bytecode for rug/scam patterns.
    Plugs into Phase 2 — especially useful for unverified contracts
    which your pipeline already handles via Dedaub fallback.

    HOW TO CALL in your existing Phase 2:
    ──────────────────────────────────────
    # After your bytecode fetch, add:
    bytecode_analysis = fingerprint_bytecode(bytecode)
    # Merge into your Phase 2 findings
    """
    if not bytecode or bytecode in ("0x", "0x0", ""):
        return {"is_contract": False, "flags": [], "high_risk": False}

    clean = bytecode.lower().replace("0x", "")
    flags = []

    for selector, label in DANGEROUS_SELECTORS.items():
        if selector.lower() in clean:
            flags.append(label)

    # Hash for reference and future database matching
    bytecode_hash = hashlib.sha256(clean.encode()).hexdigest()[:16]

    result = {
        "is_contract": True,
        "bytecode_hash": bytecode_hash,
        "bytecode_length": len(clean),
        "flags": flags,
        "flag_count": len(flags),
        # 3+ flags = high risk (aligns with your existing threshold logic)
        "high_risk": len(flags) >= 3
    }

    if result["high_risk"]:
        print(f"[Bytecode] ⚠️  HIGH RISK — {len(flags)} flags: {flags}")
    elif flags:
        print(f"[Bytecode] Flags detected: {flags}")

    return result


def analyze_ownership_timing(contract_address: str, chain_key: str = "ethereum") -> dict:
    """
    Checks if ownership was renounced and how quickly after deployment.
    Rapid renouncement (< 48h) after launch is a common rug setup.

    HOW TO CALL in your existing Phase 2:
    ──────────────────────────────────────
    ownership = analyze_ownership_timing(contract_address, chain_key)
    # Merge into Phase 2 findings
    """
    CHAIN_IDS = {
        "ethereum": 1, "base": 8453, "arbitrum": 42161,
        "optimism": 10, "bnb": 56, "bsc": 56
    }
    chain_id = CHAIN_IDS.get(chain_key.lower(), 1)
    api_key = os.getenv("ETHERSCAN_API_KEY")

    # renounceOwnership() 4-byte selector
    RENOUNCE_SIG = "0x715018a6"

    try:
        resp = requests.get(
            "https://api.etherscan.io/v2/api",
            params={
                "chainid": chain_id,
                "module": "account",
                "action": "txlist",
                "address": contract_address,
                "startblock": 0,
                "endblock": 99999999,
                "sort": "asc",
                "apikey": api_key
            },
            timeout=15
        )
        txs = resp.json().get("result", [])
        if not isinstance(txs, list):
            return {"ownership_renounced": False, "error": "no_txs"}

        deploy_ts = int(txs[0].get("timeStamp", 0)) if txs else None
        renounce_ts = None
        renounce_tx = None

        for tx in txs:
            if tx.get("input", "").startswith(RENOUNCE_SIG):
                renounce_ts = int(tx.get("timeStamp", 0))
                renounce_tx = tx.get("hash")
                break

        result = {
            "deploy_timestamp": deploy_ts,
            "renounce_timestamp": renounce_ts,
            "renounce_tx_hash": renounce_tx,
            "ownership_renounced": renounce_ts is not None,
        }

        if deploy_ts and renounce_ts:
            gap_hours = (renounce_ts - deploy_ts) / 3600
            result["hours_to_renounce"] = round(gap_hours, 2)
            result["rapid_renounce_flag"] = gap_hours < 48
            if result["rapid_renounce_flag"]:
                print(f"[Ownership] ⚠️  Renounced {gap_hours:.1f}h after deploy — rug signal")

        return result

    except Exception as e:
        print(f"[Ownership] Analysis failed: {e}")
        return {"ownership_renounced": False, "error": str(e)}


def run_phase2_enrichment(contract_address: str, bytecode: str, chain_key: str = "ethereum") -> dict:
    """
    Enriched Phase 2 checks — plugs into your existing contract vuln phase.

    HOW TO CALL in your existing Phase 2:
    ──────────────────────────────────────
    # After your bytecode fetch, add:
    phase2_enrichment = run_phase2_enrichment(
        contract_address=contract_address,
        bytecode=bytecode,  # already fetched by your pipeline
        chain_key=chain_key
    )

    Returns dict of new findings to merge into your Phase 2 results.
    """
    return {
        "bytecode_analysis": fingerprint_bytecode(bytecode),
        "ownership_timing":  analyze_ownership_timing(contract_address, chain_key)
    }


# ═══════════════════════════════════════════════════════════════
# SECTION 6 — SCORING ADDITIONS
# ADD these score values into your existing score_phase1() function
# ═══════════════════════════════════════════════════════════════

def score_phase1_enrichment(phase1_enrichment: dict) -> int:
    """
    Returns additional score points from Phase 1 enrichment.
    ADD this to your existing Phase 1 score total.

    HOW TO USE in your existing scoring:
    ─────────────────────────────────────
    existing_phase1_score = your_existing_score_function(...)
    bonus = score_phase1_enrichment(phase1_enrichment)
    final_phase1_score = min(existing_phase1_score + bonus, 100)
    """
    bonus = 0

    ofac = phase1_enrichment.get("ofac", {})
    if ofac.get("deployer_hit"):
        bonus += 40   # OFAC hit on deployer = near-automatic critical
    if ofac.get("attacker_hit"):
        bonus += 40

    ca = phase1_enrichment.get("chainabuse", {})
    deployer_ca = ca.get("deployer", {})
    attacker_ca = ca.get("attacker", {})
    if deployer_ca.get("found"):
        bonus += min(deployer_ca["report_count"] * 5, 20)
    if attacker_ca.get("found"):
        bonus += min(attacker_ca["report_count"] * 5, 20)

    chain_activity = phase1_enrichment.get("chain_activity", {})
    if len(chain_activity) > 4:
        bonus += 5   # Active across many chains = coordinated actor signal

    return min(bonus, 60)   # Cap enrichment bonus at 60 points


def score_phase2_enrichment(phase2_enrichment: dict) -> int:
    """
    Returns additional score points from Phase 2 enrichment.
    ADD this to your existing Phase 2 score total.
    """
    bonus = 0

    bc = phase2_enrichment.get("bytecode_analysis", {})
    if bc.get("high_risk"):
        bonus += 15
    elif bc.get("flags"):
        bonus += 8

    ot = phase2_enrichment.get("ownership_timing", {})
    if ot.get("rapid_renounce_flag"):
        bonus += 10

    return min(bonus, 25)


# ═══════════════════════════════════════════════════════════════
# SECTION 7 — TELEGRAM ALERT UPGRADE
# REPLACE or EXTEND your existing Telegram send function
# ═══════════════════════════════════════════════════════════════

def build_enriched_telegram_message(
    case_id: str,
    contract_address: str,
    risk_score: int,
    risk_level: str,
    critical_findings: list,
    high_findings: list,
    phase1_enrichment: dict,
    phase2_enrichment: dict,
    chain: str = "Ethereum"
) -> str:
    """
    Builds an enriched Telegram alert message.
    Extends your existing alert with new OFAC/Chainabuse/bytecode fields.

    HOW TO USE:
    ───────────
    Replace your existing message string with:
    msg = build_enriched_telegram_message(
        case_id=case_id,
        contract_address=contract_address,
        risk_score=final_score,
        risk_level=risk_level,
        critical_findings=critical_findings,
        high_findings=high_findings,
        phase1_enrichment=phase1_enrichment,
        phase2_enrichment=phase2_enrichment,
        chain=chain
    )
    # Then send msg using your existing Telegram send code
    """
    level_emoji = {"CRITICAL": "🚨", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}
    emoji = level_emoji.get(risk_level, "⚪")

    # Build findings lines (your existing logic)
    findings_lines = ""
    for f in critical_findings:
        findings_lines += f"\n  🔴 CRITICAL: {f}"
    for f in high_findings:
        findings_lines += f"\n  🟡 HIGH: {f}"

    # New enrichment lines
    enrichment_lines = ""

    ofac = phase1_enrichment.get("ofac", {})
    if ofac.get("deployer_hit") or ofac.get("attacker_hit"):
        enrichment_lines += "\n  ⛔ OFAC SDN MATCH DETECTED"

    ca = phase1_enrichment.get("chainabuse", {})
    dep_ca = ca.get("deployer", {})
    if dep_ca.get("found"):
        enrichment_lines += f"\n  📋 Chainabuse: {dep_ca['report_count']} report(s)"

    bc = phase2_enrichment.get("bytecode_analysis", {})
    if bc.get("flags"):
        enrichment_lines += f"\n  🔬 Bytecode flags: {', '.join(bc['flags'][:3])}"

    ot = phase2_enrichment.get("ownership_timing", {})
    if ot.get("rapid_renounce_flag"):
        enrichment_lines += f"\n  ⏱ Ownership renounced {ot.get('hours_to_renounce')}h post-deploy"

    chains_active = list(phase1_enrichment.get("chain_activity", {}).keys())
    if chains_active:
        enrichment_lines += f"\n  🌐 Active chains: {', '.join(chains_active)}"

    msg = (
        f"{emoji} *NanoJS Alert — {risk_level}*\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"*Case:* `{case_id}`\n"
        f"*Contract:* `{contract_address}`\n"
        f"*Chain:* {chain}\n"
        f"*Risk Score:* {risk_score}/100\n"
        f"\n*Findings:*{findings_lines}"
        f"\n\n*Enrichment:*{enrichment_lines if enrichment_lines else chr(10) + '  None'}\n"
        f"\n— NanoJS10 | github.com/NanoJS10"
    )
    return msg


# ═══════════════════════════════════════════════════════════════
# SECTION 8 — JSON REPORT EXTENSION
# EXTEND your existing save_report() function
# ═══════════════════════════════════════════════════════════════

def extend_detection_report(existing_report: dict,
                             phase1_enrichment: dict,
                             phase2_enrichment: dict) -> dict:
    """
    Merges new enrichment findings into your existing detection report dict
    before you save it as CaseID_detection_report.json.

    HOW TO USE:
    ───────────
    # Before your existing json.dump() call, add:
    detection_report = extend_detection_report(
        existing_report=detection_report,
        phase1_enrichment=phase1_enrichment,
        phase2_enrichment=phase2_enrichment
    )
    # Then save as normal
    """
    existing_report["phase1_enrichment"] = phase1_enrichment
    existing_report["phase2_enrichment"] = phase2_enrichment
    existing_report["enrichment_timestamp"] = datetime.utcnow().isoformat()

    # Add top-level OFAC flag for quick filtering
    ofac = phase1_enrichment.get("ofac", {})
    existing_report["ofac_hit"] = ofac.get("deployer_hit", False) or ofac.get("attacker_hit", False)

    # Add top-level Chainabuse flag
    ca = phase1_enrichment.get("chainabuse", {})
    existing_report["chainabuse_reported"] = (
        ca.get("deployer", {}).get("found", False) or
        ca.get("attacker", {}).get("found", False)
    )

    return existing_report


# ═══════════════════════════════════════════════════════════════
# SECTION 9 — FULL INTEGRATION EXAMPLE
# This shows exactly how your existing nanojs_master.py main()
# should look after adding everything above
# ═══════════════════════════════════════════════════════════════

"""
EXAMPLE — how your main() or run_scan() function should look:

def run_scan(contract_address, chain_key, case_id):

    # ── Your existing Step 1 (unchanged) ──
    scan_results = run_vulnerability_scanner(contract_address, chain_key)

    # ── Your existing Phase 1 start ──
    deployer_address = get_deployer(contract_address, chain_key)
    attacker_address = get_attacker(contract_address, chain_key)  # if known

    # ── NEW: Phase 1 enrichment (add this) ──
    phase1_enrichment = run_phase1_enrichment(deployer_address, attacker_address)
    phase1_base_score  = your_existing_phase1_score(deployer_address, chain_key)
    phase1_bonus       = score_phase1_enrichment(phase1_enrichment)
    phase1_score       = min(phase1_base_score + phase1_bonus, 100)

    # ── Your existing Phase 2 start ──
    bytecode = get_bytecode(contract_address, chain_key)  # already in your pipeline
    phase2_base_findings = your_existing_phase2(contract_address, bytecode)

    # ── NEW: Phase 2 enrichment (add this) ──
    phase2_enrichment = run_phase2_enrichment(contract_address, bytecode, chain_key)
    phase2_base_score = your_existing_phase2_score(phase2_base_findings)
    phase2_bonus      = score_phase2_enrichment(phase2_enrichment)
    phase2_score      = min(phase2_base_score + phase2_bonus, 100)

    # ── Your existing Phase 3 + 4 (unchanged) ──
    phase3_score = run_phase3(contract_address, chain_key)
    phase4_score = run_phase4(contract_address, chain_key)

    # ── Final score (your existing weights, unchanged) ──
    final_score = (
        phase1_score * 0.30 +
        phase2_score * 0.25 +
        phase3_score * 0.25 +
        phase4_score * 0.20
    )

    # ── Your existing detection_report dict ──
    detection_report = build_detection_report(...)

    # ── NEW: Extend report with enrichment (add this) ──
    detection_report = extend_detection_report(
        detection_report, phase1_enrichment, phase2_enrichment
    )

    # ── Save report (your existing code, unchanged) ──
    save_report(detection_report, case_id)

    # ── NEW: Enriched Telegram alert (replace your existing message) ──
    if final_score >= 40:
        msg = build_enriched_telegram_message(
            case_id=case_id,
            contract_address=contract_address,
            risk_score=int(final_score),
            risk_level=get_risk_level(final_score),
            critical_findings=scan_results.get("critical", []),
            high_findings=scan_results.get("high", []),
            phase1_enrichment=phase1_enrichment,
            phase2_enrichment=phase2_enrichment,
            chain=chain_key
        )
        send_telegram(msg)  # your existing send function
"""
"""
NanoJS — Chainabuse Update Patch
==================================
Replace your existing check_chainabuse() and run_phase1_enrichment()
in nanojs_master_integration_patch.py with these versions.

Change: Chainabuse only triggers when preliminary score >= 40
(HIGH or CRITICAL) to conserve the 10 calls/month free tier limit.
"""


# ═══════════════════════════════════════════════════════════════
# UPDATED check_chainabuse()
# Replace the old version in nanojs_master_integration_patch.py
# ═══════════════════════════════════════════════════════════════

def check_chainabuse(address: str, preliminary_score: int = 0, threshold: int = 40) -> dict:
    """
    Query Chainabuse for scam/fraud reports on an address.

    Only fires when preliminary_score >= threshold (default: 40).
    This conserves your 10 free calls/month for real suspects only.

    Authentication: Basic Auth — pass your API key as both
    username AND password (Chainabuse's requirement).

    Args:
        address:           Target wallet or contract address
        preliminary_score: Your pipeline's current score before enrichment
        threshold:         Minimum score to trigger lookup (default: 40 = HIGH)

    Returns:
        dict with keys: found, report_count, categories, skipped
    """
    # Skip if score below threshold — preserve free tier calls
    if preliminary_score < threshold:
        print(f"[Chainabuse] Score {preliminary_score} < {threshold} threshold — skipping to preserve API calls")
        return {
            "found": False,
            "report_count": 0,
            "categories": [],
            "skipped": True,
            "skip_reason": f"score_{preliminary_score}_below_threshold_{threshold}"
        }

    print(f"[Chainabuse] Score {preliminary_score} >= {threshold} — running lookup for {address}")

    # Correct endpoint from official docs
    url = "https://docs.chainabuse.com/reference/reports-1"
    api_url = "https://api.chainabuse.com/v0/reports"

    api_key = os.getenv("CHAINABUSE_API_KEY", "")

    try:
        resp = requests.get(
            api_url,
            params={"address": address},
            # Basic Auth: API key in both username and password fields
            auth=(api_key, api_key) if api_key else None,
            timeout=10
        )

        if resp.status_code == 401:
            print("[Chainabuse] ⚠️  Auth failed — check CHAINABUSE_API_KEY in .env")
            return {"found": False, "report_count": 0, "categories": [], "skipped": False, "error": "auth_failed"}

        if resp.status_code == 429:
            print("[Chainabuse] ⚠️  Rate limit hit — 10 calls/month exceeded")
            return {"found": False, "report_count": 0, "categories": [], "skipped": False, "error": "rate_limit"}

        if resp.status_code == 200:
            data = resp.json()
            reports = data.get("reports", [])
            result = {
                "found": len(reports) > 0,
                "report_count": len(reports),
                "categories": list(set(r.get("category", "unknown") for r in reports)),
                "skipped": False,
                "error": None
            }
            if result["found"]:
                print(f"[Chainabuse] ⚠️  {result['report_count']} report(s): {result['categories']}")
            else:
                print(f"[Chainabuse] No reports found for {address}")
            return result

    except Exception as e:
        print(f"[Chainabuse] Lookup failed: {e}")

    return {"found": False, "report_count": 0, "categories": [], "skipped": False, "error": "request_failed"}


# ═══════════════════════════════════════════════════════════════
# UPDATED run_phase1_enrichment()
# Replace the old version in nanojs_master_integration_patch.py
# Now accepts preliminary_score to gate Chainabuse calls
# ═══════════════════════════════════════════════════════════════

def run_phase1_enrichment(deployer_address: str,
                          attacker_address: str = None,
                          preliminary_score: int = 0) -> dict:
    """
    Enriched Phase 1 checks with Chainabuse score gate.

    HOW TO CALL in your existing Phase 1:
    ──────────────────────────────────────
    # Compute your base Phase 1 score first, then pass it in:

    phase1_base_score = your_existing_phase1_score(deployer_address, chain_key)

    phase1_enrichment = run_phase1_enrichment(
        deployer_address=deployer_address,
        attacker_address=attacker_address,   # or None
        preliminary_score=phase1_base_score  # gates Chainabuse calls
    )

    phase1_bonus = score_phase1_enrichment(phase1_enrichment)
    phase1_score = min(phase1_base_score + phase1_bonus, 100)
    """
    findings = {
        "ofac": {},
        "chainabuse": {},
        "chain_activity": {}
    }

    # ── OFAC — always runs (free, local cache, no call limit) ──
    print(f"\n[Phase 1 Enrichment] OFAC check: {deployer_address}")
    findings["ofac"]["deployer_hit"] = check_ofac(deployer_address)

    if attacker_address:
        print(f"[Phase 1 Enrichment] OFAC check: {attacker_address}")
        findings["ofac"]["attacker_hit"] = check_ofac(attacker_address)

    # ── Chainabuse — only runs if preliminary_score >= 40 ──
    print(f"[Phase 1 Enrichment] Chainabuse check: {deployer_address}")
    findings["chainabuse"]["deployer"] = check_chainabuse(
        address=deployer_address,
        preliminary_score=preliminary_score,
        threshold=40
    )

    if attacker_address:
        print(f"[Phase 1 Enrichment] Chainabuse check: {attacker_address}")
        findings["chainabuse"]["attacker"] = check_chainabuse(
            address=attacker_address,
            preliminary_score=preliminary_score,
            threshold=40
        )

    # ── Multi-chain activity — always runs (uses existing free API key) ──
    print(f"[Phase 1 Enrichment] Multi-chain scan: {deployer_address}")
    findings["chain_activity"] = _scan_wallet_all_chains(deployer_address)

    return findings


# ═══════════════════════════════════════════════════════════════
# HOW THE FLOW NOW WORKS
# ═══════════════════════════════════════════════════════════════

"""
CALL ORDER in your main run_scan():

1. Run your existing Phase 1 → get phase1_base_score
2. Pass phase1_base_score into run_phase1_enrichment()
3. Chainabuse only fires if phase1_base_score >= 40

Score < 40 (LOW/MEDIUM):
  ✅ OFAC check runs     (free, cached)
  ✅ Multi-chain runs    (free, existing key)
  ⏭  Chainabuse skipped  (preserves monthly calls)

Score >= 40 (HIGH/CRITICAL):
  ✅ OFAC check runs
  ✅ Multi-chain runs
  ✅ Chainabuse runs     (spends 1 of your 10 monthly calls)

This means your 10 free Chainabuse calls/month go only to
contracts that already scored HIGH or CRITICAL on your
existing 4-phase pipeline — exactly where they matter.
"""
