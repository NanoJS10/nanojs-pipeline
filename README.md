# NanoJS Investigations Pipeline

**Pre-execution blockchain threat detection. Built by a forensic investigator, for investigators.**

> "Data on the blockchain is permanent — analysis makes it powerful."

---

## What This Is

NanoJS is an open-source forensic pipeline that detects malicious smart contracts before exploitation occurs. It combines static vulnerability analysis, on-chain behavioral forensics, wallet clustering, and multi-source threat intelligence into a single automated scan.

Built and battle-tested across real investigations:

| Case | Type | Outcome |
|------|------|---------|
| NanoJS-FixerSell01 | Rugpull (active presale) | GitHub takedown x3, CoinTelegraph notified |
| NanoJS-PhishFactory01 | USDM impersonation (59-day pre-staging) | Responsible disclosure to @MountainUSDM |
| NanoJS-OpalVault01 | LayerZero OwnableOFT staging | Under investigation — update pending |
| NanoJS02 Zunami | $2.1M flash loan manipulation | Rekt News Chain of Evidence category |
| NanoJS01 MerlinDEX | $1.82M insider rug (zkSync Era) | MEXC account freeze confirmed |

---

## How It Works

```
Contract Address
      |
      v
+-----------------------------+
|  STEP 1: Vulnerability Scan |  <- Source code + bytecode analysis
|  7 detectors, 60-80% conf.  |     Reentrancy, flash loan oracle,
|  PoC Solidity generation    |     access control, SELFDESTRUCT
+-------------+---------------+
              |
              v
+-----------------------------+
|  STEP 2: Deep Forensic Scan |
|                             |
|  Phase 1 - Wallet Recon     |  <- Deployer age, mixer funding,
|  Phase 2 - Contract Vulns   |     throwaway wallet detection
|  Phase 3 - On-Chain Anomaly |  <- Gas spikes, flash loan sigs,
|  Phase 4 - Laundering       |     MAX_UINT256 approvals
|  Phase 5 - Enrichment (NEW) |  <- OFAC SDN, Chainabuse, bytecode
|                             |     fingerprinting, multi-chain scan
+-------------+---------------+
              |
              v
+-----------------------------+
|  STEP 3: Report Generation  |  <- Word + JSON forensic reports
|  STEP 4: Telegram Alert     |  <- Fires at score >= 40
+-----------------------------+
```

---

## Risk Scoring

```
Phase 1 (Wallet Recon):      30% weight
Phase 2 (Contract Vulns):    25% weight
Phase 3 (On-Chain Anomaly):  25% weight
Phase 4 (Laundering):        20% weight
+ Enrichment bonus (OFAC, Chainabuse, bytecode)

Score 0-19:   LOW RISK
Score 20-39:  MEDIUM RISK
Score 40-69:  HIGH RISK
Score 70-100: CRITICAL RISK
```

---

## Detection Capability

The pipeline is designed to catch the following threat categories:

| Threat Type | Detection Method |
|-------------|-----------------|
| Rugpull — presale drain | Blacklist/dynamic fee functions in bytecode, throwaway deployer wallet |
| Phishing deployment | Token name impersonation, pre-staging timing analysis |
| Flash loan price manipulation | Single AMM oracle, no Chainlink fallback, large same-block withdrawal |
| Mixer-funded deployer | Tornado Cash funding chain traced via Phase 1 wallet recon |
| Insider exploit | Deployer/attacker shared funding source detection |
| Cross-chain laundering | Multi-chain wallet scan across 9 chains, bridge/mixer outflow detection |
| Unaudited DeFi contracts | 30-180 day age window scan, no audit keyword check |
| Sanctioned wallets | OFAC SDN list screening on deployer and attacker addresses |
| Known scam addresses | Chainabuse community report lookup (fires at score >= 40) |
| Rapid ownership renouncement | Flags contracts renounced within 48h of deployment |

---

## Enrichment Modules (v2.0)

Added in v2.0  all free, no paid subscriptions required:

- **OFAC SDN Screening**  checks deployer/attacker wallets against US Treasury sanctions list. Cached locally for 24h. No API key needed.
- **Chainabuse Lookup**  queries community scam reports. Only fires when base score >= 40 to conserve free tier (10 calls/month).
- **Bytecode Fingerprinting** detects dangerous function selectors (blacklist, dynamic fee drain, transferOwnership) in unverified contracts.
- **Ownership Renouncement Timing**  flags contracts where ownership was renounced within 48h of deployment (classic rug setup signal).
- **Multi-Chain Wallet Scan** traces deployer/attacker activity across 9 chains using a single Etherscan V2 key.

---

## Chains Supported

All via single Etherscan V2 API key no separate registrations needed:

| Chain | Chain ID |
|-------|----------|
| Ethereum Mainnet | 1 |
| Base | 8453 |
| Arbitrum One | 42161 |
| Optimism | 10 |
| BNB Chain | 56 |
| Polygon | 137 |
| Linea | 59144 |
| Scroll | 534352 |
| zkSync Era | 324 |

---

## Installation

**Requirements:** Python 3.10+, Ubuntu/Debian recommended

```bash
git clone https://github.com/NanoJS10/nanojs-pipeline
cd nanojs-pipeline
pip3 install requests python-dotenv web3 python-docx
cp .env.example .env
# Fill in your API keys in .env
```

---

## Configuration

Copy `.env.example` to `.env` and fill in your keys:

```
ETHERSCAN_API_KEY=your_key_here
TELEGRAM_BOT_TOKEN=your_token_here
TELEGRAM_CHAT_ID=your_chat_id_here
CHAINABUSE_API_KEY=your_key_here
WEB3_RPC_URL=https://mainnet.infura.io/v3/your_key
```

Get free API keys:
- Etherscan V2: etherscan.io/apis
- Chainabuse: chainabuse.com -> Profile -> Settings -> API Key
- Telegram Bot: message @BotFather -> /newbot

> **Note on Etherscan API V2:** This pipeline uses the Etherscan V2 unified
> endpoint (api.etherscan.io/v2/api) with a chainid parameter. A single V2
> API key covers all 9 supported chains. The old V1 per-chain endpoints
> (api.bscscan.com, api.basescan.org etc.) are not used and separate
> registrations are not required. If you have an existing V1 key, it works
> on V2 without changes.

---

## Usage

**Manual scan (specific contract):**
```bash
python3 nanojs_master.py \
  --contract 0xCONTRACT_ADDRESS \
  --chain Ethereum \
  --case NanoJS-CaseID \
  --alert
```

**Auto-discovery (runs forever, new contracts):**
```bash
nohup python3 nanojs_autodiscovery.py \
  --chain Ethereum \
  --blocks 50 \
  > forensic_logs/discovery.log 2>&1 &
```

**Existing unaudited contracts (30-180 days old):**
```bash
python3 nanojs_existing_scanner.py \
  --chain Ethereum \
  --min-age 90 \
  --max-age 180
```

**Check running scans:**
```bash
ps aux | grep python3
tail -f forensic_logs/discovery.log
```

---

## Output

Every scan produces three files:

```
reports/NanoJS-CaseID_detection_report.json  <- Machine-readable forensic data
NanoJS-DATE_Disclosure_Report.docx           <- Publication-ready Word report (root folder)
forensic_logs/NanoJS-CaseID_forensic.log     <- Full scan log
```

The Word report includes:
- Cover page with case ID, date, chain, classification
- Executive summary with severity table
- Detailed findings with exact line numbers
- On-chain evidence
- Remediation recommendations
- PoC Solidity contracts
- 90-day disclosure timeline
- NanoJS investigator signature

---

## File Structure

```
nanojs-pipeline/
+-- nanojs_master.py              <- Main pipeline (4 steps + enrichment)
+-- nanojs_enrichment.py          <- Enrichment modules v2.0 (NEW)
+-- nanojs_onchain_generator.py   <- On-chain forensic data generator
+-- scanner_v3.py                 <- Vulnerability scanner
+-- report_generator.py           <- Word report generator
+-- nanojs_autodiscovery.py       <- Continuous new contract scanner
+-- nanojs_existing_scanner.py    <- Historical unaudited scanner
+-- wallet_clustering.py          <- Phase 5 wallet clustering
+-- autostart.sh                  <- VM boot autostart
+-- run.sh                        <- Quick scan shortcut
+-- .env.example                  <- API key template (safe to share)
+-- reports/                      <- JSON reports (gitignored)
+-- forensic_logs/                <- Scan logs (gitignored)
```

---

## Security

- Never commit `.env` — blocked by `.gitignore`
- `reports/` and `forensic_logs/` are gitignored — investigation data stays private
- All API keys loaded via environment variables only
- `test_api.py` is gitignored — never push test files with keys

---

## Responsible Disclosure

All findings follow a 90-day responsible disclosure policy:

1. Finding documented with on-chain evidence
2. Private disclosure to protocol team
3. No response in 90 days -> public disclosure
4. Reports filed with Etherscan, bug bounty platforms, Interpol Cybercrime, FBI IC3

---

## Investigator

**NanoJS10** — Independent blockchain forensic investigator

- GitHub: github.com/NanoJS10
- X: x.com/NanoJS10
- Contact: nanojs@proton.me

---

## License

MIT License free to use, modify, and distribute with attribution.

---

## Contributing

Pull requests welcome. If you find a case where the pipeline misses a known exploit pattern, open an issue with the contract address and chain it will be added to the detector suite.

---

*This tool is for defensive security research and responsible disclosure only.*
