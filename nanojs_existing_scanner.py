"""
NanoJS Existing Unaudited Project Scanner
==========================================
Finds DeFi projects deployed 30-180 days ago with no audit.

Usage:
    python3 nanojs_existing_scanner.py --chain Ethereum --min-age 90 --max-age 180
    python3 nanojs_existing_scanner.py --chain BSC --min-age 30 --max-age 90 --min-balance 0.5
"""

import os, sys, json, time, logging, argparse, requests, subprocess
from pathlib import Path
from dotenv import load_dotenv
from web3 import Web3

load_dotenv()

ETHERSCAN_API_KEY  = os.getenv("ETHERSCAN_API_KEY","")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN","")
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID","")

Path("forensic_logs").mkdir(exist_ok=True)
Path("reports").mkdir(exist_ok=True)
SEEN_FILE = Path("./seen_contracts.json")

CHAIN_CONFIGS = {
    "Ethereum": {"rpc": os.getenv("RPC_ETHEREUM",""), "chain_id":"1",    "explorer":"https://etherscan.io",           "native":"ETH", "blocks_per_day":7200},
    "BSC":      {"rpc": os.getenv("RPC_BSC","https://bsc-dataseed1.binance.org/"), "chain_id":"56","explorer":"https://bscscan.com","native":"BNB","blocks_per_day":28800},
    "Base":     {"rpc": os.getenv("RPC_BASE",""),     "chain_id":"8453", "explorer":"https://basescan.org",            "native":"ETH", "blocks_per_day":43200},
    "Arbitrum": {"rpc": os.getenv("RPC_ARBITRUM",""), "chain_id":"42161","explorer":"https://arbiscan.io",             "native":"ETH", "blocks_per_day":360000},
    "Optimism": {"rpc": os.getenv("RPC_OPTIMISM",""), "chain_id":"10",   "explorer":"https://optimistic.etherscan.io","native":"ETH", "blocks_per_day":43200},
}

HIGH_VALUE = [
    "staking","stakingrewards","stakingpool","stakevault","stake",
    "masterchef","farm","farming","yieldfarm","farmv2","farmv3",
    "vault","yieldvault","corevault","autovault","vaultv2",
    "rewardpool","rewards","rewarddistributor","rewardvault",
    "yield","autocompound","compounder","yieldoptimizer",
    "lending","lendingpool","borrowpool",
    "bridge","crosschain","relaybridge","bridgemodule",
    "liquiditypool","liquiditymining","liquiditymanager",
    "treasury","defi","finance","protocol",
    "pool","poolv2","dex","amm","swap","router",
    "executor","strategy","aggregator","locker",
]

SKIP = [
    "token","erc20","erc721","erc1155","nft","proxy","lens",
    "helper","reader","multicall","factory","test","mock",
    "dummy","safe","ownable","context","math","library",
    "interface","access","pausable","registry","storage",
    "adapter","renderer","counter","compliance","identity",
]

AUDIT_KEYWORDS = [
    "audited by","security audit","certik","trail of bits",
    "openzeppelin audit","consensys","halborn","quantstamp",
    "peckshield","slowmist","hacken","audit report",
]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("forensic_logs/existing_scanner.log"),
    ]
)
log = logging.getLogger("NanoJS-Existing")


def load_seen():
    if SEEN_FILE.exists():
        with open(SEEN_FILE) as f:
            return set(json.load(f))
    return set()

def save_seen(seen):
    with open(SEEN_FILE,"w") as f:
        json.dump(list(seen), f)

def api(chain_id, params, timeout=12):
    params["apikey"]  = ETHERSCAN_API_KEY
    params["chainid"] = chain_id
    try:
        r = requests.get("https://api.etherscan.io/v2/api",
                         params=params, timeout=timeout)
        d = r.json()
        if d.get("status") == "1":
            return d.get("result", [])
    except Exception as e:
        log.debug(f"API: {e}")
    return []

def get_info(address, chain_id):
    """Get contract name, source, and audit status."""
    result = api(chain_id, {
        "module":"contract","action":"getsourcecode","address":address
    })
    if not result:
        return None, False, False
    r      = result[0]
    name   = r.get("ContractName","")
    source = r.get("SourceCode","").lower()
    verified = bool(source.strip())
    audited  = any(kw in source for kw in AUDIT_KEYWORDS)
    return name, verified, audited

def get_age_days(address, chain_id):
    """Get contract age in days."""
    txs = api(chain_id, {
        "module":"account","action":"txlist","address":address,
        "startblock":0,"endblock":99999999,
        "page":1,"offset":1,"sort":"asc"
    })
    if txs and isinstance(txs, list):
        ts = int(txs[0].get("timeStamp",0))
        if ts:
            return round((time.time() - ts) / 86400, 1)
    return None

def get_balance(w3, address):
    try:
        return w3.eth.get_balance(Web3.to_checksum_address(address)) / 1e18
    except:
        return 0.0

def is_target(name):
    n = name.lower()
    for s in SKIP:
        if s in n: return False, None
    for kw in HIGH_VALUE:
        if kw in n: return True, kw
    return False, None

def telegram(text):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            json={"chat_id":TELEGRAM_CHAT_ID,"text":text,"parse_mode":"Markdown"},
            timeout=10
        )
    except: pass

def run_scan(address, chain_name, case_id):
    try:
        r = subprocess.run(
            ["python3","nanojs_master.py",
             "--contract",address,"--chain",chain_name,
             "--case",case_id,"--alert"],
            capture_output=True, text=True, timeout=300,
            cwd=str(Path(__file__).parent)
        )
        out = r.stdout + r.stderr
        return any(x in out for x in ["CRITICAL","WARNING] 1","WARNING] 2"]), out
    except Exception as e:
        return False, str(e)

def scan_existing_unaudited(chain_name="Ethereum", min_age_days=30,
                             max_age_days=180, min_balance=0.1,
                             min_tx_count=10, max_results=20):
    cfg      = CHAIN_CONFIGS.get(chain_name,{})
    chain_id = cfg["chain_id"]
    native   = cfg["native"]
    explorer = cfg["explorer"]
    bpd      = cfg["blocks_per_day"]
    seen     = load_seen()
    case_num = 500

    w3 = Web3(Web3.HTTPProvider(cfg["rpc"]))
    if not w3.is_connected():
        log.error(f"Cannot connect to {chain_name} RPC")
        return []

    latest      = w3.eth.block_number
    start_block = latest - int(max_age_days * bpd)
    end_block   = latest - int(min_age_days * bpd)

    log.info("="*55)
    log.info("  NanoJS Existing Unaudited Scanner")
    log.info(f"  Chain     : {chain_name}")
    log.info(f"  Age       : {min_age_days}–{max_age_days} days")
    log.info(f"  Min bal   : {min_balance} {native}")
    log.info(f"  Blocks    : {start_block:,}–{end_block:,}")
    log.info("="*55)

    telegram(
        f"🔎 *Scanning Existing Unaudited Projects*\n"
        f"Chain: {chain_name} | Age: {min_age_days}–{max_age_days} days\n"
        f"Min balance: {min_balance} {native}\n"
        f"Scanning blocks {start_block:,}–{end_block:,}\n"
        f"This may take several minutes..."
    )

    # Collect deployments
    addresses = []
    step      = max(1, (end_block - start_block) // 500)
    for bn in range(start_block, end_block, step):
        try:
            block = w3.eth.get_block(bn, full_transactions=True)
            for tx in block.transactions:
                if tx.get("to") is None:
                    receipt = w3.eth.get_transaction_receipt(tx["hash"])
                    if receipt and receipt.get("contractAddress"):
                        addresses.append(receipt["contractAddress"])
            if len(addresses) >= max_results * 20:
                break
        except Exception as e:
            log.debug(f"Block {bn}: {e}")

    log.info(f"Found {len(addresses)} deployments in age range")

    targets  = []
    scanned  = 0

    for address in addresses:
        if scanned >= max_results:
            break
        if address.lower() in seen:
            continue
        seen.add(address.lower())

        # Get name + audit status
        name, verified, audited = get_info(address, chain_id)
        if not name or not verified:
            continue
        if audited:
            log.info(f"Skip {name} — audited")
            continue

        # DeFi keyword check
        ok, keyword = is_target(name)
        if not ok:
            continue

        # Balance check
        balance = get_balance(w3, address)
        if balance < min_balance:
            log.info(f"Skip {name} — {balance:.4f} {native}")
            continue

        # Age check
        age = get_age_days(address, chain_id)
        if not age or not (min_age_days <= age <= max_age_days):
            continue

        case_id = f"NanoJS-EXIST{case_num:04d}"
        case_num += 1
        scanned += 1

        log.warning(
            f"🎯 UNAUDITED: {name} | {age} days | "
            f"{balance:.4f} {native} | [{keyword}]"
        )

        telegram(
            f"🎯 *Unaudited Project Found*\n"
            f"Name: `{name}`\n"
            f"Age: {age} days old\n"
            f"Balance: {balance:.4f} {native}\n"
            f"Keyword: `{keyword}`\n"
            f"Chain: {chain_name}\n"
            f"Address: `{address}`\n"
            f"🔗 {explorer}/address/{address}\n"
            f"⏳ Scanning as {case_id}..."
        )

        has_findings, _ = run_scan(address, chain_name, case_id)
        targets.append({
            "name": name, "address": address,
            "age_days": age, "balance": balance,
            "keyword": keyword, "findings": has_findings,
            "case_id": case_id,
        })

        if has_findings:
            log.warning(f"🚨 FINDINGS: {name}")
        else:
            log.info(f"✅ Clean: {name}")

        time.sleep(2)

    save_seen(seen)

    log.info(f"\n{'='*55}")
    log.info(f"  Scan complete — {len(targets)} targets, "
             f"{sum(1 for t in targets if t['findings'])} with findings")
    log.info(f"{'='*55}")

    telegram(
        f"✅ *Existing Unaudited Scan Done*\n"
        f"Targets: {len(targets)} | Findings: {sum(1 for t in targets if t['findings'])}"
    )
    return targets


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="NanoJS Existing Unaudited Project Scanner"
    )
    parser.add_argument("--chain",        default="Ethereum",
                        choices=list(CHAIN_CONFIGS.keys()))
    parser.add_argument("--min-age",      type=int,   default=30)
    parser.add_argument("--max-age",      type=int,   default=180)
    parser.add_argument("--min-balance",  type=float, default=0.1)
    parser.add_argument("--min-tx",       type=int,   default=10)
    parser.add_argument("--max-results",  type=int,   default=20)
    args = parser.parse_args()

    scan_existing_unaudited(
        chain_name=args.chain,
        min_age_days=args.min_age,
        max_age_days=args.max_age,
        min_balance=args.min_balance,
        min_tx_count=args.min_tx,
        max_results=args.max_results,
    )
