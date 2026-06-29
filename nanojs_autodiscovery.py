"""
NanoJS Auto-Discovery v4
=========================
Uses Web3 RPC to scan recent blocks for new contract deployments,
then checks names via Etherscan API and filters by DeFi keywords.

Usage:
    python3 nanojs_autodiscovery.py
    python3 nanojs_autodiscovery.py --chain BSC --interval 600
    python3 nanojs_autodiscovery.py --min-balance 0.5
"""

import os, sys, json, time, logging, argparse, requests, subprocess
from pathlib import Path
from dotenv import load_dotenv
from web3 import Web3

load_dotenv()

ETHERSCAN_API_KEY  = os.getenv("ETHERSCAN_API_KEY","")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN","")
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID","")

SEEN_FILE = Path("./seen_contracts.json")
Path("forensic_logs").mkdir(exist_ok=True)
Path("reports").mkdir(exist_ok=True)

CHAIN_CONFIGS = {
    "Ethereum": {
        "rpc":      os.getenv("RPC_ETHEREUM",""),
        "chain_id": "1",
        "explorer": "https://etherscan.io",
        "native":   "ETH",
    },
    "BSC": {
        "rpc":      os.getenv("RPC_BSC","https://bsc-dataseed1.binance.org/"),
        "chain_id": "56",
        "explorer": "https://bscscan.com",
        "native":   "BNB",
    },
    "Base": {
        "rpc":      os.getenv("RPC_BASE",""),
        "chain_id": "8453",
        "explorer": "https://basescan.org",
        "native":   "ETH",
    },
    "Arbitrum": {
        "rpc":      os.getenv("RPC_ARBITRUM",""),
        "chain_id": "42161",
        "explorer": "https://arbiscan.io",
        "native":   "ETH",
    },
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
    "token","erc20","erc721","erc1155","nft","nftmint",
    "proxy","lens","helper","reader","multicall","factory",
    "test","mock","dummy","safe","ownable","context",
    "math","library","interface","access","pausable",
    "registry","storage","adapter","renderer","counter",
    "compliance","identity","ticket","pixel","deployer",
    "import","wrapper","permit","timelock",
]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("forensic_logs/autodiscovery.log"),
    ]
)
log = logging.getLogger("NanoJS-Discovery")

def load_seen():
    if SEEN_FILE.exists():
        with open(SEEN_FILE) as f:
            return set(json.load(f))
    return set()

def save_seen(seen):
    with open(SEEN_FILE,"w") as f:
        json.dump(list(seen), f)

def get_contract_name(address, chain_id):
    try:
        r = requests.get("https://api.etherscan.io/v2/api", params={
            "chainid": chain_id,
            "module":  "contract",
            "action":  "getsourcecode",
            "address": address,
            "apikey":  ETHERSCAN_API_KEY,
        }, timeout=10)
        data = r.json()
        if data.get("status") == "1" and data.get("result"):
            name = data["result"][0].get("ContractName","")
            src  = data["result"][0].get("SourceCode","")
            return name, bool(src.strip())
    except:
        pass
    return "", False

def get_eth_balance(w3, address):
    try:
        return w3.eth.get_balance(
            Web3.to_checksum_address(address)) / 1e18
    except:
        return 0.0

def is_target(name):
    n = name.lower()
    for s in SKIP:
        if s in n:
            return False, None
    for kw in HIGH_VALUE:
        if kw in n:
            return True, kw
    return False, None

def telegram(text):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            json={"chat_id":TELEGRAM_CHAT_ID,
                  "text":text,"parse_mode":"Markdown"},
            timeout=10
        )
    except:
        pass

def run_scan(address, chain_name, case_id):
    try:
        result = subprocess.run(
            ["python3","nanojs_master.py",
             "--contract", address,
             "--chain",    chain_name,
             "--case",     case_id,
             "--alert"],
            capture_output=True, text=True,
            timeout=300,
            cwd=str(Path(__file__).parent)
        )
        out = result.stdout + result.stderr
        return any(x in out for x in ["CRITICAL","WARNING] 1","WARNING] 2"]), out
    except Exception as e:
        return False, str(e)

def scan_blocks_for_contracts(w3, start_block, end_block):
    """Scan blocks for new contract deployments."""
    contracts = []
    log.info(f"Scanning blocks {start_block:,} to {end_block:,}...")
    for bn in range(start_block, end_block + 1):
        try:
            block = w3.eth.get_block(bn, full_transactions=True)
            for tx in block.transactions:
                if tx.get("to") is None:
                    receipt = w3.eth.get_transaction_receipt(tx["hash"])
                    if receipt and receipt.get("contractAddress"):
                        contracts.append({
                            "address":  receipt["contractAddress"],
                            "deployer": tx["from"],
                            "block":    bn,
                            "tx_hash":  tx["hash"].hex(),
                        })
        except Exception as e:
            log.debug(f"Block {bn} error: {e}")
    return contracts

def run_discovery(chain_name="Ethereum", min_balance=0.0,
                  interval=300, max_per_cycle=10,
                  blocks_per_cycle=200):

    seen     = load_seen()
    cfg      = CHAIN_CONFIGS.get(chain_name, {})
    chain_id = cfg.get("chain_id","1")
    native   = cfg.get("native","ETH")
    explorer = cfg.get("explorer","")
    case_num = 400

    # Connect Web3
    w3 = Web3(Web3.HTTPProvider(cfg["rpc"]))
    if not w3.is_connected():
        log.error(f"Cannot connect to {chain_name} RPC")
        return

    latest = w3.eth.block_number
    log.info("="*55)
    log.info("  NanoJS Auto-Discovery v4")
    log.info(f"  Chain    : {chain_name}")
    log.info(f"  RPC      : Connected (block {latest:,})")
    log.info(f"  Min bal  : {min_balance} {native}")
    log.info(f"  Interval : {interval}s")
    log.info(f"  Blocks/cycle: {blocks_per_cycle}")
    log.info(f"  Seen     : {len(seen)} contracts")
    log.info("="*55)

    telegram(
        f"🤖 *NanoJS Auto-Discovery v4 Online*\n"
        f"Chain: {chain_name} | Block: {latest:,}\n"
        f"Min balance: {min_balance} {native}\n"
        f"Scanning {blocks_per_cycle} blocks every {interval}s\n"
        f"Watching: Vault, Farm, Staking, Pool, Bridge..."
    )

    scan_from = latest - blocks_per_cycle

    while True:
        try:
            current = w3.eth.block_number
            end_block = current
            start_block = max(scan_from, current - blocks_per_cycle)

            log.info(f"🔍 Scanning blocks {start_block:,}–{end_block:,}...")

            new_contracts = scan_blocks_for_contracts(w3, start_block, end_block)
            log.info(f"Found {len(new_contracts)} new deployments in blocks")

            found = 0
            scanned = 0

            for c in new_contracts:
                if scanned >= max_per_cycle:
                    break

                address = c["address"]
                if address.lower() in seen:
                    continue
                seen.add(address.lower())

                # Get contract name from Etherscan
                name, is_verified = get_contract_name(address, chain_id)

                if not name or not is_verified:
                    log.debug(f"Skip {address[:10]}... — unverified or no name")
                    continue

                # Filter by DeFi keywords
                ok, keyword = is_target(name)
                if not ok:
                    log.debug(f"Skip {name} — not DeFi target")
                    continue

                # Check balance
                balance = get_eth_balance(w3, address)
                if balance < min_balance:
                    log.info(f"Skip {name} — {balance:.4f} {native} < {min_balance}")
                    continue

                found += 1
                case_id = f"NanoJS-AUTO{case_num:04d}"
                case_num += 1

                log.warning(
                    f"🎯 TARGET: {name} | {address[:12]}... | "
                    f"{balance:.4f} {native} | [{keyword}]"
                )

                telegram(
                    f"🎯 *New DeFi Target Found*\n"
                    f"Name: `{name}`\n"
                    f"Chain: {chain_name}\n"
                    f"Balance: {balance:.4f} {native}\n"
                    f"Keyword: `{keyword}`\n"
                    f"Address: `{address}`\n"
                    f"Deployer: `{c['deployer'][:16]}...`\n"
                    f"Block: {c['block']:,}\n"
                    f"🔗 {explorer}/address/{address}\n"
                    f"⏳ Scanning as {case_id}..."
                )

                has_findings, output = run_scan(address, chain_name, case_id)
                scanned += 1

                if has_findings:
                    log.warning(f"🚨 FINDINGS on {name}!")
                else:
                    log.info(f"✅ Clean: {name}")

                time.sleep(3)

            scan_from = end_block + 1
            save_seen(seen)

            log.info(
                f"Cycle done — {found} DeFi targets found, "
                f"{scanned} scanned. Next in {interval}s..."
            )
            time.sleep(interval)

        except KeyboardInterrupt:
            log.info("Stopped by user.")
            telegram("⏹ NanoJS Auto-Discovery stopped.")
            save_seen(seen)
            break
        except Exception as e:
            log.error(f"Cycle error: {e}")
            time.sleep(60)

def main():
    parser = argparse.ArgumentParser(
        description="NanoJS Auto-Discovery v4 — block-based DeFi scanner"
    )
    parser.add_argument("--chain","-c", default="Ethereum",
                        choices=list(CHAIN_CONFIGS.keys()))
    parser.add_argument("--interval","-i",   type=int, default=300)
    parser.add_argument("--min-balance","-b", type=float, default=0.0)
    parser.add_argument("--max-per-cycle","-m", type=int, default=10)
    parser.add_argument("--blocks","-bl",    type=int, default=200,
                        help="Blocks to scan per cycle (default 200)")
    parser.add_argument("--list-keywords",   action="store_true")
    args = parser.parse_args()

    if args.list_keywords:
        print("\nTarget keywords:")
        for k in sorted(HIGH_VALUE): print(f"  + {k}")
        print("\nSkip keywords:")
        for k in sorted(SKIP): print(f"  - {k}")
        return

    run_discovery(
        chain_name=args.chain,
        min_balance=args.min_balance,
        interval=args.interval,
        max_per_cycle=args.max_per_cycle,
        blocks_per_cycle=args.blocks,
    )

if __name__ == "__main__":
    main()
