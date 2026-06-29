import os, time, json, logging, requests
from datetime import datetime, timezone
from web3 import Web3

logger = logging.getLogger("NanoJS.WalletClustering")

TORNADO_CASH_ROUTERS = {
    "0x722122df12d4e14e13ac3b6895a86e84145b6967",
    "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b",
    "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936",
    "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf",
    "0xa160cdab225685da1d56aa342ad8841c3b53f291",
}

CHAIN_CONFIG = {
    "Ethereum": {"rpc_env":"ETH_RPC_URL","explorer":"https://api.etherscan.io/api","api_env":"ETHERSCAN_API_KEY"},
    "Optimism": {"rpc_env":"OPTIMISM_RPC_URL","explorer":"https://api-optimistic.etherscan.io/api","api_env":"OPTIMISM_API_KEY"},
    "Arbitrum": {"rpc_env":"ARBITRUM_RPC_URL","explorer":"https://api.arbiscan.io/api","api_env":"ARBISCAN_API_KEY"},
    "BSC":      {"rpc_env":"BSC_RPC_URL","explorer":"https://api.bscscan.com/api","api_env":"BSCSCAN_API_KEY"},
    "Base":     {"rpc_env":"BASE_RPC_URL","explorer":"https://api.basescan.org/api","api_env":"BASESCAN_API_KEY"},
}

def run_clustering_phase(seed_address, chain, case_id, output_dir="reports", hop_depth=3):
    cfg     = CHAIN_CONFIG.get(chain, CHAIN_CONFIG["Ethereum"])
    api_key = os.getenv(cfg["api_env"], "")
    cache   = {}

    def get_txns(addr):
        if addr in cache: return cache[addr]
        try:
            r = requests.get(cfg["explorer"], params={
                "module":"account","action":"txlist","address":addr,
                "page":1,"offset":500,"sort":"desc","apikey":api_key
            }, timeout=15)
            data = r.json()
            if data.get("status") == "1":
                cache[addr] = data["result"]
                return data["result"]
        except: pass
        return []

    wallets, mixer_hits, cross_chain, funding_tree, flags = {}, [], {}, {}, []
    risk_score = 0

    def add_wallet(addr, role, funded_by=None):
        addr = addr.lower()
        if addr not in wallets:
            wallets[addr] = {"address":addr,"role":role,"funded_by":funded_by,"mixer":False}

    def check_mixer(addr):
        nonlocal risk_score
        for tx in get_txns(addr):
            if tx.get("to","").lower() in TORNADO_CASH_ROUTERS or tx.get("from","").lower() in TORNADO_CASH_ROUTERS:
                wallets.get(addr.lower(),{})["mixer"] = True
                mixer_hits.append(addr)
                flags.append(f"MIXER:{addr[:10]}")
                risk_score += 25
                return

    seed = seed_address.lower()
    add_wallet(seed, "seed")

    # Trace funding hops
    visited, node = set(), seed
    for hop in range(hop_depth):
        if node in visited: break
        visited.add(node)
        txns = get_txns(node)
        inbound = [t for t in txns if t.get("to","").lower()==node and int(t.get("value",0))>0]
        if not inbound: break
        funder = inbound[0]["from"].lower()
        add_wallet(funder, "funder", funded_by=node)
        funding_tree[node] = funder
        flags.append(f"FUNDER_HOP_{hop+1}:{funder[:10]}")
        risk_score += 5
        check_mixer(funder)
        node = funder

    # Co-funded siblings
    check_mixer(seed)
    seed_txns = get_txns(seed)
    seed_inbound = [t for t in seed_txns if t.get("to","").lower()==seed and int(t.get("value",0))>0]
    if seed_inbound:
        seed_funder = seed_inbound[0]["from"].lower()
        seed_ts     = int(seed_inbound[0].get("timeStamp",0))
        for tx in get_txns(seed_funder):
            to = tx.get("to","").lower()
            if to != seed and int(tx.get("value",0))>0 and abs(int(tx.get("timeStamp",0))-seed_ts)<=300:
                add_wallet(to, "co-funded", funded_by=seed_funder)
                flags.append(f"CO_FUNDED:{to[:10]}")
                risk_score += 10

    # Cross-chain
    other_chains = [c for c in CHAIN_CONFIG if c != chain]
    for other in other_chains:
        ocfg    = CHAIN_CONFIG[other]
        oc_key  = os.getenv(ocfg["api_env"],"")
        if not oc_key: continue
        for addr in list(wallets.keys()):
            try:
                r = requests.get(ocfg["explorer"], params={
                    "module":"account","action":"txlist","address":addr,
                    "page":1,"offset":3,"sort":"desc","apikey":oc_key
                }, timeout=10)
                if r.json().get("status")=="1":
                    cross_chain.setdefault(addr,[]).append(other)
                    flags.append(f"CROSS_CHAIN:{addr[:10]}→{other}")
                    risk_score += 5
                time.sleep(0.2)
            except: pass

    os.makedirs(output_dir, exist_ok=True)
    ts       = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_file = f"{output_dir}/{case_id}_cluster_{ts}.json"
    report   = {
        "seed":seed,"wallet_count":len(wallets),"risk_score":risk_score,
        "flags":flags,"mixer_hits":mixer_hits,"cross_chain":cross_chain,
        "funding_tree":funding_tree,"wallets":wallets
    }
    with open(out_file,"w") as f:
        json.dump(report, f, indent=2)

    logger.info(f"[CLUSTER] Report saved: {out_file}")
    return {
        "cluster_report": out_file,
        "wallet_count":   len(wallets),
        "cluster_score":  risk_score,
        "mixer_hits":     len(mixer_hits),
        "cross_chain":    len(cross_chain),
        "flags":          flags,
    }
