import os
import time
import threading
import requests
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv

load_dotenv()

# Simple Stacks API client for querying contract transactions and events
# Works with Hiro Stacks API endpoints. You can switch between mainnet/testnet/custom devnet.

STACKS_API_BASE = os.getenv("STACKS_API_BASE", "https://api.testnet.hiro.so")
NETWORK = os.getenv("STACKS_NETWORK", "testnet")

# Contract identification
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS", "")  # e.g., SP3FBR2AGK... or devnet address
CONTRACT_NAME = os.getenv("CONTRACT_NAME", "tokenization-system")

SESSION = requests.Session()
SESSION.headers.update({"Accept": "application/json"})


def set_contract(address: str, name: str):
    global CONTRACT_ADDRESS, CONTRACT_NAME
    CONTRACT_ADDRESS = address
    CONTRACT_NAME = name


def _url(path: str) -> str:
    return f"{STACKS_API_BASE}{path}"

def _get_with_retry(url: str, max_retries: int = 3, **kwargs) -> requests.Response:
    """GET with automatic Retry-After-aware backoff on HTTP 429."""
    for attempt in range(max_retries):
        r = SESSION.get(url, **kwargs)
        if r.status_code == 429 and attempt < max_retries - 1:
            retry_after = int(r.headers.get("Retry-After", 2))
            time.sleep(retry_after)
            continue
        return r
    return r  # type: ignore[return-value]  # loop always executes at least once


def get_contract_transactions(limit: int = 50) -> List[Dict[str, Any]]:
    if not CONTRACT_ADDRESS or not CONTRACT_NAME:
        return []
    # Extended API for contract transactions
    # Docs: GET /extended/v1/contract/{contract_id}/transactions
    contract_id = f"{CONTRACT_ADDRESS}.{CONTRACT_NAME}"
    url = _url(f"/extended/v1/contract/{contract_id}/transactions?limit={limit}")
    r = _get_with_retry(url, timeout=10)
    r.raise_for_status()
    data = r.json()
    return data.get("results", [])


def get_tx_details(txid: str) -> Optional[Dict[str, Any]]:
    url = _url(f"/extended/v1/tx/{txid}")
    r = _get_with_retry(url, timeout=10)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()


def extract_clarity_events(tx: Dict[str, Any]) -> List[Dict[str, Any]]:
    # From tx result, parse contract events and print events
    events = []
    receipt: dict = tx.get("receipt") or {}
    for ev in receipt.get("events", []):
        # Each event may have type and value; we attempt to capture prints and contract_event
        ev_type = ev.get("type")
        value = ev.get("contract_event") or ev.get("print_event") or ev.get("fungible_token_transfer") or ev.get("non_fungible_token_transfer")
        if value is not None:
            events.append({"type": ev_type, "data": value})
    return events


class TxMonitor:
    def __init__(self, poll_interval: Optional[float] = None, history_size: int = 200):
        self.base_interval = poll_interval or float(os.getenv('TX_POLL_INTERVAL', '10'))
        self.max_interval = float(os.getenv('TX_POLL_MAX_INTERVAL', '60'))
        self.backoff_factor = float(os.getenv('TX_POLL_BACKOFF_FACTOR', '1.5'))
        self.poll_interval = self.base_interval
        self.history_size = history_size
        self._seen: set[str] = set()
        self._subs: List = []
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def subscribe(self, callback):
        self._subs.append(callback)

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()  # type: ignore[union-attr]

    def stop(self):
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=2)

    def _run(self):
        current_interval = self.base_interval
        while self._running:
            try:
                txs = get_contract_transactions(limit=50)
                for tx in txs:
                    txid = tx.get("tx_id") or tx.get("txid")
                    if not txid or txid in self._seen:
                        continue
                    details = get_tx_details(txid)
                    if details:
                        events = extract_clarity_events(details)
                        payload = {
                            "txid": txid,
                            "status": details.get("tx_status"),
                            "block_height": details.get("block_height"),
                            "contract_id": details.get("contract_id"),
                            "events": events,
                            "raw": details,
                        }
                        for cb in self._subs:
                            try:
                                cb(payload)
                            except Exception:
                                pass
                    self._seen.add(txid)
                    if len(self._seen) > self.history_size:
                        self._seen = set(list(self._seen)[-self.history_size:])  # type: ignore[index]
                # Success — reset to base interval
                current_interval = self.base_interval
            except Exception:
                # Exponential backoff on error
                current_interval = min(current_interval * self.backoff_factor, self.max_interval)  # type: ignore[arg-type]
            time.sleep(current_interval)


if __name__ == "__main__":
    # Simple CLI monitor example
    addr = os.getenv("CONTRACT_ADDRESS") or input("Contract address (SP...): ")
    name = os.getenv("CONTRACT_NAME") or input("Contract name: ")
    set_contract(addr, name)

    monitor = TxMonitor(poll_interval=3)
    monitor.subscribe(lambda e: print(f"New tx: {e['txid']} status={e['status']} events={len(e['events'])}"))
    print(f"Monitoring {addr}.{name} via {STACKS_API_BASE} ... Press Ctrl+C to stop")
    monitor.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()

