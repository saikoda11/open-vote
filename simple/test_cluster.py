import time
import httpx
 
NODES = {
    "node1": "http://127.0.0.1:8001",
    "node2": "http://127.0.0.1:8002",
    "node3": "http://127.0.0.1:8003",
}
 
def get(url):
    return httpx.get(url, timeout=5).json()
 
def post(url, body):
    return httpx.post(url, json=body, timeout=5).json()
 
def check_all_heads():
    print("\n--- Chain heads ---")
    for name, base in NODES.items():
        r = get(f"{base}/chain/head")
        print(f"  {name}: height={r['height']} hash={r['block_hash'][:12]}... leader={r['validator_id']}")
 
def check_all_states():
    print("\n--- States ---")
    for name, base in NODES.items():
        r = get(f"{base}/state")
        print(f"  {name}: height={r['height']} list={r['list']}")
 
def wait_for_nodes(retries=10):
    print("Waiting for nodes to start...")
    for _ in range(retries):
        try:
            for base in NODES.values():
                get(f"{base}/chain/head")
            print("All nodes up.\n")
            return
        except Exception:
            time.sleep(1)
    raise RuntimeError("Nodes did not start in time")
 
def test_submit_and_propagate():
    print("=== Test: submit 3 transactions (one to each node) ===")
 
    values = ["alpha", "beta", "gamma"]
    for i, (name, base) in enumerate(NODES.items()):
        val = values[i]
        r = post(f"{base}/tx/append", {"value": val})
        print(f"  Submitted '{val}' to {name}: {r}")
 
    print("Waiting 3s for blocks to propagate...")
    time.sleep(3)
    check_all_heads()
    check_all_states()
 
    # Verify all nodes agree
    states = [get(f"{base}/state")["list"] for base in NODES.values()]
    assert states[0] == states[1] == states[2], f"State mismatch! {states}"
    print("\n✓ All nodes agree on state:", states[0])
 
def test_forwarding():
    print("\n=== Test: submit to wrong node (should forward to leader) ===")
    # Submit 9 more items to node1 regardless of who leads
    submitted = []
    for i in range(9):
        val = f"item-{i}"
        r = post(f"{NODES['node1']}/tx/append", {"value": val})
        submitted.append(val)
        print(f"  Submitted '{val}': {r}")
 
    print("Waiting 5s for all blocks to be produced...")
    time.sleep(5)
    check_all_heads()
    check_all_states()
 
    states = [get(f"{base}/state")["list"] for base in NODES.values()]
    assert states[0] == states[1] == states[2], f"State mismatch! {states}"
    print("\n✓ All nodes agree. Final state:", states[0])
 
if __name__ == "__main__":
    wait_for_nodes()
    check_all_heads()
    test_submit_and_propagate()
    test_forwarding()
    print("\n✓ All tests passed")
 