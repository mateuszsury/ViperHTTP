import os
import sys
import time
import shutil
import types


def ensure_clean_dir(path):
    if os.path.isdir(path):
        shutil.rmtree(path)
    os.makedirs(path)


def main():
    tmp_dir = os.path.join("tools", ".tmp_sessions")
    ensure_clean_dir(tmp_dir)

    dummy = types.SimpleNamespace(fs_lock=None, fs_unlock=None)
    sys.modules["viperhttp"] = dummy
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)

    import viperhttp_session as vhttp_session

    store = vhttp_session.VFSSessionStore(
        base_path=tmp_dir,
        ttl_ms=60_000,
        max_sessions=2,
        max_total_bytes=10_000,
        write_at_interval_ms=0,
        gc_interval_ms=0,
        compact_interval_ms=0,
        compact_on_load=True,
    )

    store.set("a", {"v": 1}, None)
    time.sleep(0.05)
    store.set("b", {"v": 2}, None)
    store.get("a")
    time.sleep(0.05)
    store.set("c", {"v": 3}, None)

    assert store.get("a") is not None, "LRU kept 'a' after access"
    assert store.get("b") is None, "LRU evicted 'b' as least recently used"
    assert store.get("c") is not None, "LRU kept newest 'c'"

    store2 = vhttp_session.VFSSessionStore(
        base_path=tmp_dir,
        ttl_ms=60_000,
        max_sessions=1,
        max_total_bytes=None,
        write_at_interval_ms=0,
        gc_interval_ms=0,
        compact_interval_ms=0,
        compact_on_load=True,
    )
    store2.compact(force=True)

    files = [name for name in os.listdir(tmp_dir) if name.endswith(".json")]
    assert len(files) == 1, "compaction on load enforces max_sessions"

    shutil.rmtree(tmp_dir)
    print("PASS")


if __name__ == "__main__":
    main()
