import pytest
from soc_toolkit.db import init_db
from soc_toolkit.chain import audit_chain

def test_audit_chain_add_and_verify():
    init_db()
    res_before = audit_chain.verify_integrity()
    assert res_before["is_valid"] is True

    block = audit_chain.add_block({"test_event": "UNIT_TEST_BLOCK"})
    assert block["block_index"] > 0
    assert "block_hash" in block

    res_after = audit_chain.verify_integrity()
    assert res_after["is_valid"] is True
    assert res_after["total_blocks"] >= 2
