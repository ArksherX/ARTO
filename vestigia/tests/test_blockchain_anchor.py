from core.blockchain_anchor import BlockchainAnchor


def test_blockchain_anchor_file(tmp_path):
    anchor_path = tmp_path / "anchors.json"
    anchor = BlockchainAnchor(provider="file", anchor_path=str(anchor_path))
    record = anchor.anchor(["a" * 64, "b" * 64, "c" * 64])
    assert record["provider"] == "file"
    listed = anchor.list_anchors()
    assert len(listed["anchors"]) == 1
    assert anchor.verify_anchor(record["anchor_id"]) is not None
