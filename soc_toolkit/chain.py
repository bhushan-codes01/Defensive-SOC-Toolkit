import hashlib
import json
import time
from typing import List, Dict, Any, Tuple
from .db import get_connection

def calculate_sha256(data: str) -> str:
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

class AuditChain:
    def __init__(self):
        self.init_chain()

    def init_chain(self):
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM audit_chain")
            count = cursor.fetchone()[0]
            if count == 0:
                # Add Genesis Block
                genesis_payload = {"event": "GENESIS_BLOCK", "system": "Defensive SOC Toolkit"}
                payload_json = json.dumps(genesis_payload, sort_keys=True)
                payload_hash = calculate_sha256(payload_json)
                prev_hash = "0" * 64
                ts = time.time()
                block_data = f"0|{ts:.4f}|{payload_hash}|{prev_hash}"
                block_hash = calculate_sha256(block_data)

                cursor.execute("""
                    INSERT INTO audit_chain (block_index, timestamp, payload_hash, prev_hash, block_hash, payload_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (0, ts, payload_hash, prev_hash, block_hash, payload_json))
                conn.commit()

    def add_block(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT block_index, block_hash FROM audit_chain ORDER BY block_index DESC LIMIT 1")
            last_block = cursor.fetchone()
            
            last_index = last_block["block_index"]
            prev_hash = last_block["block_hash"]
            new_index = last_index + 1

            payload_json = json.dumps(payload, sort_keys=True)
            payload_hash = calculate_sha256(payload_json)
            ts = time.time()
            
            block_data = f"{new_index}|{ts:.4f}|{payload_hash}|{prev_hash}"
            block_hash = calculate_sha256(block_data)

            cursor.execute("""
                INSERT INTO audit_chain (block_index, timestamp, payload_hash, prev_hash, block_hash, payload_json)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (new_index, ts, payload_hash, prev_hash, block_hash, payload_json))
            conn.commit()

            return {
                "block_index": new_index,
                "timestamp": ts,
                "payload_hash": payload_hash,
                "prev_hash": prev_hash,
                "block_hash": block_hash
            }

    def get_chain(self) -> List[Dict[str, Any]]:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_chain ORDER BY block_index ASC")
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def verify_integrity(self) -> Dict[str, Any]:
        chain = self.get_chain()
        is_valid = True
        broken_indices = []

        for i in range(len(chain)):
            block = chain[i]
            # Check payload hash
            recomputed_payload_hash = calculate_sha256(block["payload_json"])
            if recomputed_payload_hash != block["payload_hash"]:
                is_valid = False
                broken_indices.append(block["block_index"])
                continue

            if i > 0:
                prev_block = chain[i - 1]
                if block["prev_hash"] != prev_block["block_hash"]:
                    is_valid = False
                    broken_indices.append(block["block_index"])

            # Check block hash
            block_data = f"{block['block_index']}|{block['timestamp']:.4f}|{block['payload_hash']}|{block['prev_hash']}"
            recomputed_block_hash = calculate_sha256(block_data)
            if recomputed_block_hash != block["block_hash"]:
                is_valid = False
                if block["block_index"] not in broken_indices:
                    broken_indices.append(block["block_index"])

        merkle_root = self.calculate_merkle_root([b["block_hash"] for b in chain])

        return {
            "is_valid": is_valid,
            "total_blocks": len(chain),
            "broken_indices": broken_indices,
            "merkle_root": merkle_root,
            "status": "VALID" if is_valid else "TAMPERED_DETECTED"
        }

    def calculate_merkle_root(self, hashes: List[str]) -> str:
        if not hashes:
            return calculate_sha256("")
        if len(hashes) == 1:
            return hashes[0]
        
        next_level = []
        for i in range(0, len(hashes), 2):
            h1 = hashes[i]
            h2 = hashes[i + 1] if i + 1 < len(hashes) else h1
            combined = calculate_sha256(h1 + h2)
            next_level.append(combined)
        
        return self.calculate_merkle_root(next_level)

audit_chain = AuditChain()
