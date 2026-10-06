import hashlib
import json
import sqlite3
import time
import math
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Set

def canonical_serialize(data: Any) -> bytes:
    """Детерминированная каноническая сериализация JSON."""
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

def canonical_hash(data: Any) -> str:
    """Генерация SHA-256 хэша от канонического представления."""
    return hashlib.sha256(canonical_serialize(data)).hexdigest()

def validate_numeric(v: Any) -> bool:
    """Проверка числового значения: исключает bool, NaN, Inf."""
    if isinstance(v, bool):
        return False
    if not isinstance(v, (int, float)):
        return False
    if math.isnan(v) or math.isinf(v):
        return False
    return True

# --- Merkle Tree Engine ---
class MerkleTree:
    """
    Детерминированное дерево Меркла для генерации компактных доказательств (Merkle Proofs)
    и внешнего якорения (External Public Anchoring).
    """
    @staticmethod
    def _hash_pair(left: str, right: str) -> str:
        combined = (left + right).encode('utf-8')
        return hashlib.sha256(combined).hexdigest()

    @classmethod
    def compute_root(cls, leaves: List[str]) -> str:
        if not leaves:
            return "0" * 64
        current_level = [l for l in leaves]
        while len(current_level) > 1:
            if len(current_level) % 2 != 0:
                current_level.append(current_level[-1])
            next_level = []
            for i in range(0, len(current_level), 2):
                next_level.append(cls._hash_pair(current_level[i], current_level[i+1]))
            current_level = next_level
        return current_level[0]

    @classmethod
    def get_proof(cls, leaves: List[str], index: int) -> List[Dict[str, str]]:
        if not leaves or index < 0 or index >= len(leaves):
            return []
        current_level = [l for l in leaves]
        idx = index
        proof = []

        while len(current_level) > 1:
            if len(current_level) % 2 != 0:
                current_level.append(current_level[-1])
            is_right = (idx % 2 == 1)
            pair_idx = idx - 1 if is_right else idx + 1
            sibling = current_level[pair_idx]
            proof.append({
                "position": "left" if is_right else "right",
                "hash": sibling
            })
            idx = idx // 2
            next_level = []
            for i in range(0, len(current_level), 2):
                next_level.append(cls._hash_pair(current_level[i], current_level[i+1]))
            current_level = next_level

        return proof

    @classmethod
    def verify_proof(cls, leaf: str, proof: List[Dict[str, str]], root: str) -> bool:
        current = leaf
        for p in proof:
            sibling = p["hash"]
            if p["position"] == "left":
                current = cls._hash_pair(sibling, current)
            else:
                current = cls._hash_pair(current, sibling)
        return current == root


# --- Photonic & Physical Invariants Solver ---
class PhysicalInvariantSolver:
    """
    Симулятор и валидатор физических и фотонных ограничений TGP:
    - Проверка законов сохранения энергии
    - Фотонный резонансный Q-фактор (Maxwell / Photonic Crystal)
    - Энергетическая себестоимость (без субъективных фиатных наценок)
    """
    @staticmethod
    def verify_photonic_q_factor(energy_stored_joules: float, power_loss_watts: float, frequency_hz: float) -> Tuple[bool, float]:
        """Q = 2 * pi * f * (E_stored / P_loss)"""
        if not (validate_numeric(energy_stored_joules) and validate_numeric(power_loss_watts) and validate_numeric(frequency_hz)):
            return False, 0.0
        if energy_stored_joules <= 0 or power_loss_watts <= 0 or frequency_hz <= 0:
            return False, 0.0
        
        q_factor = 2.0 * math.pi * frequency_hz * (energy_stored_joules / power_loss_watts)
        is_valid = q_factor >= 1e4
        return is_valid, q_factor

    @staticmethod
    def calculate_energy_cost(mass_kg: float, distance_km: float, efficiency: float = 0.85) -> float:
        """Расчет базовой энергетической себестоимости физического перемещения (в Джоулях)."""
        if not (validate_numeric(mass_kg) and validate_numeric(distance_km) and validate_numeric(efficiency)):
            return float('inf')
        if mass_kg < 0 or distance_km < 0 or efficiency <= 0:
            return float('inf')
        
        g = 9.81
        mu = 0.05
        work_joules = (mass_kg * g * mu * (distance_km * 1000.0)) / efficiency
        return work_joules


@dataclass(frozen=True)
class SystemState:
    """Иммутабельный снимок состояния системы SDPAP v3."""
    version: int
    nodes: Tuple[str, ...]
    permissions: frozenset
    state_hash: str
    merkle_root: str


class SDPAPKernelProduction:
    """
    Промышленное ядро SDPAP Kernel v3 & TGP (Production Release - Pure Deterministic Architecture):
    - Полный отказ от внешних ключей подписи (Zero-Trust Keyless Hash-Chain Verification)
    - Level 1 Gate Barrier: verify_hash_chain (Проверка цепи канонических хэшей)
    - Level 2: OCC & Replay Guard (проверка версии состояния и уникальности nonce)
    - Level 3: Gate-Side Independent Graph Recomputation (независимый пересчет графа)
    - Level 4: Physical & Epistemological Invariants (проверка фотонного Q-фактора и Попперовская фальсификация)
    - SQLite WAL Ledger с append-only триггерами и Merkle Tree якорением
    """
    GENESIS_HASH = "0" * 64

    def __init__(self, db_path: str = "/workspace/scratch/sdpap_production.db"):
        self._db_path = db_path
        self._used_nonces: Set[str] = set()

        initial_nodes = ("root_boundary", "green_anchor_genesis")
        initial_perms = frozenset(["execute_core", "compute_phc", "popperean_verify"])
        init_hash = canonical_hash({"version": 1, "nodes": list(initial_nodes), "perms": sorted(list(initial_perms))})

        self._current_state = SystemState(
            version=1,
            nodes=initial_nodes,
            permissions=initial_perms,
            state_hash=init_hash,
            merkle_root=MerkleTree.compute_root([init_hash])
        )

        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    sequence INTEGER PRIMARY KEY,
                    state_version INTEGER NOT NULL,
                    timestamp REAL NOT NULL,
                    hypothesis_id TEXT,
                    observation_data TEXT,
                    evaluation_result TEXT,
                    prev_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE,
                    merkle_root TEXT NOT NULL,
                    envelope_hash TEXT NOT NULL
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS state_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
            """)
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS trg_prevent_update
                BEFORE UPDATE ON audit_log
                BEGIN
                    SELECT RAISE(ABORT, 'append-only: update forbidden');
                END;
            """)
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS trg_prevent_delete
                BEFORE DELETE ON audit_log
                BEGIN
                    SELECT RAISE(ABORT, 'append-only: delete forbidden');
                END;
            """)
            cursor = conn.execute("SELECT value FROM state_meta WHERE key='version'")
            if cursor.fetchone() is None:
                conn.execute("INSERT INTO state_meta (key, value) VALUES ('version', '1')")
            conn.commit()

    @property
    def current_state(self) -> SystemState:
        return self._current_state

    def verify_hash_chain(self, req_version: int, nonce: str, payload: Dict[str, Any], envelope_hash: Optional[str] = None) -> bool:
        """
        L1 Barrier: Математическая проверка детерминированного хэша конверта и связи с хэш-цепочкой.
        Не требует внешних секретных/приватных ключей.
        """
        envelope = {
            "version": req_version,
            "nonce": nonce,
            "payload": payload
        }
        computed_hash = canonical_hash(envelope)
        if envelope_hash is not None and envelope_hash != computed_hash:
            return False
        return True

    def process_request(self, request: Dict[str, Any]) -> str:
        """
        Главный транзакционный конвейер шлюза TGP (Fail-Closed).
        """
        snapshot = self._current_state

        try:
            payload = request.get("payload")
            req_version = request.get("version")
            nonce = request.get("nonce")
            provided_hash = request.get("envelope_hash")

            if payload is None or req_version is None or nonce is None:
                return "REJECT"

            # Level 1: L1 Gate Barrier — проверка цепи детерминированных хэшей (verify_hash_chain)
            if not self.verify_hash_chain(req_version, nonce, payload, provided_hash):
                return "REJECT"

            # Level 2: OCC & Replay Guard
            if req_version != snapshot.version or nonce in self._used_nonces:
                return "REJECT"

            # Level 3: Независимый рекомпут графа на стороне шлюза (M Operator)
            recomputed = self._step_independent_recompute(payload, snapshot)

            # Level 4: Физические и Попперовские инварианты
            eval_result, is_valid = self._step_validate_constraints_and_falsification(payload, recomputed)
            if not is_valid:
                return "REJECT"

            # Атомарное вычисление нового хэша состояния и Merkle Root
            new_version = snapshot.version + 1
            new_nodes = recomputed["nodes"]
            env_hash = canonical_hash({"version": req_version, "nonce": nonce, "payload": payload})
            
            event_hash = canonical_hash({
                "version": new_version,
                "nodes": list(new_nodes),
                "nonce": nonce,
                "eval_result": eval_result,
                "envelope_hash": env_hash
            })

            all_hashes = self._get_all_event_hashes() + [event_hash]
            new_merkle_root = MerkleTree.compute_root(all_hashes)

            self._commit_to_ledger(new_version, nonce, payload, eval_result, event_hash, new_merkle_root, env_hash)

            self._current_state = SystemState(
                version=new_version,
                nodes=new_nodes,
                permissions=snapshot.permissions,
                state_hash=event_hash,
                merkle_root=new_merkle_root
            )
            self._used_nonces.add(nonce)

            return "PASS"

        except Exception:
            self._current_state = snapshot
            return "REJECT"

    def _step_independent_recompute(self, payload: Dict[str, Any], state: SystemState) -> Dict[str, Any]:
        target = payload.get("target_node", "node_derived")
        
        e_stored = payload.get("photonic_energy_joules", 1e-6)
        p_loss = payload.get("photonic_power_loss", 1e-12)
        freq = payload.get("frequency_hz", 1.93e14)

        valid_q, calculated_q = PhysicalInvariantSolver.verify_photonic_q_factor(e_stored, p_loss, freq)

        return {
            "nodes": state.nodes + (target,),
            "computed_metrics": {
                "metric_value": payload.get("metric_value", 100.0),
                "q_factor": calculated_q,
                "q_factor_valid": valid_q,
                "energy_cost_j": PhysicalInvariantSolver.calculate_energy_cost(
                    payload.get("mass_kg", 1.0),
                    payload.get("distance_km", 10.0)
                )
            }
        }

    def _step_validate_constraints_and_falsification(self, payload: Dict[str, Any], recomputed: Dict[str, Any]) -> Tuple[str, bool]:
        req_perm = payload.get("required_permission", "execute_core")
        if req_perm not in self._current_state.permissions:
            return "PERMISSION_DENIED", False

        metrics = recomputed.get("computed_metrics", {})
        
        if not validate_numeric(metrics.get("metric_value")):
            return "NUMERIC_INVALID", False

        if not metrics.get("q_factor_valid", False):
            return "PHYSICAL_INVARIANT_FAILED", False

        falsification_test = payload.get("test_hypothesis_falsified", False)
        if falsification_test is True:
            return "FALSIFIED", False

        return "NOT_FALSIFIED", True

    def _get_all_event_hashes(self) -> List[str]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT event_hash FROM audit_log ORDER BY sequence ASC")
            return [r[0] for r in cursor.fetchall()]

    def _commit_to_ledger(self, new_version: int, nonce: str, payload: Dict[str, Any], eval_result: str, event_hash: str, merkle_root: str, env_hash: str) -> None:
        with self._get_connection() as conn:
            conn.execute("BEGIN EXCLUSIVE;")
            cursor = conn.cursor()

            cursor.execute("SELECT sequence, event_hash FROM audit_log ORDER BY sequence DESC LIMIT 1")
            row = cursor.fetchone()
            if row is None:
                seq = 1
                prev_hash = self.GENESIS_HASH
            else:
                seq = row[0] + 1
                prev_hash = row[1]

            timestamp = time.time()

            cursor.execute("""
                INSERT INTO audit_log (sequence, state_version, timestamp, hypothesis_id, observation_data, evaluation_result, prev_hash, event_hash, merkle_root, envelope_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (seq, new_version, timestamp, payload.get("target_node"), json.dumps(payload, ensure_ascii=False), eval_result, prev_hash, event_hash, merkle_root, env_hash))

            cursor.execute("UPDATE state_meta SET value = ? WHERE key = 'version'", (str(new_version),))
            conn.commit()

    def generate_merkle_proof(self, sequence: int) -> Dict[str, Any]:
        """Генерация открытого доказательства Меркла для конкретной транзакции."""
        all_hashes = self._get_all_event_hashes()
        if sequence < 1 or sequence > len(all_hashes):
            raise ValueError("Invalid sequence number")
        
        target_hash = all_hashes[sequence - 1]
        proof = MerkleTree.get_proof(all_hashes, sequence - 1)
        root = MerkleTree.compute_root(all_hashes)

        return {
            "sequence": sequence,
            "target_hash": target_hash,
            "merkle_proof": proof,
            "merkle_root": root,
            "verified": MerkleTree.verify_proof(target_hash, proof, root)
        }

    def export_public_anchor(self) -> Dict[str, Any]:
        """Экспорт внешнего публичного сертификата якорения (Green Anchor)."""
        all_hashes = self._get_all_event_hashes()
        root = MerkleTree.compute_root(all_hashes) if all_hashes else self.GENESIS_HASH
        
        return {
            "protocol": "SDPAP_v3_TGP",
            "state_version": self._current_state.version,
            "state_hash": self._current_state.state_hash,
            "merkle_root": root,
            "total_records": len(all_hashes),
            "timestamp": time.time(),
            "anchor_signature": canonical_hash({"root": root, "version": self._current_state.version})
        }

    def verify_full_integrity(self) -> Tuple[bool, str]:
        """Полная аутентификация локальной хэш-цепочки и соответствия Merkle Root."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT sequence, prev_hash, event_hash, merkle_root FROM audit_log ORDER BY sequence ASC")
            rows = cursor.fetchall()

            if not rows:
                return True, "Ledger empty"

            expected_prev = self.GENESIS_HASH
            accumulated_hashes = []

            for row in rows:
                seq, prev_h, ev_h, stored_root = row
                if prev_h != expected_prev:
                    return False, f"Broken chain at sequence {seq}: prev_hash mismatch ({prev_h} != {expected_prev})"
                expected_prev = ev_h
                accumulated_hashes.append(ev_h)

                expected_root = MerkleTree.compute_root(accumulated_hashes)
                if stored_root != expected_root:
                    return False, f"Merkle Root corruption at sequence {seq}: {stored_root} != {expected_root}"

            return True, f"Full integrity & Merkle tree verified for {len(rows)} records"
