"""
╔══════════════════════════════════════════════════════════════╗
║   TAMPER-EVIDENT AUDIT LEDGER — DevSecOps Lab                ║
║   So cai Kiem toan Chong Gia mao bang SHA-256                ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║   Thuat ngu hoc thuat:                                       ║
║     - "Blockchain" -> "Tamper-Evident Audit Ledger"          ║
║         (So cai Kiem toan Chong Gia mao)                     ║
║     - "Block"      -> "LedgerEntry" (Ban ghi So cai)         ║
║     - "block_height" -> "ledger_index"                       ║
║                                                              ║
║   Co che:                                                    ║
║     Moi ban ghi (LedgerEntry) duoc bao ve bang SHA-256       ║
║     cua chinh no VA hash cua ban ghi truoc do.               ║
║     Bat ky thay doi nao deu bi phat hien ngay lap tuc        ║
║     khi goi verify_ledger_integrity().                       ║
║                                                              ║
║   Luu moi su kien bao mat:                                   ║
║     - Phat hien lo hong (VULNERABILITY_DETECTED)             ║
║     - AI tao ban va (AI_PATCH_APPLIED)                       ║
║     - Build thanh cong (BUILD_SUCCESS)                       ║
║     - Build that bai + rollback (BUILD_FAILED / ROLLBACK)    ║
║     - Code duoc push len SCM (GIT_PUSHED)                    ║
║                                                              ║
║   Truy vet danh tinh (Actor Tracking):                       ║
║     Moi ban ghi ghi nhan truong "actor" — dinh danh          ║
║     cua nguoi hoac he thong thuc hien hanh dong.             ║
║     Actor duoc bao ve boi SHA-256 hash, khong the            ║
║     sua doi ma khong bi phat hien.                           ║
╚══════════════════════════════════════════════════════════════╝

Cach dung:
    from blockchain_ledger import SecurityLedger, EventType
    ledger = SecurityLedger()
    ledger.record_event(EventType.VULNERABILITY_DETECTED, {
        "vuln_id": 42, "title": "SQL Injection"
    }, actor="SonarQube")
    ledger.verify_ledger_integrity()

Tuong thich nguoc (backward compatible):
    add_event()    -> biet danh cua record_event()
    verify_chain() -> biet danh cua verify_ledger_integrity()
"""

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ─────────────────────────────────────────────────────────────
# EVENT TYPES (khong doi — la hang so domain, khong phai kien truc)
# ─────────────────────────────────────────────────────────────
class EventType:
    VULNERABILITY_DETECTED = "VULNERABILITY_DETECTED"
    SCA_VULNERABILITY_DETECTED = "SCA_VULNERABILITY_DETECTED"
    IAC_VULNERABILITY_DETECTED = "IAC_VULNERABILITY_DETECTED"
    AI_PATCH_APPLIED       = "AI_PATCH_APPLIED"
    BUILD_SUCCESS          = "BUILD_SUCCESS"
    BUILD_FAILED           = "BUILD_FAILED"
    ROLLBACK               = "ROLLBACK"
    GIT_PUSHED             = "GIT_PUSHED"
    DEPLOYMENT_SUCCESS     = "DEPLOYMENT_SUCCESS"
    INTEGRATION_TEST_PASSED= "INTEGRATION_TEST_PASSED"
    INTEGRATION_TEST_FAILED= "INTEGRATION_TEST_FAILED"
    LEDGER_INITIALIZED     = "LEDGER_INITIALIZED"      # doi tu CHAIN_INITIALIZED
    VERIFICATION_PASSED    = "VERIFICATION_PASSED"
    VERIFICATION_FAILED    = "VERIFICATION_FAILED"

    # Human-in-the-Loop approval/deployment events
    PATCH_CREATED          = "PATCH_CREATED"
    PATCH_APPROVAL_REQUESTED = "PATCH_APPROVAL_REQUESTED"
    PATCH_APPROVED         = "PATCH_APPROVED"
    PATCH_REJECTED         = "PATCH_REJECTED"
    PATCH_MERGED           = "PATCH_MERGED"
    DEPLOY_STARTED         = "DEPLOY_STARTED"
    DEPLOY_SUCCESS         = "DEPLOY_SUCCESS"
    DEPLOY_FAILED          = "DEPLOY_FAILED"

    # Alias giu tuong thich nguoc
    CHAIN_INITIALIZED = LEDGER_INITIALIZED


# ─────────────────────────────────────────────────────────────
# LEDGER ENTRY  (truoc day goi la "Block")
# ─────────────────────────────────────────────────────────────
class LedgerEntry:
    """
    Mot ban ghi don trong So cai Kiem toan.

    Thuat ngu hoc thuat:
        - "LedgerEntry" thay cho "Block" — mo ta chinh xac hon
          rang day la mot ban ghi trong so sach ke toan
        - "ledger_index" thay cho "block_height" / "index"
        - "entry_hash" thay cho "block_hash"
        - "previous_entry_hash" thay cho "previous_hash"

    Bao mat:
        entry_hash = SHA-256( ledger_index | timestamp | actor |
                              event_type | data | previous_entry_hash )
        => Thay doi bat ky truong nao (ke ca actor) lam hash khong con khop.
    """

    def __init__(
        self,
        ledger_index: int,
        timestamp: str,
        event_type: str,
        data: Dict[str, Any],
        previous_entry_hash: str,
        actor: str = "SYSTEM",
    ):
        self.ledger_index        = ledger_index
        self.timestamp           = timestamp
        self.event_type          = event_type
        self.data                = data
        self.previous_entry_hash = previous_entry_hash
        self.actor               = actor
        self.entry_hash          = self._calculate_hash()

    def _calculate_hash(self) -> str:
        """SHA-256 tren tat ca cac truong ke ca actor (canonical JSON, sorted keys)."""
        content = {
            "ledger_index":        self.ledger_index,
            "timestamp":           self.timestamp,
            "actor":               self.actor,
            "event_type":          self.event_type,
            "data":                self.data,
            "previous_entry_hash": self.previous_entry_hash,
        }
        raw = json.dumps(content, sort_keys=True, ensure_ascii=False, separators=(',', ':'))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Xuat ban ghi ra dict JSON voi ten truong hoc thuat."""
        return {
            "ledger_index":        self.ledger_index,
            "timestamp":           self.timestamp,
            "actor":               self.actor,
            "event_type":          self.event_type,
            "data":                self.data,
            "previous_entry_hash": self.previous_entry_hash,
            "entry_hash":          self.entry_hash,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "LedgerEntry":
        """Tai lai ban ghi tu dict JSON (ho tro ca dinh dang cu lan moi)."""
        # Ho tro dinh dang cu (truong "index", "hash", "previous_hash")
        ledger_index        = d.get("ledger_index", d.get("index", 0))
        previous_entry_hash = d.get("previous_entry_hash", d.get("previous_hash", "0" * 64))
        actor               = d.get("actor", "SYSTEM")  # Mac dinh SYSTEM cho entry cu

        entry = cls(
            ledger_index        = ledger_index,
            timestamp           = d["timestamp"],
            event_type          = d["event_type"],
            data                = d["data"],
            previous_entry_hash = previous_entry_hash,
            actor               = actor,
        )
        # Bao ton hash da luu de kiem tra toan ven
        entry.entry_hash = d.get("entry_hash", d.get("hash", entry.entry_hash))
        return entry


# ─────────────────────────────────────────────────────────────
# AUDIT LEDGER  (truoc day goi la "SecurityLedger" / "Blockchain")
# ─────────────────────────────────────────────────────────────
class AuditLedger:
    """
    So cai Kiem toan Chong Gia mao (Tamper-Evident Audit Ledger).

    Thuat ngu hoc thuat:
        "AuditLedger" = co che ghi chep so sach duoc chung thuc
        bang mat ma, trong do moi ban ghi lien ket voi ban ghi
        truoc no qua SHA-256. Bat ky can thiep nao vao du lieu
        lich su deu bi phat hien qua ham verify_ledger_integrity().

    So cai duoc luu ra file JSON va tu dong load lai khi khoi dong.

    Phan biet voi Blockchain phan tan:
        Day la mot "single-node append-only tamper-evident log",
        khac voi Blockchain phan tan (distributed ledger) o cho
        khong co co che dong thuan (consensus) hay mang ngang hang.
        Muc dich: dam bao audit trail noi bo khong the bi sua doi
        ma khong bi phat hien.
    """

    LEDGER_FILE = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "security_audit_ledger.json"
    )

    def __init__(self, ledger_file: Optional[str] = None):
        if ledger_file:
            self.LEDGER_FILE = ledger_file
        self.entries: List[LedgerEntry] = []
        self._lock = threading.RLock()  # RLock: tranh deadlock khi verify re-enter record_event
        self._load_or_create()

    # ── Persistence ───────────────────────────────────────────

    def _load_or_create(self):
        """Load so cai tu file neu ton tai, tao Genesis Entry neu chua co."""
        # Ho tro ca ten file cu (security_audit_chain.json)
        legacy_file = self.LEDGER_FILE.replace(
            "security_audit_ledger.json", "security_audit_chain.json"
        )

        source_file = None
        if os.path.exists(self.LEDGER_FILE):
            source_file = self.LEDGER_FILE
        elif os.path.exists(legacy_file):
            source_file = legacy_file
            print(f"[Ledger] Tim thay file cu '{legacy_file}', dang migrate...")

        if source_file:
            try:
                with open(source_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.entries = [LedgerEntry.from_dict(b) for b in data]
                print(f"[Ledger] So cai da tai: {len(self.entries)} ban ghi "
                      f"tu '{source_file}'")
                if source_file == legacy_file:
                    self._save()
                    print(f"[Ledger] Da migrate sang '{self.LEDGER_FILE}'")
                if len(self.entries) > 0:
                    return
            except (json.JSONDecodeError, KeyError) as e:
                print(f"[!] File so cai bi hong: {e} — Tao so cai moi.")

        # Tao so cai moi
        self.entries = []
        self._create_genesis_entry()

    def _save(self):
        """Luu toan bo so cai ra file JSON (atomic write — tranh crash giau giua chung)."""
        tmp_path = self.LEDGER_FILE + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(
                [e.to_dict() for e in self.entries],
                f, indent=2, ensure_ascii=False,
            )
            f.flush()
            try:
                os.fsync(f.fileno())  # dam bao byte da xuong dia
            except OSError:
                pass
        import time
        for attempt in range(10):
            try:
                os.replace(tmp_path, self.LEDGER_FILE)  # atomic tren Windows va Unix
                break
            except OSError as e:
                if attempt == 9:
                    print(f"[Ledger] Error replacing ledger file after 10 attempts: {e}")
                    raise e
                time.sleep(0.1)

    # ── Genesis ───────────────────────────────────────────────

    def _create_genesis_entry(self):
        """Tao ban ghi khoi dau (Genesis Entry) — goc cua chuoi hash."""
        genesis = LedgerEntry(
            ledger_index        = 0,
            timestamp           = "2026-06-21T11:40:59.823084+00:00",
            event_type          = EventType.LEDGER_INITIALIZED,
            data                = {
                "message": "DevSecOps Tamper-Evident Audit Ledger — Genesis Entry",
                "project": "DevSecOpsLab",
                "version": "3.0.0",
                "note":    "SHA-256 chained entries with actor tracking, single-node append-only log",
            },
            previous_entry_hash = "0" * 64,
            actor               = "SYSTEM",
        )
        self.entries.append(genesis)
        self._save()
        print(f"[Ledger] Genesis Entry tao thanh cong "
              f"-> hash: {genesis.entry_hash[:16]}...")

    # ── Core API ──────────────────────────────────────────────

    def record_event(self, event_type: str, data: Dict[str, Any],
                     actor: str = "SYSTEM",
                     user_id: Optional[str] = None) -> LedgerEntry:
        """
        Ghi mot su kien bao mat moi vao So cai.

        Moi ban ghi moi duoc bao ve bang SHA-256 ket hop voi
        entry_hash cua ban ghi truoc (chaining), dam bao khong
        the chen, xoa, hoac sua doi bat ky ban ghi nao ma khong
        lam vo hieu toan bo chuoi hash phia sau.

        Args:
            event_type : Mot trong cac hang so EventType
            data       : Dict chua thong tin chi tiet su kien
            actor      : Dinh danh nguoi/he thong thuc hien hanh dong
                         (vd: "PIPELINE", "AI_ENGINE", "admin@company.com")
            user_id    : (Optional) ID nguoi dung/service account thuc hien
                         hanh dong (vd: Keycloak sub claim, username).
                         Duoc ghi vao truong data.user_id — bao ve boi SHA-256.

        Returns:
            LedgerEntry vua duoc them vao so cai
        """
        with self._lock:
            # Inject user_id vao data payload neu duoc cung cap
            if user_id is not None:
                data = {**data, "user_id": user_id}

            previous_entry      = self.entries[-1]
            new_entry = LedgerEntry(
                ledger_index        = len(self.entries),
                timestamp           = self._now(),
                event_type          = event_type,
                data                = data,
                previous_entry_hash = previous_entry.entry_hash,
                actor               = actor,
            )
            self.entries.append(new_entry)
            self._save()

        icon = self._event_icon(event_type)
        uid_info = f" user_id={user_id}" if user_id else ""
        print(f"[Ledger] #{new_entry.ledger_index:04d} {icon} "
              f"[{event_type}] actor={actor}{uid_info} -> {new_entry.entry_hash[:16]}...")
        return new_entry

    # Alias tuong thich nguoc
    def add_event(self, event_type: str, data: Dict[str, Any],
                  actor: str = "SYSTEM",
                  user_id: Optional[str] = None) -> LedgerEntry:
        """Alias cua record_event() — giu tuong thich nguoc."""
        return self.record_event(event_type, data, actor=actor, user_id=user_id)

    def verify_ledger_integrity(self) -> bool:
        """
        Kiem tra tinh toan ven cua toan bo So cai Kiem toan.

        Thuat toan:
            Voi moi ban ghi i (tu 0 den n):
              1. Tinh lai entry_hash tu cac truong du lieu
              2. So sanh voi entry_hash da luu — neu khac -> bi gia mao
              3. Neu i > 0: kiem tra previous_entry_hash == entries[i-1].entry_hash
                 => dam bao chuoi hash lien tuc, khong bi chen/xoa

        Returns:
            True  : So cai nguyen ven, khong bi can thiep
            False : Phat hien can thiep, da ghi log canh bao
        """
        print(f"\n[Ledger] {'='*50}")
        print(f"[Ledger] Kiem tra toan ven So cai Kiem toan...")
        print(f"[Ledger] Tong so ban ghi: {len(self.entries)}")
        print(f"[Ledger] {'='*50}")

        # Lock để tránh race condition với record_event() chạy đồng thời
        with self._lock:
            # Anchor check: Kiểm tra block Genesis có khớp mã băm gốc cố định không
            GENESIS_HASH = "9dd0b15d19e0e03e72b671f8c8e4dcacc5ec30f9f15cac4a589748bd57232784"
            if len(self.entries) > 0:
                if self.entries[0].entry_hash != GENESIS_HASH:
                    print("[CANH BAO] Genesis block hash khong khop! Ledger da bi thay the hoan toan.")
                    self.record_event(EventType.VERIFICATION_FAILED, {
                        "reason": "Genesis block hash mismatch",
                        "severity": "CRITICAL",
                    }, actor="INTEGRITY_CHECKER")
                    return False

            # i bắt đầu từ 0 để BAO GỒM cả Genesis (trước đây bị bỏ qua ở
            # range(1, ...) — attacker có thể sửa Genesis mà không bị phát hiện).
            for i in range(len(self.entries)):
                current  = self.entries[i]

                # Bước 1: Kiểm tra entry_hash (áp dụng cho MỌI entry kể cả Genesis)
                expected_hash = current._calculate_hash()
                if current.entry_hash != expected_hash:
                    print(f"[CANH BAO] Ban ghi #{i} BI GIA MAO! Hash khong khop.")
                    print(f"    Luu tru:   {current.entry_hash}")
                    print(f"    Tinh toan: {expected_hash}")
                    self.record_event(EventType.VERIFICATION_FAILED, {
                        "tampered_ledger_index": i,
                        "stored_hash":           current.entry_hash,
                        "expected_hash":         expected_hash,
                        "severity":              "CRITICAL",
                    }, actor="INTEGRITY_CHECKER")
                    return False

                # Bước 2: Kiểm tra liên kết với bản ghi trước (bỏ qua Genesis)
                if i > 0:
                    previous = self.entries[i - 1]
                    if current.previous_entry_hash != previous.entry_hash:
                        print(f"[CANH BAO] Ban ghi #{i}: Chuoi hash bi dut gay!")
                        print(f"    previous_entry_hash luu: {current.previous_entry_hash[:16]}...")
                        print(f"    entry_hash cua #{i-1}:   {previous.entry_hash[:16]}...")
                        self.record_event(EventType.VERIFICATION_FAILED, {
                            "broken_chain_at_index": i,
                            "severity":              "CRITICAL",
                        }, actor="INTEGRITY_CHECKER")
                        return False

        print(f"[Ledger] TOAN VEN OK — {len(self.entries)} ban ghi da kiem tra.")
        self.record_event(EventType.VERIFICATION_PASSED, {
            "entries_verified": len(self.entries),
            "result":           "INTEGRITY_OK",
        }, actor="INTEGRITY_CHECKER")
        return True

    # Alias tuong thich nguoc
    def verify_chain(self) -> bool:
        """Alias cua verify_ledger_integrity() — giu tuong thich nguoc."""
        return self.verify_ledger_integrity()

    def get_ledger(self) -> List[Dict[str, Any]]:
        """Tra ve toan bo so cai duoi dang list of dicts (dinh dang moi)."""
        return [e.to_dict() for e in self.entries]

    # Alias tuong thich nguoc
    def get_chain(self) -> List[Dict[str, Any]]:
        """Alias cua get_ledger() — giu tuong thich nguoc."""
        return self.get_ledger()

    def get_stats(self) -> Dict[str, Any]:
        """Thong ke nhanh ve So cai Kiem toan."""
        event_counts: Dict[str, int] = {}
        for entry in self.entries:
            et = entry.event_type
            event_counts[et] = event_counts.get(et, 0) + 1

        total_vulns    = event_counts.get(EventType.VULNERABILITY_DETECTED, 0)
        total_builds   = (event_counts.get(EventType.BUILD_SUCCESS, 0) +
                          event_counts.get(EventType.BUILD_FAILED,  0))
        success_builds = event_counts.get(EventType.BUILD_SUCCESS, 0)

        return {
            "total_entries":      len(self.entries),   # doi tu total_blocks
            "event_breakdown":    event_counts,
            "total_vulns_found":  total_vulns,
            "total_builds":       total_builds,
            "build_success_rate": (
                f"{round(success_builds / total_builds * 100, 1)}%"
                if total_builds > 0 else "N/A"
            ),
            "ledger_file":        self.LEDGER_FILE,
            "integrity_note":     "SHA-256 chained entries — Tamper-Evident",
        }

    def print_ledger(self):
        """In toan bo So cai ra console (debug / demo)."""
        print("\n" + "═" * 65)
        print("  SO CAI KIEM TOAN CHONG GIA MAO — TAMPER-EVIDENT AUDIT LEDGER")
        print("═" * 65)
        for entry in self.entries:
            icon = self._event_icon(entry.event_type)
            print(f"\n  Ban ghi #{entry.ledger_index:04d}  {icon}  [{entry.event_type}]")
            print(f"  Actor     : {entry.actor}")
            print(f"  Thoi gian : {entry.timestamp}")
            print(f"  Hash      : {entry.entry_hash[:32]}...")
            print(f"  Hash truoc: {entry.previous_entry_hash[:32]}...")
            print(f"  Du lieu   : {json.dumps(entry.data, ensure_ascii=False)[:120]}")
        print("\n" + "═" * 65)

    # Alias tuong thich nguoc
    def print_chain(self):
        """Alias cua print_ledger() — giu tuong thich nguoc."""
        self.print_ledger()

    # ── Helpers ───────────────────────────────────────────────

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _event_icon(event_type: str) -> str:
        icons = {
            EventType.VULNERABILITY_DETECTED: "VULN",
            EventType.SCA_VULNERABILITY_DETECTED: "SCA ",
            EventType.IAC_VULNERABILITY_DETECTED: "IaC ",
            EventType.AI_PATCH_APPLIED:       "AI  ",
            EventType.BUILD_SUCCESS:          "OK  ",
            EventType.BUILD_FAILED:           "FAIL",
            EventType.ROLLBACK:               "BACK",
            EventType.GIT_PUSHED:             "PUSH",
            EventType.DEPLOYMENT_SUCCESS:     "DEPL",
            EventType.INTEGRATION_TEST_PASSED:"TEST",
            EventType.INTEGRATION_TEST_FAILED:"T_FL",
            EventType.LEDGER_INITIALIZED:     "INIT",
            EventType.VERIFICATION_PASSED:    "LOCK",
            EventType.VERIFICATION_FAILED:    "WARN",
            EventType.PATCH_CREATED:          "CRTD",
            EventType.PATCH_APPROVAL_REQUESTED: "REQS",
            EventType.PATCH_APPROVED:         "APRV",
            EventType.PATCH_REJECTED:         "REJC",
            EventType.PATCH_MERGED:           "MRGD",
            EventType.DEPLOY_STARTED:         "DP_S",
            EventType.DEPLOY_SUCCESS:         "DP_K",
            EventType.DEPLOY_FAILED:          "DP_F",
        }
        return icons.get(event_type, "LOG ")


# Alias tuong thich nguoc: giu ten cu SecurityLedger de khong can sua import
SecurityLedger = AuditLedger


# ─────────────────────────────────────────────────────────────
# STANDALONE DEMO / SELF-TEST
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import tempfile

    print("╔═══════════════════════════════════════════════════════╗")
    print("║  TAMPER-EVIDENT AUDIT LEDGER — Self-Test & Demo       ║")
    print("╚═══════════════════════════════════════════════════════╝\n")

    demo_file = os.path.join(tempfile.gettempdir(), "demo_audit_ledger.json")
    if os.path.exists(demo_file):
        os.remove(demo_file)

    ledger = AuditLedger(ledger_file=demo_file)

    print("\n--- Mo phong chu ky DevSecOps hoan chinh ---")

    ledger.record_event(EventType.VULNERABILITY_DETECTED, {
        "vuln_id":   101,
        "title":     "SQL Injection via string concatenation",
        "severity":  "High",
        "file":      "src/main/java/com/devsecops/UserController.java",
        "line":      42,
        "source":    "DefectDojo",
    }, actor="SonarQube")

    ledger.record_event(EventType.AI_PATCH_APPLIED, {
        "vuln_id":   101,
        "model":     "qwen2.5-coder:7b",
        "strategy":  "RAG + Secure_Coding_Guidelines.txt",
        "cwe":       "CWE-89",
        "patch_len": 1234,
    }, actor="AI_ENGINE")

    ledger.record_event(EventType.BUILD_SUCCESS, {
        "tool":      "Maven",
        "gates":     ["Compile OK", "Unit Tests OK", "Semgrep SAST OK"],
        "duration_s": 18.7,
    }, actor="PIPELINE")

    ledger.record_event(EventType.GIT_PUSHED, {
        "branch":    "hotfix/vuln_101",
        "remote":    "origin",
        "scm":       "OneDev",
        "auto_merged": True,
    }, actor="PIPELINE")

    # In so cai
    ledger.print_ledger()

    # Kiem tra toan ven
    is_valid = ledger.verify_ledger_integrity()
    print(f"\n[Ket qua] So cai toan ven: {is_valid}")

    # Thong ke
    stats = ledger.get_stats()
    print(f"\n[Thong ke]\n{json.dumps(stats, indent=2, ensure_ascii=False)}")

    # Demo phat hien gia mao
    print("\n--- Demo Phat hien Gia mao ---")
    print("[!] Gia mao du lieu ban ghi #1...")
    ledger.entries[1].data["title"] = "HACKED — gia mao"
    is_valid_after = ledger.verify_ledger_integrity()
    print(f"[Ket qua] Sau khi gia mao: {is_valid_after}")
    print("\n[OK] Self-test hoan tat!")

    if os.path.exists(demo_file):
        os.remove(demo_file)
