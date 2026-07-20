"""
╔══════════════════════════════════════════════════════════════════╗
║   EXPERIMENT RUNNER — DevSecOps Research Evaluation Tool        ║
║   Đo lường & So sánh hiệu quả hai pipeline AI tự động vá lỗi   ║
╚══════════════════════════════════════════════════════════════════╝

Chức năng:
  - Chạy thực nghiệm với nhiều loại lỗ hổng bảo mật khác nhau
  - Đo lường thời gian xử lý từng bước của 2 pipeline:
      Pipeline A: OpenAI GPT (Cloud)
      Pipeline B: RAG + Ollama qwen2.5-coder:7b (Local)
  - Xuất kết quả ra experiment_results.json và bảng ASCII đẹp
  - Tích hợp với Audit Ledger để ghi nhận thực nghiệm

Chế độ:
  --mode demo   : Chạy với dữ liệu mô phỏng (không cần DefectDojo)
  --mode live   : Chạy với dữ liệu thực từ DefectDojo (mặc định)
  --pipeline A  : Chỉ chạy pipeline OpenAI
  --pipeline B  : Chỉ chạy pipeline RAG+Ollama
  --pipeline all: Chạy cả 2 (mặc định)

Ví dụ:
  python experiment_runner.py --mode demo
  python experiment_runner.py --mode live --pipeline B
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

# ─── AUTO-LOAD .env ───────────────────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    _env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.exists(_env_path):
        load_dotenv(_env_path, override=False)
except ImportError:
    pass

# ─── AUDIT LEDGER ─────────────────────────────────────────────────────────────
from blockchain_ledger import SecurityLedger, EventType

# ─── TELEGRAM ─────────────────────────────────────────────────────────────────
from telegram_notifier import TelegramNotifier

# ─── FIREBASE SYNC ────────────────────────────────────────────────────────────
try:
    import firebase_sync
    FIREBASE_ENABLED = True
except ImportError:
    FIREBASE_ENABLED = False

# ─── CONFIG ───────────────────────────────────────────────────────────────────
from pathlib import Path
_PROJECT_ROOT        = str(Path(__file__).resolve().parent)
PROJECT_PATH         = os.path.join(_PROJECT_ROOT, "vulnerable-spring-boot")
TARGET_FILE_RELATIVE = "src/main/java/com/devsecops/UserController.java"  # fallback
TARGET_FILE_FULL     = os.path.join(PROJECT_PATH, TARGET_FILE_RELATIVE)
RESULTS_FILE         = os.path.join(os.path.dirname(__file__), "experiment_results.json")
GUIDELINES_PATH      = os.path.join(os.path.dirname(__file__), "Secure_Coding_Guidelines.txt")

# ─── ZERO TRUST SECRET LOADING — 3 tầng ──────────────────────────────────────
def _load_secrets() -> dict:
    """
    [Zero Trust] Load DefectDojo credentials theo thứ tự:
      Layer 1: AWS Secrets Manager (Floci)
      Layer 2: HashiCorp Vault
      Layer 3: Environment Variables
    Không bao giờ hardcode token trong source code.
    """
    # Layer 1: AWS Secrets Manager (Floci)
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from aws_secrets_client import AWSSecretsClient
        aws   = AWSSecretsClient()
        token = aws.get_secret("dojo_token")
        url   = aws.get_secret("dojo_url") or "http://localhost:8080"
        if token:
            print("[Zero Trust][✓] Credentials loaded từ AWS Secrets Manager (Layer 1)")
            return {"dojo_token": token, "dojo_url": url}
    except SystemExit:
        pass
    except Exception as e:
        print(f"[Zero Trust][L1] AWS Secrets Manager lỗi: {e}")

    # Layer 2: HashiCorp Vault
    try:
        from vault_client import VaultClient
        vault = VaultClient()
        token = vault.get_secret("dojo_token")
        url   = vault.get_secret("dojo_url") or "http://localhost:8080"
        if token:
            print("[Zero Trust][✓] Credentials loaded từ HashiCorp Vault (Layer 2)")
            return {"dojo_token": token, "dojo_url": url}
    except SystemExit:
        pass
    except Exception as e:
        print(f"[Zero Trust][L2] Vault lỗi: {e}")

    # Layer 3: Environment Variables (chỉ là fallback cuối cùng)
    token = os.getenv("DEFECTDOJO_TOKEN", "")
    url   = os.getenv("DEFECTDOJO_URL", "http://localhost:8080")
    if not token or token.startswith("__"):
        print("[Zero Trust][✗] FAIL-SECURE: Token la placeholder hoac rong.")
        print("[Zero Trust]    DEFECTDOJO_TOKEN=", repr(token))
        print("[Zero Trust]    → Set token that trong .env hoac khoi dong Vault/Floci.")
        sys.exit(1)
    print("[Zero Trust][WARN] Fallback Layer 3 (Environment Variables) - không khuyến khích")
    return {"dojo_token": token, "dojo_url": url}


# Load secrets tại module level (chạy một lần khi import)
_secrets      = _load_secrets()
DOJO_BASE_URL = _secrets["dojo_url"]
DOJO_URL      = (
    f"{DOJO_BASE_URL}/api/v2/findings/"
    "?test__engagement__product__name=Vulnerable-SpringBoot-App"
    "&active=true&severity=High"
)
DOJO_HEADERS  = {
    "Authorization": f"Token {_secrets['dojo_token']}",
    "Accept": "application/json",
}

# ─── DYNAMIC FILE RESOLVER ────────────────────────────────────────────────────
_JAVA_FILE_MAP = {
    "UserController":    "src/main/java/com/devsecops/UserController.java",
    "ProductController": "src/main/java/com/devsecops/ProductController.java",
    "AuthController":    "src/main/java/com/devsecops/AuthController.java",
    "PingController":    "src/main/java/com/devsecops/PingController.java",
    "FileController":    "src/main/java/com/devsecops/FileController.java",
    "OrderController":   "src/main/java/com/devsecops/OrderController.java",
    "WebhookController": "src/main/java/com/devsecops/WebhookController.java",
    "XmlController":     "src/main/java/com/devsecops/XmlController.java",
    "JwtUtils":          "src/main/java/com/devsecops/JwtUtils.java",
    "SessionController": "src/main/java/com/devsecops/SessionController.java",
    "ReportController":  "src/main/java/com/devsecops/ReportController.java",
    "CacheController":   "src/main/java/com/devsecops/CacheController.java",
    "CryptoController":  "src/main/java/com/devsecops/CryptoController.java",
}


def _resolve_file(vuln: dict) -> str:
    """
    [Dynamic] Xác định file Java cần vá từ thông tin finding.
    Dùng cho live mode để AI vá đúng file thay vì luôn vá UserController.
    """
    # 1. file_path trực tiếp
    fp = vuln.get("file_path") or ""
    if fp and "java" in fp.lower():
        rel = fp.replace("\\", "/")
        if "src/main" in rel:
            return rel[rel.index("src/main"):]
        return rel

    # 2. component (dạng: com.devsecops.XyzController)
    comp = (vuln.get("component") or "").lower()
    for cls, path in _JAVA_FILE_MAP.items():
        if cls.lower() in comp:
            return path

    # 3. title của finding
    title = (vuln.get("title") or vuln.get("vuln_title") or "").lower()
    for cls, path in _JAVA_FILE_MAP.items():
        if cls.lower() in title:
            return path

    # 4. trường "file" (dùng trong DEMO_VULNERABILITIES)
    file_field = (vuln.get("file") or "").lower()
    for cls, path in _JAVA_FILE_MAP.items():
        if cls.lower().replace("controller", "") in file_field:
            return path

    return TARGET_FILE_RELATIVE  # fallback

# ─── MÔ PHỎNG LỖ HỔNG (Demo Mode) ────────────────────────────────────────────
DEMO_VULNERABILITIES = [
    {
        "id": 1001,
        "title": "SQL Injection via String Concatenation",
        "severity": "High",
        "cwe": "CWE-89",
        "owasp": "A03:2021",
        "description": "Câu lệnh SQL được xây dựng bằng cách nối chuỗi trực tiếp với input người dùng, cho phép attacker inject mã SQL tùy ý.",
        "file": "UserController.java",
        "sonar_rule": "java:S2077",
    },
    {
        "id": 1002,
        "title": "Hardcoded Credentials (DB Password)",
        "severity": "High",
        "cwe": "CWE-798",
        "owasp": "A07:2021",
        "description": "Mật khẩu cơ sở dữ liệu được hardcode trực tiếp trong mã nguồn, lộ thông tin nhạy cảm trong source control.",
        "file": "UserController.java",
        "sonar_rule": "java:S2068",
    },
    {
        "id": 1003,
        "title": "Resource Leak - Connection Not Closed",
        "severity": "High",
        "cwe": "CWE-772",
        "owasp": "A04:2021",
        "description": "Kết nối JDBC không được đóng trong khối finally, gây rò rỉ tài nguyên và có thể làm cạn kiệt connection pool.",
        "file": "UserController.java",
        "sonar_rule": "java:S2095",
    },
    {
        "id": 1004,
        "title": "Cross-Site Scripting (XSS) - Reflected",
        "severity": "High",
        "cwe": "CWE-79",
        "owasp": "A03:2021",
        "description": "Input người dùng được phản chiếu trực tiếp vào HTML response mà không encode, cho phép attacker inject script độc hại.",
        "file": "ProductController.java",
        "sonar_rule": "java:S5131",
    },
    {
        "id": 1005,
        "title": "Weak Cryptographic Hash (MD5)",
        "severity": "High",
        "cwe": "CWE-327",
        "owasp": "A02:2021",
        "description": "Thuật toán MD5 được sử dụng để hash mật khẩu. MD5 đã bị phá vỡ từ năm 1996 và không an toàn cho mục đích bảo mật.",
        "file": "AuthController.java",
        "sonar_rule": "java:S4790",
    },
    {
        "id": 1006,
        "title": "OS Command Injection",
        "severity": "Critical",
        "cwe": "CWE-78",
        "owasp": "A03:2021",
        "description": "Thực thi lệnh hệ thống (OS) bằng cách truyền chuỗi không kiểm duyệt từ input vào Runtime.exec().",
        "file": "PingController.java",
        "sonar_rule": "java:S2076",
    },
    {
        "id": 1007,
        "title": "Unrestricted File Upload",
        "severity": "High",
        "cwe": "CWE-434",
        "owasp": "A04:2021",
        "description": "Upload file không kiểm tra định dạng và Path Traversal không kiểm duyệt tên file cẩn thận.",
        "file": "FileController.java",
        "sonar_rule": "java:S2083",
    },
    {
        "id": 1008,
        "title": "Insecure Direct Object Reference (IDOR)",
        "severity": "High",
        "cwe": "CWE-284",
        "owasp": "A01:2021",
        "description": "Truy xuất kết quả DB dựa trên object reference từ input mà không xác thực quyền sở hữu.",
        "file": "OrderController.java",
        "sonar_rule": "java:S4499",
    },
    {
        "id": 1009,
        "title": "Server-Side Request Forgery (SSRF)",
        "severity": "High",
        "cwe": "CWE-918",
        "owasp": "A10:2021",
        "description": "Thực hiện HTTP URL connection từ đầu vào của người dùng mà không qua whitelist an toàn.",
        "file": "WebhookController.java",
        "sonar_rule": "java:S5144",
    },
    {
        "id": 1010,
        "title": "XML External Entity (XXE)",
        "severity": "High",
        "cwe": "CWE-611",
        "owasp": "A05:2021",
        "description": "Parse XML sử dụng DocumentBuilder mà không vô hiệu hóa external entities và DTDs.",
        "file": "XmlController.java",
        "sonar_rule": "java:S2755",
    },
    {
        "id": 1011,
        "title": "Use of Hard-coded Cryptographic Key",
        "severity": "Critical",
        "cwe": "CWE-321",
        "owasp": "A02:2021",
        "description": "Thiết lập chữ ký cho JWT bằng mật khẩu tĩnh, định sẵn và quá yếu trong source code.",
        "file": "JwtUtils.java",
        "sonar_rule": "java:S2068",
    }
]

# ─── PIPELINE SIMULATION DATA (cho chế độ demo không cần AI thực) ─────────────
SIMULATED_RESULTS = {
    1001: {
        "pipeline_A": {"patch_found": True,  "build_success": True,  "time_s": 8.3,  "patch_len": 1847},
        "pipeline_B": {"patch_found": True,  "build_success": True,  "time_s": 18.7, "patch_len": 1923},
    },
    1002: {
        "pipeline_A": {"patch_found": True,  "build_success": True,  "time_s": 6.9,  "patch_len": 1654},
        "pipeline_B": {"patch_found": True,  "build_success": True,  "time_s": 15.2, "patch_len": 1702},
    },
    1003: {
        "pipeline_A": {"patch_found": True,  "build_success": True,  "time_s": 7.4,  "patch_len": 2103},
        "pipeline_B": {"patch_found": True,  "build_success": True,  "time_s": 22.1, "patch_len": 2241},
    },
    1004: {
        "pipeline_A": {"patch_found": True,  "build_success": False, "time_s": 9.1,  "patch_len": 2319},
        "pipeline_B": {"patch_found": True,  "build_success": True,  "time_s": 21.4, "patch_len": 2156},
    },
    1005: {
        "pipeline_A": {"patch_found": True,  "build_success": True,  "time_s": 7.8,  "patch_len": 2567},
        "pipeline_B": {"patch_found": False, "build_success": False, "time_s": 19.8, "patch_len": 0},
    },
    1006: {
        "pipeline_A": {"patch_found": True,  "build_success": True,  "time_s": 8.1,  "patch_len": 2410},
        "pipeline_B": {"patch_found": True,  "build_success": True,  "time_s": 25.4, "patch_len": 2480},
    },
    1007: {
        "pipeline_A": {"patch_found": True,  "build_success": True,  "time_s": 7.3,  "patch_len": 1820},
        "pipeline_B": {"patch_found": True,  "build_success": True,  "time_s": 19.5, "patch_len": 1910},
    },
    1008: {
        "pipeline_A": {"patch_found": True,  "build_success": False, "time_s": 6.8,  "patch_len": 2100},
        "pipeline_B": {"patch_found": True,  "build_success": True,  "time_s": 16.2, "patch_len": 2045},
    },
    1009: {
        "pipeline_A": {"patch_found": True,  "build_success": True,  "time_s": 9.5,  "patch_len": 2855},
        "pipeline_B": {"patch_found": True,  "build_success": True,  "time_s": 27.8, "patch_len": 2700},
    },
    1010: {
        "pipeline_A": {"patch_found": True,  "build_success": True,  "time_s": 8.4,  "patch_len": 2690},
        "pipeline_B": {"patch_found": True,  "build_success": True,  "time_s": 22.4, "patch_len": 2715},
    },
    1011: {
        "pipeline_A": {"patch_found": True,  "build_success": True,  "time_s": 6.5,  "patch_len": 1540},
        "pipeline_B": {"patch_found": True,  "build_success": True,  "time_s": 14.1, "patch_len": 1650},
    },
}


# ═══════════════════════════════════════════════════════════════════════════════
# EXPERIMENT RUNNER CLASS
# ═══════════════════════════════════════════════════════════════════════════════
class ExperimentRunner:
    def __init__(self, mode: str = "demo", pipeline: str = "all"):
        self.mode     = mode
        self.pipeline = pipeline
        self.ledger   = SecurityLedger()
        self.notifier = TelegramNotifier()
        self.results: List[Dict[str, Any]] = []
        self.start_time = datetime.now().isoformat()

    def run(self):
        self._banner()

        if self.mode == "demo":
            print()
            print("=" * 62)
            print("  [!] DEMO MODE — KET QUA MO PHONG (SIMULATED), KHONG PHAI AI THUC")
            print("      De chay AI that:  python experiment_runner.py --mode live")
            print("=" * 62)
            print()
        else:
            print()
            print("=" * 62)
            print("  [LIVE MODE] Dang goi AI that (Ollama / OpenAI that)")
            print("=" * 62)
            print()

        if FIREBASE_ENABLED:
            firebase_sync.clear_old_results()

        # 1. Lấy danh sách lỗ hổng
        vulns = self._get_vulnerabilities()
        if not vulns:
            print("[✗] Không tìm thấy lỗ hổng nào để thực nghiệm.")
            return

        print(f"\n[*] Tổng số lỗ hổng: {len(vulns)}")
        print(f"[*] Pipeline: {self.pipeline.upper()}")
        print(f"[*] Chế độ:   {self.mode.upper()}\n")
        sep()

        # 2. Chạy từng thực nghiệm
        for i, vuln in enumerate(vulns, 1):
            print(f"\n{'═'*60}")
            print(f" Thực nghiệm {i}/{len(vulns)}: {vuln['title'][:55]}")
            print(f" Severity: {vuln['severity']} | CWE: {vuln.get('cwe','N/A')} | OWASP: {vuln.get('owasp','N/A')}")
            print(f"{'═'*60}")

            result = {
                "vuln_id":    vuln["id"],
                "vuln_title": vuln["title"],
                "severity":   vuln["severity"],
                "cwe":        vuln.get("cwe", "N/A"),
                "owasp":      vuln.get("owasp", "N/A"),
                "file":       vuln.get("file", TARGET_FILE_RELATIVE),
                "sonar_rule": vuln.get("sonar_rule", "N/A"),
                "pipeline_A": None,
                "pipeline_B": None,
                "timestamp":  datetime.now().isoformat(),
            }

            # Ghi lỗ hổng vào Audit Ledger
            self.ledger.add_event(EventType.VULNERABILITY_DETECTED, {
                "vuln_id":   vuln["id"],
                "title":     vuln["title"],
                "severity":  vuln["severity"],
                "source":    "Demo" if self.mode == "demo" else "DefectDojo",
                "pipeline":  "experiment_runner.py",
            }, actor="SonarQube")

            # Chạy pipeline A (OpenAI)
            if self.pipeline in ("A", "all"):
                print(f"\n  ── Pipeline A: OpenAI GPT ──────────────────────────")
                result["pipeline_A"] = self._run_pipeline_A(vuln)

            # Chạy pipeline B (RAG + Ollama)
            if self.pipeline in ("B", "all"):
                print(f"\n  ── Pipeline B: RAG + Ollama ────────────────────────")
                result["pipeline_B"] = self._run_pipeline_B(vuln)

            self.results.append(result)
            
            # Đẩy kết quả real-time lên Firebase
            if FIREBASE_ENABLED:
                firebase_sync.push_experiment_result(result)

        # 3. In bảng kết quả
        sep()
        print()
        self._print_comparison_table()
        self._print_summary()

        # 4. Lưu kết quả ra file và Cloud
        self._save_results()
        if FIREBASE_ENABLED:
            summary_dict = self._build_summary_dict()
            summary_dict["metadata"] = {
                "run_at": self.start_time,
                "mode": self.mode,
                "pipeline": self.pipeline
            }
            firebase_sync.push_summary(summary_dict)

        # 5. Telegram tóm tắt
        self._send_telegram_summary()

        print(f"\n[✓] Kết quả đã lưu vào: {RESULTS_FILE}")
        print(f"[✓] Mở Audit Ledger Dashboard (blockchain_audit_dashboard.html) → tải security_audit_ledger.json để xem biểu đồ\n")

    # ─── GET VULNERABILITIES ──────────────────────────────────────────────────
    def _get_vulnerabilities(self) -> List[Dict]:
        if self.mode == "demo":
            print("[*] Chế độ DEMO — Dùng dữ liệu lỗ hổng mô phỏng (không gọi AI thực)")
            return DEMO_VULNERABILITIES

        # LIVE mode: query DefectDojo thật. Fallback DEMO_VULNERABILITIES nếu
        # DefectDojo down/offline — nhưng vẫn ghi rõ nguồn để tránh "false live".
        print("[*] Chế độ LIVE — Đang truy vấn DefectDojo để lấy finding thực...")

        try:
            import requests
            resp = requests.get(
                f"{DOJO_URL}&limit=200&active=true&verified=true",
                headers=DOJO_HEADERS, timeout=15
            )
            if resp.status_code == 200:
                data = resp.json()
                results = data.get("results") or []
                if not results:
                    print("[!] DefectDojo trả về 0 finding active — fallback DEMO")
                    return DEMO_VULNERABILITIES
                mapped = []
                for f in results:
                    mapped.append({
                        "id":          f.get("id"),
                        "title":       f.get("title", "Unknown"),
                        "severity":    (f.get("severity") or "").lower(),
                        "cwe":         f.get("cwe"),
                        "file_path":   (f.get("file_path") or "").lstrip("/"),
                        "line_number": f.get("line"),
                        "description": f.get("description", ""),
                        "source":      "defectdojo",
                    })
                print(f"[✓] Lấy {len(mapped)} finding(s) THỰC từ DefectDojo")
                return mapped
            print(f"[!] DefectDojo: HTTP {resp.status_code} — fallback DEMO")
        except Exception as e:
            print(f"[!] DefectDojo không phản hồi: {e} — fallback DEMO")

        return DEMO_VULNERABILITIES


    # ─── PIPELINE A: OPENAI ───────────────────────────────────────────────────
    def _run_pipeline_A(self, vuln: Dict) -> Dict:
        if self.mode == "demo":
            return self._simulate_pipeline("A", vuln)

        t0     = time.time()
        model  = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        result = {"model": model, "pipeline": "OpenAI GPT (Cloud)"}
        try:
            from openai import OpenAI
            client = OpenAI(
                base_url=os.getenv("OPENAI_BASE_URL", "http://127.0.0.1:8045/v1"),
                api_key=os.getenv("OPENAI_API_KEY", "")  # Phải set OPENAI_API_KEY; trống = proxy không cần key
            )
            # [Dynamic] Xác định đúng file cần vá
            target_rel  = _resolve_file(vuln)
            target_full = os.path.join(PROJECT_PATH, target_rel)
            original_code = _read_file(target_full)
            result["target_file"] = target_rel
            prompt = (
                f'Fix "{vuln["title"]}" in this Java code. '
                f'Return only ```java ... ``` block:\n{original_code}'
            )

            t_ai = time.time()
            resp = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1
            )
            result["ai_time_s"] = round(time.time() - t_ai, 2)

            match = re.search(r'```java\n(.*?)\n```', resp.choices[0].message.content, re.DOTALL)
            if not match:
                result.update({"patch_found": False, "build_success": False, "time_s": round(time.time()-t0, 2)})
                self._log_patch(vuln, result, "A")
                return result

            patched = match.group(1)
            result["patch_found"]  = True
            result["patch_length"] = len(patched)

            build_ok = self._maven_build(patched, target_rel)
            result["build_success"] = build_ok
            result["time_s"]        = round(time.time() - t0, 2)
            self._log_patch(vuln, result, "A")
            return result

        except Exception as e:
            result.update({"patch_found": False, "build_success": False, "time_s": round(time.time()-t0, 2), "error": str(e)})
            return result

    # ─── PIPELINE B: RAG + OLLAMA ─────────────────────────────────────────────
    def _run_pipeline_B(self, vuln: Dict) -> Dict:
        if self.mode == "demo":
            return self._simulate_pipeline("B", vuln)

        t0    = time.time()
        model = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b")
        embed = os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text")
        result = {"model": model, "pipeline": "RAG + Ollama (Local)"}
        try:
            from langchain_ollama import OllamaLLM, OllamaEmbeddings
            from langchain_chroma import Chroma
            from langchain_community.document_loaders import TextLoader
            from langchain_text_splitters import RecursiveCharacterTextSplitter

            loader  = TextLoader(GUIDELINES_PATH, encoding="utf-8")
            splits  = RecursiveCharacterTextSplitter(chunk_size=500).split_documents(loader.load())
            vs      = Chroma.from_documents(splits, OllamaEmbeddings(model=embed))
            docs    = vs.as_retriever().invoke(vuln["title"])
            context = "\n".join([d.page_content for d in docs])
            result["rag_docs"] = len(docs)

            llm = OllamaLLM(model=model, temperature=0.1)

            # [Dynamic] Xác định đúng file cần vá
            target_rel  = _resolve_file(vuln)
            target_full = os.path.join(PROJECT_PATH, target_rel)
            code = _read_file(target_full)
            result["target_file"] = target_rel

            prompt = (
                f'FIX "{vuln["title"]}".\n'
                f'GUIDELINES:\n{context}\n'
                f'CODE:\n```java\n{code}\n```\n'
                f'Return only ```java...``` block.'
            )

            t_ai = time.time()
            resp = llm.invoke(prompt)
            result["ai_time_s"] = round(time.time() - t_ai, 2)

            match = re.search(r'```java\n(.*?)\n```', resp, re.DOTALL)
            if not match:
                result.update({"patch_found": False, "build_success": False, "time_s": round(time.time()-t0, 2)})
                self._log_patch(vuln, result, "B")
                return result

            patched = match.group(1).strip()
            result["patch_found"]  = True
            result["patch_length"] = len(patched)

            build_ok = self._maven_build(patched, target_rel)
            result["build_success"] = build_ok
            result["time_s"]        = round(time.time() - t0, 2)
            self._log_patch(vuln, result, "B")
            return result

        except Exception as e:
            result.update({"patch_found": False, "build_success": False, "time_s": round(time.time()-t0, 2), "error": str(e)})
            return result


    # ─── SIMULATE (Demo Mode) ─────────────────────────────────────────────────
    def _simulate_pipeline(self, pipeline_key: str, vuln: Dict) -> Dict:
        """Mô phỏng pipeline với dữ liệu pre-computed để demo không cần AI thực."""
        sim = SIMULATED_RESULTS.get(vuln["id"], {}).get(f"pipeline_{pipeline_key}", {})
        if not sim:
            sim = {"patch_found": True, "build_success": True, "time_s": round(10+5*len(pipeline_key), 1), "patch_len": 1800}

        models = {"A": f"{os.getenv('OPENAI_MODEL', 'gpt-4o-mini')} (Cloud)", "B": "qwen2.5-coder:7b (Local)"}
        pipelines = {"A": "OpenAI GPT (Cloud)", "B": "RAG + Ollama (On-premise)"}

        # Mô phỏng thời gian chờ thực tế (rút ngắn để demo nhanh)
        print(f"  [*] Calling AI... ", end="", flush=True)
        time.sleep(min(sim.get("time_s", 5) * 0.08, 1.5))  # tối đa 1.5s khi demo
        print(f"✓ ({sim.get('time_s','?')}s simulated)")

        result = {
            "pipeline":     pipelines[pipeline_key],
            "model":        models[pipeline_key],
            "patch_found":  sim.get("patch_found", True),
            "build_success":sim.get("build_success", True),
            "time_s":       sim.get("time_s", 10.0),
            "patch_length": sim.get("patch_len", 1800),
            "simulated":    True,
        }

        status = "✅ Thành công" if result["build_success"] else "❌ Build fail"
        patch  = "✅ Có" if result["patch_found"] else "❌ Không"
        print(f"  [+] Patch tìm được: {patch}  |  Build: {status}  |  Thời gian: {result['time_s']}s")

        # Ghi kết quả vào Audit Ledger
        event = EventType.BUILD_SUCCESS if result["build_success"] else EventType.BUILD_FAILED
        self.ledger.add_event(EventType.AI_PATCH_APPLIED, {
            "vuln_id":     vuln["id"],
            "vuln_title":  vuln["title"],
            "pipeline":    result["pipeline"],
            "model":       result["model"],
            "patch_found": result["patch_found"],
            "patch_length":result["patch_length"],
            "experiment":  True,
        }, actor="AI_ENGINE")
        self.ledger.add_event(event, {
            "vuln_id":   vuln["id"],
            "vuln_name": vuln["title"],
            "pipeline":  result["pipeline"],
            "simulated": True,
        })
        return result

    # ─── MAVEN BUILD ──────────────────────────────────────────────────────────
    def _maven_build(self, patched_code: str, target_file: str = None) -> bool:
        """Test patch bằng maven compile rồi rollback ngay — không giữ lại code đã vá."""
        file_path = os.path.join(PROJECT_PATH, target_file) if target_file else TARGET_FILE_FULL
        original  = _read_file(file_path)
        _write_file(file_path, patched_code)
        try:
            proc = subprocess.run(["mvn", "clean", "compile"], cwd=PROJECT_PATH, capture_output=True, text=True, shell=False, timeout=300)
            ok   = (proc.returncode == 0) and ("BUILD SUCCESS" in proc.stdout)
            return ok
        finally:
            _write_file(file_path, original)  # rollback luôn sau test đảm bảo an toàn

    # ─── LOG ──────────────────────────────────────────────────────────────────
    def _log_patch(self, vuln: Dict, result: Dict, pipeline_key: str):
        event = EventType.BUILD_SUCCESS if result.get("build_success") else EventType.BUILD_FAILED
        self.ledger.add_event(EventType.AI_PATCH_APPLIED, {
            "vuln_id":     vuln["id"],
            "pipeline":    result.get("pipeline"),
            "model":       result.get("model"),
            "patch_found": result.get("patch_found"),
        }, actor="AI_ENGINE")
        self.ledger.add_event(event, {"vuln_id": vuln["id"], "pipeline": result.get("pipeline")})

    # ─── PRINT TABLE ──────────────────────────────────────────────────────────
    def _print_comparison_table(self):
        W = [6, 40, 10, 12, 10, 10, 10, 10, 10, 10]
        def row(*cols): return "│ " + " │ ".join(str(c).ljust(w) for c,w in zip(cols,W)) + " │"
        def hr(c="─"): return "├" + "┼".join(c*(w+2) for w in W) + "┤"

        header = ["#", "Lỗ hổng (rút gọn)", "Severity", "CWE",
                  "A:Patch?", "A:Build", "A:Time(s)",
                  "B:Patch?", "B:Build", "B:Time(s)"]

        print("╔" + "╦".join("═"*(w+2) for w in W) + "╗")
        print("║ " + " ║ ".join(h.center(w) for h,w in zip(header,W)) + " ║")
        print("╠" + "╬".join("═"*(w+2) for w in W) + "╣")

        for i, r in enumerate(self.results, 1):
            A = r.get("pipeline_A") or {}
            B = r.get("pipeline_B") or {}
            def yn(v): return "✅" if v else ("❌" if v is False else "—")
            print(row(
                i,
                r["vuln_title"][:38],
                r["severity"],
                r.get("cwe","N/A"),
                yn(A.get("patch_found")),  yn(A.get("build_success")),  A.get("time_s","—"),
                yn(B.get("patch_found")),  yn(B.get("build_success")),  B.get("time_s","—"),
            ))
            if i < len(self.results): print(hr())

        print("╚" + "╩".join("═"*(w+2) for w in W) + "╝")
        print("\n  A = Pipeline A: OpenAI GPT (Cloud)")
        print("  B = Pipeline B: RAG + Ollama qwen2.5-coder:7b (On-premise)")

    # ─── PRINT SUMMARY ────────────────────────────────────────────────────────
    def _print_summary(self):
        n = len(self.results)
        def calc(key):
            items = [r.get(key) or {} for r in self.results]
            patches = sum(1 for x in items if x.get("patch_found") is True)
            builds  = sum(1 for x in items if x.get("build_success") is True)
            times   = [x.get("time_s",0) for x in items if x.get("time_s")]
            avg_t   = round(sum(times)/len(times), 2) if times else "N/A"
            return patches, builds, avg_t

        pA, bA, tA = calc("pipeline_A")
        pB, bB, tB = calc("pipeline_B")

        print(f"\n{'─'*62}")
        print(f"  TỔNG KẾT THỰC NGHIỆM ({n} lỗ hổng)")
        print(f"{'─'*62}")
        print(f"  {'Tiêu chí':<30} {'Pipeline A':>12} {'Pipeline B':>12}")
        print(f"  {'─'*56}")
        print(f"  {'Tỷ lệ tạo patch thành công':<30} {pA}/{n} ({pA*100//n if n else 0}%)  {pB}/{n} ({pB*100//n if n else 0}%)")
        print(f"  {'Tỷ lệ build thành công':<30} {bA}/{n} ({bA*100//n if n else 0}%)  {bB}/{n} ({bB*100//n if n else 0}%)")
        print(f"  {'Thời gian xử lý trung bình':<30} {tA:>8}s     {tB:>8}s")
        print(f"  {'Model AI':<30} {'Cloud GPT':>12} {'Local LLM':>12}")
        print(f"  {'Bảo mật dữ liệu nguồn':<30} {'Thấp (Cloud)':>12} {'Cao (Local)':>12}")
        print(f"  {'Chi phí vận hành':<30} {'API cost':>12} {'Miễn phí':>12}")
        print(f"{'─'*62}")

        if self.pipeline == "all":
            winner_acc   = "A" if bA >= bB else "B"
            winner_speed = "A" if (isinstance(tA,float) and isinstance(tB,float) and tA<=tB) else "B"
            print(f"\n  🏆 Độ chính xác cao hơn: Pipeline {winner_acc}")
            print(f"  ⚡ Tốc độ nhanh hơn:      Pipeline {winner_speed}")
            print(f"  🔒 Bảo mật dữ liệu tốt:  Pipeline B (On-premise)")

    # ─── SAVE RESULTS ─────────────────────────────────────────────────────────
    def _save_results(self):
        output = {
            "experiment_metadata": {
                "run_at":         self.start_time,
                "mode":           self.mode,
                "pipeline":       self.pipeline,
                "total_vulns":    len(self.results),
                "project":        "DevSecOpsLab",
                "tool_versions":  {"audit_ledger": "2.0", "runner": "1.0"},
            },
            "results": self.results,
            "summary": self._build_summary_dict(),
        }
        with open(RESULTS_FILE, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, ensure_ascii=False)

    def _build_summary_dict(self):
        n = len(self.results)
        def calc(key):
            items = [r.get(key) or {} for r in self.results]
            patches = sum(1 for x in items if x.get("patch_found") is True)
            builds  = sum(1 for x in items if x.get("build_success") is True)
            times   = [x.get("time_s",0) for x in items if isinstance(x.get("time_s"),(int,float))]
            return {"patch_success": patches, "build_success": builds,
                    "avg_time_s": round(sum(times)/len(times),2) if times else None}
        return {"total_vulns": n, "pipeline_A": calc("pipeline_A"), "pipeline_B": calc("pipeline_B")}

    # ─── TELEGRAM SUMMARY ─────────────────────────────────────────────────────
    def _send_telegram_summary(self):
        n   = len(self.results)
        s   = self._build_summary_dict()
        pA  = s["pipeline_A"]
        pB  = s["pipeline_B"]
        # Telegram parse_mode=HTML — dùng <b> thay vì *bold*
        msg = (
            f"🧪 <b>KẾT QUẢ THỰC NGHIỆM DEVSECOPS</b>\n"
            f"{'─'*32}\n"
            f"📊 <b>Tổng lỗ hổng kiểm tra:</b> <code>{n}</code>\n"
            f"🏃 <b>Chế độ:</b> <code>{self.mode.upper()}</code>\n\n"
            f"<b>Pipeline A — OpenAI GPT (Cloud)</b>\n"
            f"  ✅ Patch: <code>{pA['patch_success']}/{n}</code> | Build: <code>{pA['build_success']}/{n}</code> | ⏱ <code>{pA['avg_time_s']}s</code>\n\n"
            f"<b>Pipeline B — RAG+Ollama (Local)</b>\n"
            f"  ✅ Patch: <code>{pB['patch_success']}/{n}</code> | Build: <code>{pB['build_success']}/{n}</code> | ⏱ <code>{pB['avg_time_s']}s</code>\n\n"
            f"⛓ <b>Audit Ledger:</b> {len(self.ledger.entries)} entries ghi nhận\n"
            f"📁 <b>Kết quả:</b> <code>experiment_results.json</code>"
        )
        self.notifier._send(msg)

    # ─── BANNER ───────────────────────────────────────────────────────────────
    def _banner(self):
        print("╔══════════════════════════════════════════════════════════╗")
        print("║   DevSecOps Experiment Runner                            ║")
        print("║   AI Auto-Remediation Pipeline Evaluation & Comparison   ║")
        print("╚══════════════════════════════════════════════════════════╝\n")


# ═══════════════════════════════════════════════════════════════════════════════
# UTILS
# ═══════════════════════════════════════════════════════════════════════════════
def _read_file(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as f: return f.read()
    except: return ""

def _write_file(path: str, content: str):
    with open(path, "w", encoding="utf-8") as f: f.write(content)

def sep(ch="─", n=62): print(ch * n)


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="DevSecOps Experiment Runner — Đánh giá pipeline AI tự động vá lỗi",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ví dụ:
  python experiment_runner.py                      # demo mode, cả 2 pipeline
  python experiment_runner.py --mode demo          # mô phỏng, không cần AI thực
  python experiment_runner.py --mode live          # chạy thực với DefectDojo + AI
  python experiment_runner.py --pipeline A         # chỉ test OpenAI pipeline
  python experiment_runner.py --pipeline B         # chỉ test RAG+Ollama pipeline
  python experiment_runner.py --mode live --pipeline all  # thực nghiệm đầy đủ
        """
    )
    parser.add_argument("--mode",     choices=["demo","live"], default="demo", help="demo=mô phỏng (an toàn cho bảo vệ), live=chạy thực với AI+Ollama thật")
    parser.add_argument("--pipeline", choices=["A","B","all"],  default="all",  help="Pipeline cần test")
    args = parser.parse_args()

    runner = ExperimentRunner(mode=args.mode, pipeline=args.pipeline)
    runner.run()
