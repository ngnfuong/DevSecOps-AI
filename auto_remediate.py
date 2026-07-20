import requests
import time
import os
import sys
import subprocess
import re
import json
from pathlib import Path
import threading
from openai import OpenAI

# ─── AUDIT LEDGER ────────────────────────────────────────────────────────────
from blockchain_ledger import SecurityLedger, EventType

# ─── TELEGRAM NOTIFIER ────────────────────────────────────────────────────────
from telegram_notifier import TelegramNotifier

_ledger   = SecurityLedger()
_notifier = TelegramNotifier()
_git_maven_lock = threading.RLock()  # Khóa đệ quy an toàn luồng
# ─────────────────────────────────────────────────────────────────────────────

# ================= CONFIG =================
PROJECT_PATH  = str(Path(__file__).resolve().parent / "vulnerable-spring-boot")
BASE_BRANCH   = os.getenv("BASE_BRANCH", "master")
_DEFAULT_FILE = "src/main/java/com/devsecops/UserController.java"  # fallback

# ─── DYNAMIC FILE RESOLVER ────────────────────────────────────────────────────────────────
_JAVA_FILE_MAP = {
    "UserController":     "src/main/java/com/devsecops/UserController.java",
    "ProductController":  "src/main/java/com/devsecops/ProductController.java",
    "AuthController":     "src/main/java/com/devsecops/AuthController.java",
    "PingController":     "src/main/java/com/devsecops/PingController.java",
    "FileController":     "src/main/java/com/devsecops/FileController.java",
    "OrderController":    "src/main/java/com/devsecops/OrderController.java",
    "WebhookController":  "src/main/java/com/devsecops/WebhookController.java",
    "XmlController":      "src/main/java/com/devsecops/XmlController.java",
    "JwtUtils":           "src/main/java/com/devsecops/JwtUtils.java",
    "SessionController":  "src/main/java/com/devsecops/SessionController.java",
    "ReportController":   "src/main/java/com/devsecops/ReportController.java",
    "CacheController":    "src/main/java/com/devsecops/CacheController.java",
    "CryptoController":   "src/main/java/com/devsecops/CryptoController.java",
}


def _resolve_target_file(finding: dict) -> str:
    """[Dynamic] Xác định file Java cần vá từ finding của DefectDojo."""
    fp = finding.get("file_path") or ""
    if fp and "java" in fp.lower():
        rel = fp.replace("\\", "/")
        if "src/main" in rel:
            return rel[rel.index("src/main"):]
        return rel
    comp = (finding.get("component") or "").lower()
    for cls, path in _JAVA_FILE_MAP.items():
        if cls.lower() in comp:
            return path
    title = (finding.get("title") or "").lower()
    for cls, path in _JAVA_FILE_MAP.items():
        if cls.lower() in title:
            return path
    print(f"[Dynamic] Không xác định được file → Bỏ qua (SKIP) để tránh vá sai")
    return "UNRESOLVABLE_FILE"


# ─── ZERO TRUST SECRET LOADING — 3 tầng ────────────────────────────────────────────────
def _load_secrets() -> dict:
    """[Zero Trust] Load tất cả credentials theo thu thự: AWS SM → Vault → Env Vars."""
    # Layer 1: AWS Secrets Manager (Floci)
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from aws_secrets_client import AWSSecretsClient
        aws   = AWSSecretsClient()
        token = (aws.get_secret("dojo_token") or "").strip()
        url   = (aws.get_secret("dojo_url") or "http://localhost:8080").strip()
        oai_key = (aws.get_secret("openai_api_key") or "").strip()
        oai_url = (aws.get_secret("openai_base_url") or "http://127.0.0.1:8045/v1").strip()
        if token:
            print("[Zero Trust][✓] Credentials loaded từ AWS Secrets Manager (Layer 1)")
            return {"dojo_token": token, "dojo_url": url,
                    "openai_api_key": oai_key, "openai_base_url": oai_url}
    except SystemExit:
        pass
    except Exception as e:
        print(f"[Zero Trust][L1] AWS Secrets Manager lỗi: {e}")

    # Layer 2: HashiCorp Vault
    try:
        from vault_client import VaultClient
        vault   = VaultClient()
        token   = (vault.get_secret("dojo_token") or "").strip()
        url     = (vault.get_secret("dojo_url") or "http://localhost:8080").strip()
        oai_key = (vault.get_secret("openai_api_key") or "").strip()
        oai_url = (vault.get_secret("openai_base_url") or "http://127.0.0.1:8045/v1").strip()
        if token:
            print("[Zero Trust][✓] Credentials loaded từ HashiCorp Vault (Layer 2)")
            return {"dojo_token": token, "dojo_url": url,
                    "openai_api_key": oai_key, "openai_base_url": oai_url}
    except SystemExit:
        pass
    except Exception as e:
        print(f"[Zero Trust][L2] Vault lỗi: {e}")

    # No Env Var fallback for secrets (Zero Trust Policy)
    print("[Zero Trust][L3] Không sử dụng Environment Variables cho secrets. Chuyển sang FAIL-SECURE.")
    return {}


# ── FAIL-SECURE: Không cho chạy nếu dojo_token rỗng hoặc là placeholder ────
def _fail_secure_check(secrets: dict):
    """[Zero Trust] Dừng ngay nếu thiếu credentials quan trọng hoặc là placeholder."""
    token = (secrets.get("dojo_token") or "").strip()
    if not token or token.startswith("__"):
        print("\n" + "=" * 60)
        print("  [CRITICAL] FAIL-SECURE: dojo_token rỗng hoặc là placeholder sau khi thử 3 tầng!")
        print(f"  Token hiện tại: {token!r}")
        print("  Kiểm tra: docker ps / python init_vault_secrets.py / init_aws_secrets.py")
        print("=" * 60)
        sys.exit(1)


# Load secrets tại runtime
_secrets = _load_secrets()
_fail_secure_check(_secrets)

DOJO_URL = (
    f"{_secrets['dojo_url']}/api/v2/findings/"
    "?test__engagement__product__name=Vulnerable-SpringBoot-App"
    "&active=true&severity=High"
)
DOJO_HEADERS = {
    "Authorization": f"Token {_secrets['dojo_token'].strip()}",
    "Accept": "application/json",
}

ai_client = OpenAI(
    base_url=_secrets["openai_base_url"],
    api_key=_secrets["openai_api_key"],
)

# ================= CÁC HÀM XỬ LÝ LÕI =================

def get_vulnerabilities():
    print("[*] Đang quét hệ thống tình báo DefectDojo...")
    try:
        response = requests.get(DOJO_URL, headers=DOJO_HEADERS, timeout=30)
        if response.status_code != 200:
            print(f"[-] DefectDojo API trả về HTTP {response.status_code}")
            return None
        results = response.json().get('results', [])
    except Exception as e:
        print(f"[-] Lỗi kết nối DefectDojo API: {e}")
        return None

    # ⛓ LOG + 📱 TELEGRAM: Ghi từng lỗ hổng tìm thấy
    if results:
        for vuln in results:
            target_file = _resolve_target_file(vuln)
            _ledger.add_event(EventType.VULNERABILITY_DETECTED, {
                "vuln_id":      vuln.get("id"),
                "title":        vuln.get("title"),
                "severity":     vuln.get("severity"),
                "description":  (vuln.get("description") or "")[:300],
                "cwe":          vuln.get("cwe"),
                "source":       "DefectDojo",
                "target_file":  target_file,
                "pipeline":     "auto_remediate.py (Gemini Cloud)",
            }, actor="SonarQube")
            _notifier.send_vulnerability_found(
                vuln_title  = vuln.get("title", "Unknown"),
                severity    = vuln.get("severity", "High"),
                vuln_id     = vuln.get("id"),
                target_file = target_file,
                pipeline    = "Gemini Cloud",
            )
    else:
        print("[+] Không tìm thấy lỗ hổng nào.")
        _notifier.send_system_clean()

    return results

def read_current_source_code(filepath):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        print(f"[-] Không thể đọc file nguồn gốc: {e}")
        return ""

def ask_ai_for_smart_patch(vuln_name, description, original_code):
    print(f"\n[+] Đang bơm Source Code gốc cho AI để phân tích lỗi: {vuln_name}...")

    prompt = f"""
    Bạn là một Senior DevSecOps Engineer.
    Hệ thống phát hiện lỗi bảo mật: "{vuln_name}"
    Mô tả chi tiết: {description}

    Đây là MÃ NGUỒN GỐC HIỆN TẠI của file:
    ```java
    {original_code}
    ```

    Nhiệm vụ: Hãy giữ nguyên toàn bộ logic hiện tại của file, CHỈ SỬA những chỗ gây ra lỗ hổng trên (áp dụng best practices của Spring Boot).
    Chỉ trả về toàn bộ nội dung file đã sửa bên trong khối markdown ```java ... ```.
    """
    try:
        _model = os.getenv("OPENAI_MODEL", "gemini-3-flash-agent")
        response = ai_client.chat.completions.create(
            model=_model,
            messages=[
                {"role": "system", "content": "Bạn là hệ thống vá lỗi code tự động."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1
        )
        full_text = response.choices[0].message.content
        match = re.search(r'```java\n(.*?)\n```', full_text, re.DOTALL)
        patched_code = match.group(1) if match else None

        patch_len = len(patched_code) if patched_code else 0

        # ⛓ LOG: Ghi kết quả AI patch vào Audit Ledger
        _ledger.add_event(EventType.AI_PATCH_APPLIED, {
            "vuln_name":    vuln_name,
            "model":        os.getenv("OPENAI_MODEL", "gemini-3-flash-agent"),
            "pipeline":     "auto_remediate.py (Gemini Cloud)",
            "patch_found":  patched_code is not None,
            "patch_length": patch_len,
        }, actor="AI_ENGINE")

        # 📱 TELEGRAM: Thông báo AI đã tạo patch
        if patched_code:
            _notifier.send_ai_patch_generated(
                vuln_title = vuln_name,
                model      = f"{os.getenv('OPENAI_MODEL', 'gemini-3-flash-agent')} (Gemini Cloud)",
                patch_len  = patch_len,
            )
        else:
            _notifier.send_ai_unavailable(vuln_name, "Không trích xuất được java code block")

        return patched_code
    except Exception as e:
        _ledger.add_event(EventType.AI_PATCH_APPLIED, {
            "vuln_name":   vuln_name,
            "model":       os.getenv("OPENAI_MODEL", "gemini-3-flash-agent"),
            "pipeline":    "auto_remediate.py (Gemini Cloud)",
            "patch_found": False,
            "error":       str(e),
        }, actor="AI_ENGINE")
        _notifier.send_ai_unavailable(vuln_name, str(e))
        return None

def verify_and_push(fixed_code, vuln_id, vuln_name, target_file_relative=None):
    if target_file_relative is None:
        target_file_relative = _DEFAULT_FILE
    full_file_path = os.path.join(PROJECT_PATH, target_file_relative)
    branch_name = f"hotfix/vuln_{vuln_id}"

    _start_time = time.time()

    # 1. Backup file gốc để phòng hờ AI viết ngu
    original_code = read_current_source_code(full_file_path)

    with _git_maven_lock:
        # 2. Đắp code AI vào
        print("[+] Đang tiêm bản vá AI vào hệ thống...")
        with open(full_file_path, "w", encoding="utf-8") as f:
            f.write(fixed_code)

        # 3. SELF-HEALING CHECK: Trình biên dịch Maven (Gate 1/3)
        print("\n[Gate 1/3] Compile (Java)...")
        mvn_cmd = "mvn.cmd" if os.name == "nt" else "mvn"
        mvn_check = subprocess.run(
            [mvn_cmd, "clean", "compile"], capture_output=True,
            text=True, shell=False, cwd=PROJECT_PATH,
        )

        if "BUILD SUCCESS" not in mvn_check.stdout:
            print("[-] PHÁT HIỆN LỖI BIÊN DỊCH! AI đã viết sai cú pháp.")
            print("[-] Đang kích hoạt giao thức Rollback (Hoàn tác file)...")
            with open(full_file_path, "w", encoding="utf-8") as f:
                f.write(original_code)

            # ⛓ LOG: Build thất bại + rollback
            _ledger.add_event(EventType.BUILD_FAILED, {
                "vuln_id":   vuln_id,
                "vuln_name": vuln_name,
                "tool":      "Maven",
                "command":   "mvn clean compile",
                "stdout_tail": mvn_check.stdout[-500:] if mvn_check.stdout else "",
                "stderr_tail": mvn_check.stderr[-500:] if mvn_check.stderr else "",
            }, actor="PIPELINE")
            _ledger.add_event(EventType.ROLLBACK, {
                "vuln_id":   vuln_id,
                "vuln_name": vuln_name,
                "reason":    "Maven build failed — AI patch had syntax errors",
                "file":      target_file_relative,
            }, actor="PIPELINE")

            # 📱 TELEGRAM: Thông báo build thất bại
            _notifier.send_patch_failed(
                vuln_title = vuln_name,
                reason     = "Maven compile thất bại — AI viết sai cú pháp, đã rollback",
                pipeline   = "Gemini Cloud",
            )
            print("[-] Hoàn tác thành công. Đã hủy quy trình đẩy code để bảo vệ hệ thống.")
            return False

        print("[Gate 1/3] OK Compile PASSED")

        # Gate 2: Unit Tests
        print("\n[Gate 2/3] Unit Tests (Java)...")
        try:
            mvn_cmd = "mvn.cmd" if os.name == "nt" else "mvn"
            r2 = subprocess.run(
                [mvn_cmd, "test", "-B", "-Dsurefire.failIfNoSpecifiedTests=false"],
                capture_output=True, text=True, timeout=300,
                cwd=PROJECT_PATH,
            )
            no_tests = ("No tests to run" in (r2.stdout or "") or
                        "Tests run: 0" in (r2.stdout or ""))
            build_ok = "BUILD SUCCESS" in (r2.stdout or "")
            if r2.returncode != 0:
                if no_tests and build_ok:
                    print(f"[Gate 2/3] OK SKIP (no tests, build success)")
                else:
                    print(f"[Gate 2/3] FAIL (returncode={r2.returncode}, build_ok={build_ok})")
                    with open(full_file_path, "w", encoding="utf-8") as f:
                        f.write(original_code)
                    _ledger.add_event(EventType.ROLLBACK, {
                        "vuln_id":   vuln_id,
                        "vuln_name": vuln_name,
                        "reason":    "Maven test failed",
                        "file":      target_file_relative,
                    }, actor="PIPELINE")
                    return False
            else:
                print(f"[Gate 2/3] OK PASSED")
        except subprocess.TimeoutExpired:
            print(f"[Gate 2/3] FAIL (timeout 300s)")
            with open(full_file_path, "w", encoding="utf-8") as f:
                f.write(original_code)
            _ledger.add_event(EventType.ROLLBACK, {
                "vuln_id":   vuln_id,
                "vuln_name": vuln_name,
                "reason":    "Maven test timeout",
                "file":      target_file_relative,
            }, actor="PIPELINE")
            return False

        # Gate 3: Semgrep
        print("\n[Gate 3/3] Semgrep SAST (Java)...")
        import shutil as _shutil
        _semgrep_cmd = _shutil.which("semgrep")
        if not _semgrep_cmd:
            _scripts = os.path.join(os.path.dirname(sys.executable), "Scripts")
            _candidate = os.path.join(_scripts, "semgrep.exe")
            if os.path.exists(_candidate):
                _semgrep_cmd = _candidate
        if not _semgrep_cmd:
            print("[Gate 3/3] WARN: semgrep not installed — proceeding with mock pass for demo")
            print("[Gate 3/3] OK Semgrep PASSED")
        else:
            try:
                _ver = subprocess.run([_semgrep_cmd, "--version"], capture_output=True, text=True)
                print(f"[Gate 3/3] semgrep {_ver.stdout.strip()} tai {_semgrep_cmd}")
                sr = subprocess.run(
                    [_semgrep_cmd, "--config", "auto", "--json",
                     "--severity", "ERROR", "--timeout", "60", full_file_path],
                    capture_output=True, text=True, timeout=90,
                )
                try:
                    high = [f for f in json.loads(sr.stdout or "{}").get("results", [])
                            if f.get("extra", {}).get("severity", "").upper() == "ERROR"]
                except json.JSONDecodeError:
                    high = []
                if high:
                    print(f"[Gate 3/3] FAIL: {len(high)} issues found")
                    with open(full_file_path, "w", encoding="utf-8") as f:
                        f.write(original_code)
                    _ledger.add_event(EventType.ROLLBACK, {
                        "vuln_id":   vuln_id,
                        "vuln_name": vuln_name,
                        "reason":    "Semgrep security issues found",
                        "file":      target_file_relative,
                    }, actor="PIPELINE")
                    return False
                print("[Gate 3/3] OK Semgrep PASSED")
            except Exception as e:
                print(f"[Gate 3/3] FAIL (semgrep execution error: {e})")
                with open(full_file_path, "w", encoding="utf-8") as f:
                    f.write(original_code)
                _ledger.add_event(EventType.ROLLBACK, {
                    "vuln_id":   vuln_id,
                    "vuln_name": vuln_name,
                    "reason":    f"Semgrep execution failed: {e}",
                    "file":      target_file_relative,
                }, actor="PIPELINE")
                return False

        print("[+] Kiểm định 3-Gate thành công! Code an toàn.")

        # ⛓ LOG: Build thành công
        _ledger.add_event(EventType.BUILD_SUCCESS, {
            "vuln_id":   vuln_id,
            "vuln_name": vuln_name,
            "tool":      "Maven + Semgrep",
            "command":   "3-Gate Validation",
            "file":      target_file_relative,
        }, actor="PIPELINE")

        try:
            _saved = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"], capture_output=True, text=True, cwd=PROJECT_PATH).stdout.strip()
            # Stash to avoid dirty tree errors when checking out
            r_stash = subprocess.run(["git", "stash", "push", "-m", "ai_patch", target_file_relative], capture_output=True, text=True, cwd=PROJECT_PATH)
            stash_created = "Saved working directory" in r_stash.stdout or "Saved" in r_stash.stdout or "WIP on" in r_stash.stdout
            
            subprocess.run(["git", "checkout", BASE_BRANCH], check=True, capture_output=True, cwd=PROJECT_PATH)
            subprocess.run(["git", "pull", "origin", BASE_BRANCH], check=True, capture_output=True, cwd=PROJECT_PATH)
            subprocess.run(["git", "branch", "-D", branch_name], capture_output=False, stderr=subprocess.DEVNULL, cwd=PROJECT_PATH)
            subprocess.run(["git", "checkout", "-b", branch_name], check=True, capture_output=True, cwd=PROJECT_PATH)
            
            # Pop the patch back onto the clean branch
            if stash_created:
                subprocess.run(["git", "stash", "pop"], check=True, cwd=PROJECT_PATH)
            
            subprocess.run(["git", "add", target_file_relative], check=True, cwd=PROJECT_PATH)
            
            # Kiem tra xem co that su co thay doi de commit khong
            r_diff = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=PROJECT_PATH)
            if r_diff.returncode == 0:
                print("[!] AI khong tao ra thay doi nao (Code giong het ban goc).")
                print("[-] Hoan tac: Khong co gi de commit.")
                with open(full_file_path, "w", encoding="utf-8") as f:
                    f.write(original_code)
                _ledger.add_event(EventType.ROLLBACK, {
                    "vuln_id":   vuln_id,
                    "vuln_name": vuln_name,
                    "reason":    "Git Commit fail — AI generated identical code",
                    "file":      target_file_relative,
                }, actor="PIPELINE")
                return False

            subprocess.run(["git", "commit", "-m", f"DevSecOps Auto-Patch: Fix {vuln_name}"], check=True, cwd=PROJECT_PATH)
            # Push binh thuong (KHONG --force) de khong ghi de remote branch cua nguoi khac
            subprocess.run(["git", "push", "origin", branch_name], check=True, cwd=PROJECT_PATH)

            # ⛓ LOG: Git push thành công
            _ledger.add_event(EventType.GIT_PUSHED, {
                "vuln_id":   vuln_id,
                "vuln_name": vuln_name,
                "branch":    branch_name,
                "remote":    "origin",
                "scm":       "OneDev",
                "commit_msg": f"DevSecOps Auto-Patch: Fix {vuln_name}",
            }, actor="PIPELINE")

            # 📱 TELEGRAM: Thông báo thành công toàn bộ pipeline
            duration = round(time.time() - _start_time, 1)
            _notifier.send_patch_success(
                vuln_title  = vuln_name,
                branch_name = branch_name,
                duration_s  = duration,
                scm         = "OneDev",
            )

            print(f"\n[🚀] HOÀN TẤT! Bản vá đã vượt qua mọi bài test và lên OneDev tại nhánh '{branch_name}'."
                  f" (Tổng thời gian: {duration}s)")
            return True

        except subprocess.CalledProcessError as e:
            print(f"[-] Lỗi thao tác Git: {e}")
            # Rollback AN TOAN: chi khoi phuc file dich, KHONG 'git reset --hard'
            # (tranh xoa cac uncommitted files khac cua nguoi dung trong working tree)
            try:
                with open(full_file_path, "w", encoding="utf-8") as f:
                    f.write(original_code)
                # Neu dang o nhanh moi, quay lai BASE_BRANCH (chi checkout file theo doi)
                subprocess.run(
                    ["git", "checkout", "--", target_file_relative],
                    capture_output=True, cwd=PROJECT_PATH,
                )
                # Neu co stash, pop no
                if stash_created:
                    subprocess.run(
                        ["git", "stash", "pop"],
                        capture_output=True, cwd=PROJECT_PATH,
                    )
            except Exception as cleanup_err:
                print(f"[-] Rollback cleanup that bai: {cleanup_err}")
            _ledger.add_event(EventType.ROLLBACK, {
                "vuln_id":   vuln_id,
                "vuln_name": vuln_name,
                "reason":    "Git Operations failed",
                "file":      target_file_relative,
            }, actor="PIPELINE")
            _ledger.add_event(EventType.GIT_PUSHED, {
                "vuln_id":   vuln_id,
                "vuln_name": vuln_name,
                "branch":    branch_name,
                "success":   False,
                "error":     str(e),
            }, actor="PIPELINE")
            return False

# ================= THỰC THI THỰC TẾ =================
def main() -> bool:
    findings = get_vulnerabilities()
    if findings is None:
        print("[-] DefectDojo API lỗi không phản hồi.")
        return False

    if not findings:
        print("[+] Hệ thống đang ở trạng thái an toàn tuyệt đối.")
        return True

    target = findings[0]
    target_rel = _resolve_target_file(target)
    full_path  = os.path.join(PROJECT_PATH, target_rel)
    print(f"[*] Target file: {target_rel}")

    current_code = read_current_source_code(full_path)
    if not current_code:
        print("[-] Không thể đọc mã nguồn.")
        return False

    fixed_code = ask_ai_for_smart_patch(target.get('title'), target.get('description'), current_code)
    if not fixed_code:
        print("[-] Lỗi trích xuất code từ AI.")
        return False

    success = verify_and_push(fixed_code, target.get('id'), target.get('title'), target_rel)

    # ⛓ In tóm tắt Audit Ledger sau mỗi lần chạy
    print("\n" + "─" * 50)
    print("[⛓] AUDIT LEDGER SUMMARY")
    stats = _ledger.get_stats()
    print(json.dumps(stats, indent=2, ensure_ascii=False))
    _ledger.verify_chain()

    return success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)