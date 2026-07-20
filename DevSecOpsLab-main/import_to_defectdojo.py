"""
Script nhập báo cáo SonarQube vào DefectDojo.
Được gọi tự động bởi pipeline OneDev sau bước quét SAST.

╔══════════════════════════════════════════════════════════════════╗
║  ZERO TRUST SECRET MANAGEMENT — 3 tầng bảo vệ                   ║
║                                                                  ║
║  Tầng 1: AWS Secrets Manager (Floci) — Chuẩn enterprise cloud   ║
║  Tầng 2: HashiCorp Vault             — Secret management nội bộ ║
║  Tầng 3: Biến môi trường             — Fallback tương thích     ║
╚══════════════════════════════════════════════════════════════════╝
"""
import requests
import json
import sys
import os
import time

# ── ZERO TRUST LAYER 1: AWS Secrets Manager (via Floci AWS Emulator) ──────────
def _load_from_aws_secrets_manager() -> dict | None:
    """
    [Zero Trust L1] Fetch secrets từ AWS Secrets Manager.
    Dùng Floci local emulator — compatible 100% với AWS thật.
    """
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from aws_secrets_client import AWSSecretsClient
        aws = AWSSecretsClient()
        print("[Zero Trust][L1] Đang fetch secrets từ AWS Secrets Manager (Floci)...")
        return {
            "sonar_url":    (aws.get_secret("sonar_url")     or "http://localhost:9000").strip(),
            "sonar_token":  (aws.get_secret("sonar_token")   or "").strip(),
            "sonar_key":    (aws.get_secret("sonar_project")  or "vulnerable-spring-boot").strip(),
            "dojo_url":     (aws.get_secret("dojo_url")      or "http://localhost:8080").strip(),
            "dojo_token":   (aws.get_secret("dojo_token")    or "").strip(),
        }
    except SystemExit:
        return None   # Floci chưa chạy → thử tầng 2
    except Exception as e:
        print(f"[Zero Trust][L1] AWS Secrets Manager lỗi: {e}")
        return None


# ── ZERO TRUST LAYER 2: HashiCorp Vault (fallback) ────────────────────────────
def _load_from_vault() -> dict | None:
    """[Zero Trust L2] Fallback sang HashiCorp Vault nếu Floci không khả dụng."""
    try:
        from vault_client import VaultClient
        vault = VaultClient()
        print("[Zero Trust][L2] Floci không khả dụng → dùng HashiCorp Vault...")
        return {
            "sonar_url":    (vault.get_secret("sonar_url")    or "http://localhost:9000").strip(),
            "sonar_token":  (vault.get_secret("sonar_token")  or "").strip(),
            "sonar_key":    (vault.get_secret("sonar_project") or "vulnerable-spring-boot").strip(),
            "dojo_url":     (vault.get_secret("dojo_url")     or "http://localhost:8080").strip(),
            "dojo_token":   (vault.get_secret("dojo_token")   or "").strip(),
        }
    except SystemExit:
        return None   # Vault cũng không chạy → thử tầng 3
    except Exception as e:
        print(f"[Zero Trust][L2] Vault lỗi: {e}")
        return None


# ── ZERO TRUST LAYER 3: Environment Variables (last resort) ───────────────────
def _load_from_env() -> dict:
    """[Zero Trust L3] Fallback cuối cùng sang biến môi trường."""
    print("[Zero Trust][L3] Vault cũng không khả dụng → dùng biến môi trường.")
    return {
        "sonar_url":   os.getenv("SONAR_URL",   "http://localhost:9000").strip(),
        "sonar_token": os.getenv("SONAR_TOKEN",  "").strip(),
        "sonar_key":   os.getenv("SONAR_KEY",    "vulnerable-spring-boot").strip(),
        "dojo_url":    os.getenv("DEFECTDOJO_URL",     "http://localhost:8080").strip(),
        "dojo_token":  os.getenv("DEFECTDOJO_TOKEN",   "").strip(),
    }


# ── ORCHESTRATOR: Thử lần lượt từng tầng ─────────────────────────────────────
def _load_secrets() -> dict:
    """
    [Zero Trust] Tải secrets theo thứ tự ưu tiên:
      AWS Secrets Manager (Floci) → HashiCorp Vault → Env Vars

    Chỉ chấp nhận tầng secret khi CẢ sonar_token VÀ dojo_token đều có giá trị.
    (Trước đây chỉ check sonar_token → dojo_token có thể rỗng mà vẫn pass.)
    """
    secrets = _load_from_aws_secrets_manager()
    if secrets and secrets.get("sonar_token") and secrets.get("dojo_token"):
        print("[Zero Trust][✓] Secrets loaded từ AWS Secrets Manager (Layer 1)")
        return secrets

    secrets = _load_from_vault()
    if secrets and secrets.get("sonar_token") and secrets.get("dojo_token"):
        print("[Zero Trust][✓] Secrets loaded từ HashiCorp Vault (Layer 2)")
        return secrets

    secrets = _load_from_env()
    print("[Zero Trust][✓] Secrets loaded từ Environment Variables (Layer 3)")
    return secrets


# ── CONFIG (Zero Trust 3 tầng — tải tại runtime) ─────────────────────────────
_secrets = _load_secrets()

SONAR_URL    = os.getenv("SONAR_URL", _secrets["sonar_url"])
SONAR_TOKEN  = os.getenv("SONAR_TOKEN", _secrets["sonar_token"]).strip()
SONAR_KEY    = os.getenv("SONAR_KEY", _secrets["sonar_key"])

DOJO_URL     = os.getenv("DEFECTDOJO_URL", _secrets["dojo_url"])
DOJO_TOKEN   = os.getenv("DEFECTDOJO_TOKEN", _secrets["dojo_token"]).strip()
DOJO_HEADERS = {"Authorization": f"Token {DOJO_TOKEN.strip()}"}

# ── FAIL-SECURE: Không cho chạy với token rỗng ───────────────────────────────
if not SONAR_TOKEN or not DOJO_TOKEN:
    print("\n" + "=" * 60)
    print("  [CRITICAL] FAIL-SECURE: Token rỗng sau khi thử 3 tầng!")
    if not SONAR_TOKEN:
        print("  → SONAR_TOKEN = (empty)")
    if not DOJO_TOKEN:
        print("  → DOJO_TOKEN  = (empty)")
    print("  Kiểm tra: docker ps / python init_vault_secrets.py")
    print("=" * 60)
    sys.exit(1)


PRODUCT_NAME    = os.getenv("PRODUCT_NAME", "Vulnerable-SpringBoot-App")
ENGAGEMENT_NAME = os.getenv("ENGAGEMENT_NAME", "DevSecOps_Auto_Scan")


def fetch_sonar_issues() -> dict:
    """Lấy danh sách issues từ SonarQube API."""
    print(f"[*] Fetching SonarQube issues for project: {SONAR_KEY}")
    url = f"{SONAR_URL}/api/issues/search"
    params = {
        "componentKeys": SONAR_KEY,
        "ps": 500,
        "severities": "BLOCKER,CRITICAL,MAJOR",
    }
    try:
        resp = requests.get(url, params=params, auth=(SONAR_TOKEN, ""), timeout=30)
        resp.raise_for_status()
        data = resp.json()
        total = data.get("total", 0)
        print(f"[+] Found {total} issues in SonarQube")
        return data
    except requests.exceptions.ConnectionError:
        print(f"[!] Cannot connect to SonarQube at {SONAR_URL}")
        return {"issues": [], "total": 0}
    except Exception as e:
        print(f"[!] SonarQube fetch error: {e}")
        return {"issues": [], "total": 0}


def ensure_engagement() -> int:
    """Tạo hoặc lấy Engagement ID trong DefectDojo."""
    # Tìm product
    resp = requests.get(
        f"{DOJO_URL}/api/v2/products/?name={PRODUCT_NAME}",
        headers=DOJO_HEADERS, timeout=120
    )
    products = resp.json().get("results", []) if resp.ok else []
    if not products:
        # Tạo product mới
        resp = requests.post(f"{DOJO_URL}/api/v2/products/", headers=DOJO_HEADERS, json={
            "name": PRODUCT_NAME, "prod_type": 1, "description": "Vulnerable Spring Boot App for DevSecOps research"
        }, timeout=120)
        product_id = resp.json().get("id")
        print(f"[+] Created product: {PRODUCT_NAME} (id={product_id})")
    else:
        product_id = products[0]["id"]
        print(f"[+] Found product: {PRODUCT_NAME} (id={product_id})")

    # Tìm engagement
    resp = requests.get(
        f"{DOJO_URL}/api/v2/engagements/?product={product_id}&name={ENGAGEMENT_NAME}",
        headers=DOJO_HEADERS, timeout=120
    )
    engagements = resp.json().get("results", []) if resp.ok else []
    if not engagements:
        from datetime import date, timedelta
        resp = requests.post(f"{DOJO_URL}/api/v2/engagements/", headers=DOJO_HEADERS, json={
            "name": ENGAGEMENT_NAME, "product": product_id,
            "target_start": date.today().isoformat(),
            "target_end": (date.today() + timedelta(days=365)).isoformat(),
            "status": "In Progress", "engagement_type": "CI/CD",
        }, timeout=120)
        eng_id = resp.json().get("id")
        print(f"[+] Created engagement: {ENGAGEMENT_NAME} (id={eng_id})")
    else:
        eng_id = engagements[0]["id"]
        print(f"[+] Found engagement: {ENGAGEMENT_NAME} (id={eng_id})")
    return eng_id


def import_to_defectdojo(sonar_data: dict, engagement_id: int):
    """Nhập từng issue SonarQube vào DefectDojo."""
    issues = sonar_data.get("issues", [])
    if not issues:
        print("[*] No issues to import.")
        return 0

    sonar_json = json.dumps(sonar_data).encode("utf-8")
    files = {"file": ("sonar-report.json", sonar_json, "application/json")}
    data = {
        "product_name":      PRODUCT_NAME,
        "engagement_name":   ENGAGEMENT_NAME,
        "auto_create_context": "true",
        "scan_type":         "SonarQube Scan",
        "engagement":        engagement_id,
        "active":            "true",
        "verified":          "false",
        "close_old_findings": "false",
    }
    try:
        resp = requests.post(
            f"{DOJO_URL}/api/v2/import-scan/",
            headers=DOJO_HEADERS,
            data=data, files=files, timeout=180
        )
        if resp.status_code in (200, 201):
            result = resp.json()
            print(f"[+] Import successful! Test ID: {result.get('test')}")
            print(f"[+] Findings created: {result.get('statistics', {}).get('created', '?')}")
            return result.get("test")
        else:
            print(f"[!] Import failed ({resp.status_code}): {resp.text[:300]}")
            return None
    except Exception as e:
        print(f"[!] DefectDojo import error: {e}")
        return None


def main():
    print("=" * 50)
    print(" import_to_defectdojo.py — DevSecOpsLab")
    print("=" * 50)

    # 1. Lấy issues từ SonarQube
    sonar_data = fetch_sonar_issues()

    if not sonar_data.get("issues"):
        print("[*] No issues found. Checking if SonarQube analysis is complete...")
        time.sleep(10)
        sonar_data = fetch_sonar_issues()

    # 2. Đảm bảo có engagement trong DefectDojo
    try:
        engagement_id = ensure_engagement()
    except Exception as e:
        # Trước đây sys.exit(0) → CI/CD nghĩ thành công (false success).
        # Sửa: exit 2 + log rõ → CI/CD fail đúng nghĩa.
        print(f"[!] DefectDojo setup error: {e}")
        print("[!] KHÔNG import được findings vào DefectDojo. Pipeline fail.")
        sys.exit(2)

    # 3. Import
    test_id = import_to_defectdojo(sonar_data, engagement_id)
    if test_id:
        print(f"\n[✓] SUCCESS: Imported to DefectDojo (Test #{test_id})")
        print(f"[*] View at: {DOJO_URL}/test/{test_id}")
        try:
            print("[*] Gửi thông báo hoàn thành tới Dashboard Backend...")
            requests.post("http://localhost:5555/api/pipeline/ci_complete", json={"status": "success", "test_id": test_id}, timeout=5)
        except Exception as e:
            print(f"[!] Không thể kết nối tới Dashboard API: {e}")
    else:
        print("\n[!] Import to DefectDojo was not successful (check logs above)")
        # Import fail → exit non-zero để OneDev biết bước này lỗi
        sys.exit(3)

    print("=" * 50)


if __name__ == "__main__":
    main()
