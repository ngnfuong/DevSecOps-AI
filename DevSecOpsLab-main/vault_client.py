"""
╔══════════════════════════════════════════════════════════════════╗
║   VAULT CLIENT — Zero Trust Secret Manager                       ║
║   Kết nối tới HashiCorp Vault để lấy Secret động (Dynamic)       ║
║   Thay thế cho việc hardcode token trong source code             ║
╚══════════════════════════════════════════════════════════════════╝

Triết lý Zero Trust áp dụng ở đây:
  - KHÔNG LƯU token nào trong source code hay file cấu hình
  - MỌI bí mật đều được lấy từ Vault tại thời điểm chạy (runtime)
  - Vault cấp quyền ngắn hạn (short-lived) — hết pipeline = hết quyền

Cách dùng:
  from vault_client import VaultClient
  client = VaultClient()
  token = client.get_secret("sonar_token")
"""

import os
import requests
import json
import sys
from typing import Optional

# ── CONFIG ───────────────────────────────────────────────────────────────────
VAULT_ADDR  = os.getenv("VAULT_ADDR",  "http://localhost:8200")
# Trước đây default = "dev_root_token" — hardcoded trong source. Mặc dù đây là
# dev-mode root token của Vault, việc hardcode là anti-pattern (Zero Trust claim).
# Sửa: KHÔNG default; bắt buộc set VAULT_TOKEN env, nếu không thì fail loudly
# khi thực sự truy cập Vault (không fail ngay lúc import).
VAULT_TOKEN = os.getenv("VAULT_TOKEN")
VAULT_PATH  = os.getenv("VAULT_PATH",  "secret/data/devsecops")  # KV v2 path


class VaultClient:
    """
    Client kết nối HashiCorp Vault theo mô hình Zero Trust.
    Tất cả các secret được fetch từ Vault thay vì đọc từ biến môi trường tĩnh.
    """

    def __init__(
        self,
        vault_addr:  str = VAULT_ADDR,
        vault_token: str = VAULT_TOKEN,
        vault_path:  str = VAULT_PATH,
    ):
        if not vault_token:
            # Fail loudly khi thật sự cần Vault (không hardcode "dev_root_token").
            print("[Vault][✗] VAULT_TOKEN env var chưa được set.")
            print("[Vault]    → Set: set VAULT_TOKEN=<token> (Windows) hoặc export VAULT_TOKEN=...")
            print("[Vault]    → Hoặc dùng: python init_vault_secrets.py để lấy token.")
            sys.exit(1)
        self.addr   = vault_addr.rstrip("/")
        self.token  = vault_token
        self.path   = vault_path
        self.headers = {
            "X-Vault-Token": self.token,
            "Content-Type":  "application/json",
        }
        self._cache: dict = {}  # Cache cục bộ trong vòng đời 1 pipeline run
        self._verify_connection()

    # ── PUBLIC API ────────────────────────────────────────────────────────────

    def get_secret(self, key: str) -> Optional[str]:
        """
        [Zero Trust] Lấy 1 secret theo tên key từ Vault.
        Ví dụ: client.get_secret("sonar_token")
        Tự động strip whitespace/newlines (CR/LF) để tránh 401/403 ở downstream API.
        """
        if not self._cache:
            self._load_all_secrets()
        value = self._cache.get(key)
        if value is None:
            print(f"[Vault][!] Không tìm thấy key '{key}' trong path '{self.path}'")
            return value
        if isinstance(value, str):
            return value.strip()
        return value

    def put_secret(self, secrets: dict) -> bool:
        """
        Lưu/cập nhật secrets vào Vault (chỉ dùng khi khởi tạo).
        Ví dụ: client.put_secret({"sonar_token": "sqa_abc...", "dojo_token": "..."})
        """
        api_url = f"{self.addr}/v1/{self.path}"
        payload = {"data": secrets}
        try:
            resp = requests.post(api_url, headers=self.headers, json=payload, timeout=10)
            if resp.status_code in (200, 204):
                print(f"[Vault][+] Đã lưu {len(secrets)} secret(s) vào path: {self.path}")
                return True
            else:
                print(f"[Vault][!] Lỗi lưu secret: {resp.status_code} - {resp.text[:200]}")
                return False
        except Exception as e:
            print(f"[Vault][!] Không kết nối được Vault: {e}")
            return False

    def list_secret_keys(self) -> list:
        """Liệt kê tất cả key hiện có trong Vault path."""
        if not self._cache:
            self._load_all_secrets()
        return list(self._cache.keys())

    # ── INTERNAL ──────────────────────────────────────────────────────────────

    def _verify_connection(self):
        """Kiểm tra kết nối tới Vault server khi khởi tạo client."""
        try:
            resp = requests.get(
                f"{self.addr}/v1/sys/health",
                headers=self.headers,
                timeout=5
            )
            if resp.status_code in (200, 429, 472, 473):
                # 200: Active, 429: Standby, 47x: DR/Perf — đều là healthy
                print(f"[Vault][✓] Kết nối thành công → {self.addr}")
            else:
                print(f"[Vault][!] Vault phản hồi lạ: {resp.status_code}")
        except requests.exceptions.ConnectionError:
            print(f"[Vault][✗] KHÔNG KẾT NỐI ĐƯỢC Vault tại {self.addr}")
            print(f"[Vault]    → Kiểm tra container Vault đang chạy chưa:")
            print(f"[Vault]    → docker compose up -d vault")
            sys.exit(1)

    def _load_all_secrets(self):
        """Tải toàn bộ secrets từ Vault path vào cache cục bộ."""
        # KV v2: GET /v1/secret/data/devsecops → response.data.data
        api_url = f"{self.addr}/v1/{self.path}"
        try:
            resp = requests.get(api_url, headers=self.headers, timeout=10)
            if resp.status_code == 200:
                raw = resp.json()
                # KV v2: secrets nằm trong data.data
                self._cache = raw.get("data", {}).get("data", {})
                print(f"[Vault][✓] Đã tải {len(self._cache)} secret(s) từ '{self.path}'")
            elif resp.status_code == 404:
                print(f"[Vault][!] Chưa có dữ liệu tại path '{self.path}'.")
                print("[Vault]    → Chạy: python init_vault_secrets.py để nạp secrets.")
                self._cache = {}
            else:
                print(f"[Vault][!] Lỗi đọc secret: {resp.status_code} - {resp.text[:200]}")
                self._cache = {}
        except Exception as e:
            print(f"[Vault][!] Lỗi kết nối Vault: {e}")
            self._cache = {}


# ── CLI DEMO ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 55)
    print(" VaultClient — Zero Trust Secret Manager Demo")
    print("=" * 55)
    client = VaultClient()
    keys = client.list_secret_keys()
    if keys:
        print(f"\n[*] Các key hiện có trong Vault:")
        for k in keys:
            val = client.get_secret(k)
            masked = val[:8] + "..." + val[-4:] if val and len(val) > 12 else "???"
            print(f"    ✓ {k:30s} → {masked}")
    else:
        print("[*] Vault đang rỗng. Chạy: python init_vault_secrets.py")
    print("=" * 55)
