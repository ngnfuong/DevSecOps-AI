"""
╔══════════════════════════════════════════════════════════╗
║   TELEGRAM NOTIFIER — DevSecOps ChatOps Alerts           ║
║   Gửi thông báo tự động về Telegram khi có sự kiện       ║
╚══════════════════════════════════════════════════════════╝

Setup:
  1. Tạo bot qua @BotFather → lấy BOT_TOKEN
  2. Lấy CHAT_ID: nhắn tin bot trước rồi truy cập
     https://api.telegram.org/bot<TOKEN>/getUpdates
  3. Tạo file .env hoặc set biến môi trường:
       TELEGRAM_BOT_TOKEN=123456:ABCdef...
       TELEGRAM_CHAT_ID=-1001234567890

Cách dùng:
    from telegram_notifier import TelegramNotifier
    notifier = TelegramNotifier()
    notifier.send_vulnerability_found("SQL Injection", "High", 42)
    notifier.send_patch_success("SQL Injection", "hotfix/vuln_42", 8.3)
    notifier.send_patch_failed("SQL Injection", "Maven compile error")
"""

import os
import requests
import html
from datetime import datetime
from typing import Optional

# ─────────────────────────────────────────────
# LOAD .env nếu có (fallback thủ công)
# ─────────────────────────────────────────────
def _load_dotenv():
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.exists(env_path):
        return
    with open(env_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, val = line.partition("=")
                os.environ.setdefault(key.strip(), val.strip())

_load_dotenv()


# ─────────────────────────────────────────────
# NOTIFIER
# ─────────────────────────────────────────────
class TelegramNotifier:
    """
    Gửi thông báo DevSecOps về Telegram (sử dụng parse_mode HTML để ổn định tuyệt đối).
    """

    TELEGRAM_API = "https://api.telegram.org/bot{token}/sendMessage"
    TIMEOUT_SEC  = 8

    def __init__(
        self,
        bot_token: Optional[str] = None,
        chat_id:   Optional[str] = None,
    ):
        self.bot_token = bot_token or os.getenv("TELEGRAM_BOT_TOKEN", "")
        self.chat_id   = chat_id   or os.getenv("TELEGRAM_CHAT_ID",   "")
        # Treat placeholder values as unset (chống việc __SET_IN_LOCAL_ONLY__ kích hoạt API call)
        _is_placeholder = lambda v: not v or v.startswith("__SET_IN") or v.startswith("your_")
        self.enabled = not _is_placeholder(self.bot_token) and not _is_placeholder(self.chat_id)

        if self.enabled:
            print(f"[📱] Telegram Notifier: ACTIVE (chat_id={self.chat_id})")
        else:
            print("[📱] Telegram Notifier: DISABLED (set TELEGRAM_BOT_TOKEN & TELEGRAM_CHAT_ID)")

    # ── Public API ────────────────────────────

    def send_vulnerability_found(
        self,
        vuln_title:  str,
        severity:    str,
        vuln_id:     Optional[int] = None,
        target_file: str = "",
        pipeline:    str = "",
    ):
        sev_icon = self._severity_icon(severity)
        msg = (
            f"🚨 <b>PHÁT HIỆN LỖ HỔNG BẢO MẬT</b>\n"
            f"{'─' * 30}\n"
            f"{sev_icon} <b>Mức độ:</b> <code>{html.escape(severity)}</code>\n"
            f"🔎 <b>Tên lỗi:</b> <code>{html.escape(vuln_title)}</code>\n"
            f"🆔 <b>ID:</b> <code>{html.escape(str(vuln_id or 'N/A'))}</code>\n"
            f"📄 <b>File:</b> <code>{html.escape(target_file or 'N/A')}</code>\n"
            f"🤖 <b>Pipeline:</b> {html.escape(pipeline or 'Auto-Remediation')}\n"
            f"⏰ <b>Thời gian:</b> {self._now()}\n\n"
            f"<i>Đang khởi động AI để phân tích và vá lỗi...</i>"
        )
        self._send(msg)

    def send_ai_patch_generated(
        self,
        vuln_title: str,
        model:      str,
        patch_len:  int = 0,
        rag_docs:   int = 0,
    ):
        rag_info = f"\n📚 <b>RAG docs dùng:</b> <code>{rag_docs}</code>" if rag_docs else ""
        msg = (
            f"🤖 <b>AI ĐÃ TẠO BẢN VÁ</b>\n"
            f"{'─' * 30}\n"
            f"🔴 <b>Lỗ hổng:</b> <code>{html.escape(vuln_title)}</code>\n"
            f"🧠 <b>Model AI:</b> <code>{html.escape(model)}</code>\n"
            f"📝 <b>Kích thước patch:</b> <code>{patch_len:,} ký tự</code>\n"
            f"{rag_info}\n"
            f"⏰ <b>Thời gian:</b> {self._now()}\n\n"
            f"<i>Đang chạy Maven compile để kiểm tra...</i>"
        )
        self._send(msg)

    def send_patch_success(
        self,
        vuln_title:  str,
        branch_name: str,
        duration_s:  float = 0.0,
        scm:         str   = "OneDev",
    ):
        msg = (
            f"✅ <b>VÁ LỖI THÀNH CÔNG — ĐÃ PUSH CODE</b>\n"
            f"{'─' * 30}\n"
            f"🔴 <b>Lỗ hổng:</b> <code>{html.escape(vuln_title)}</code>\n"
            f"🌿 <b>Branch:</b> <code>{html.escape(branch_name)}</code>\n"
            f"🏗️ <b>Build:</b> Maven compile SUCCESS\n"
            f"🚀 <b>SCM:</b> {html.escape(scm)}\n"
            f"⏱️ <b>Tổng thời gian:</b> <code>{duration_s:.1f}s</code>\n"
            f"⛓ <b>Audit Ledger:</b> Entry mới đã ghi\n"
            f"⏰ <b>Thời gian:</b> {self._now()}\n\n"
            f"✨ <i>Lỗ hổng đã được vá tự động. Vui lòng review PR trên {html.escape(scm)}.</i>"
        )
        self._send(msg)

    def send_patch_failed(
        self,
        vuln_title: str,
        reason:     str = "Maven build error",
        pipeline:   str = "",
    ):
        msg = (
            f"❌ <b>VÁ LỖI THẤT BẠI — ĐÃ ROLLBACK</b>\n"
            f"{'─' * 30}\n"
            f"🔴 <b>Lỗ hổng:</b> <code>{html.escape(vuln_title)}</code>\n"
            f"💥 <b>Lý do:</b> {html.escape(reason[:200])}\n"
            f"↩️ <b>Trạng thái:</b> Code đã rollback về bản gốc\n"
            f"🤖 <b>Pipeline:</b> {html.escape(pipeline or 'Auto-Remediation')}\n"
            f"⛓ <b>Audit Ledger:</b> BUILD_FAILED + ROLLBACK đã ghi\n"
            f"⏰ <b>Thời gian:</b> {self._now()}\n\n"
            f"⚠️ <i>Cần kiểm tra thủ công. AI patch có lỗi hoặc không có thay đổi.</i>"
        )
        self._send(msg)

    def send_ai_unavailable(self, vuln_title: str, error: str = ""):
        msg = (
            f"⚠️ <b>AI KHÔNG TẠO ĐƯỢC BẢN VÁ</b>\n"
            f"{'─' * 30}\n"
            f"🔴 <b>Lỗ hổng:</b> <code>{html.escape(vuln_title)}</code>\n"
            f"❓ <b>Lỗi:</b> {html.escape(error[:200] or 'Không trích xuất được code block')}\n"
            f"⏰ <b>Thời gian:</b> {self._now()}\n\n"
            f"⚠️ <i>Cần can thiệp thủ công.</i>"
        )
        self._send(msg)

    def send_system_clean(self):
        msg = (
            f"🔒 <b>HỆ THỐNG AN TOÀN</b>\n"
            f"{'─' * 30}\n"
            f"✅ DefectDojo không phát hiện lỗ hổng High nào.\n"
            f"⏰ <b>Kiểm tra lúc:</b> {self._now()}\n\n"
            f"<i>Pipeline DevSecOps đang hoạt động bình thường.</i>"
        )
        self._send(msg)

    def send_deployment_status(self, vuln_title: str, status: str, message: str):
        icon = "🚀" if status == "SUCCESS" else "🔥"
        msg = (
            f"{icon} <b>PRODUCTION DEPLOYMENT & INTEGRATION TEST</b>\n"
            f"{'─' * 30}\n"
            f"🔴 <b>Lỗ hổng:</b> <code>{html.escape(vuln_title)}</code>\n"
            f"📊 <b>Trạng thái:</b> <code>{status}</code>\n"
            f"📝 <b>Chi tiết:</b> {html.escape(message)}\n"
            f"⏰ <b>Thời gian:</b> {self._now()}\n\n"
            f"<i>Dữ liệu đã được ghi vào Audit Ledger.</i>"
        )
        self._send(msg)

    # ── Internal ──────────────────────────────

    def _send(self, text: str) -> bool:
        if not self.enabled:
            print(f"[📱] Telegram: SKIPPED (disabled) — msg len={len(text)}")
            return False
        try:
            url = self.TELEGRAM_API.format(token=self.bot_token)
            resp = requests.post(
                url,
                json={
                    "chat_id":    self.chat_id,
                    "text":       text,
                    "parse_mode": "HTML",
                },
                timeout=self.TIMEOUT_SEC,
            )
            if resp.status_code == 200:
                print(f"[📱] Telegram: ✅ Gửi thành công")
                return True
            else:
                print(f"[📱] Telegram: ❌ Lỗi HTTP {resp.status_code}: {resp.text[:200]}")
                return False
        except requests.exceptions.Timeout:
            print("[📱] Telegram: ⏱️ Timeout — bỏ qua, pipeline tiếp tục")
            return False
        except Exception as e:
            print(f"[📱] Telegram: ⚠️ Lỗi — {e} — bỏ qua, pipeline tiếp tục")
            return False

    @staticmethod
    def _now() -> str:
        return datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    @staticmethod
    def _severity_icon(severity: str) -> str:
        return {
            "Critical": "🔴🔴",
            "High":     "🔴",
            "Medium":   "🟡",
            "Low":      "🟢",
            "Info":     "ℹ️",
        }.get(severity, "⚪")


# ─────────────────────────────────────────────
# TEST / SELF-CHECK
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("╔══════════════════════════════════════════╗")
    print("║  TELEGRAM NOTIFIER — Connection Test     ║")
    print("╚══════════════════════════════════════════╝\n")

    notifier = TelegramNotifier()

    if not notifier.enabled:
        print("\n[!] Chưa cấu hình. Tạo file .env với nội dung:")
        print("    TELEGRAM_BOT_TOKEN=<your_bot_token>")
        print("    TELEGRAM_CHAT_ID=<your_chat_id>\n")
        print("Hướng dẫn lấy CHAT_ID:")
        print("  1. Mở Telegram → nhắn tin cho bot của bạn")
        print("  2. Truy cập: https://api.telegram.org/bot<TOKEN>/getUpdates")
        print("  3. Tìm trường \"id\" trong \"chat\" object")
    else:
        print("\n[*] Đang gửi test message...")
        ok = notifier._send(
            "🧪 *DevSecOps Telegram Notifier — Test*\n"
            "─────────────────────────────\n"
            "✅ Kết nối thành công!\n"
            "⛓ Audit Ledger: ACTIVE\n"
            "🤖 AI Auto-Remediation: READY\n\n"
            "_Hệ thống DevSecOps đã sẵn sàng._"
        )
        if ok:
            print("\n[✓] Test thành công! Kiểm tra Telegram của bạn.")
        else:
            print("\n[✗] Gửi thất bại. Kiểm tra lại BOT_TOKEN và CHAT_ID.")
