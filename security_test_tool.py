import sys
import requests
from bs4 import BeautifulSoup
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTextEdit, QPushButton, QVBoxLayout,
    QWidget, QLabel, QTableWidget, QTableWidgetItem, QHeaderView
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal


class SecurityTester(QThread):
    # Sinyaller: (kategori, mesaj) olarak gönderelim
    log_signal = pyqtSignal(str, str)
    raw_response_signal = pyqtSignal(str)
    owasp_result_signal = pyqtSignal(dict)
    risk_score_signal = pyqtSignal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.session = requests.Session()
        self.timeout = 8  # saniye

    def run(self):
        try:
            self.perform_tests()
        except Exception as e:
            self.log_signal.emit("error", f"💥 Test sırasında hata: {str(e)}")

    def log(self, level, msg):
        self.log_signal.emit(level, msg)

    def get_csrf_token(self, html):
        soup = BeautifulSoup(html, "html.parser")
        token_input = soup.find("input", {"name": "csrf_token"})
        if token_input and token_input.has_attr("value"):
            return token_input['value']
        return None

    def perform_tests(self):
        self.log("info", "🔍 Güvenlik Testleri Başlatıldı\n" + "-" * 40)

        login_url = "Admin/login.php"
        admin_url = "Admin/admin.php"

        # 1. Login
        self.log("info", "🔐 Oturum açılıyor...")
        login_payload = {"username": "admin", "password": "16556156sdf15sdvcsd%&/(%&/657"}

        try:
            r_login = self.session.post(login_url, data=login_payload, timeout=self.timeout)
            r_login.raise_for_status()
        except Exception as e:
            self.log("error", f"❌ Oturum açma başarısız: {e}")
            return

        token = self.get_csrf_token(r_login.text)
        if token:
            self.log("success", f"✅ Oturum açıldı, CSRF token alındı: {token}")
        else:
            self.log("warning", "⚠️ CSRF token alınamadı.")

        # 2. CSRF Test
        self.log("info", "▶ POST (CSRF token ile sahte form gönderimi)...")
        payload = {
            "add_user": "1",
            "new_username": "pentester",
            "new_password": "123456",
            "new_email": "pentest@example.com",
            "new_api": "api_key_test",
            "new_kurumsal_email": "kurum@kurum.com",
            "csrf_token": token or "FAKE_TOKEN"
        }
        headers = {
            "Referer": "http://sss.com/",
            "Origin": "http://sss.com/",
            "User-Agent": "Mozilla/5.0 (PentestBot)"
        }
        try:
            r_post = self.session.post(admin_url, data=payload, headers=headers, allow_redirects=True, timeout=self.timeout)
            self.raw_response_signal.emit(r_post.text)
        except Exception as e:
            self.log("error", f"❌ POST isteği başarısız: {e}")
            return

        csrf_passed = False
        resp_text_lower = r_post.text.lower()
        if "csrf" in resp_text_lower or "token" in resp_text_lower:
            self.log("success", "✅ CSRF koruması aktif!")
            csrf_passed = True
        elif "geçersiz kaynak" in r_post.text:
            self.log("success", "✅ Referer doğrulama aktif!")
            csrf_passed = True
        elif "kullanıcı eklendi" in resp_text_lower:
            self.log("error", "❌ CSRF koruması başarısız! Kullanıcı eklendi!")
        else:
            self.log("warning", "⚠️ POST sonrası koruma mesajı bulunamadı. Elle kontrol gerekebilir.")

        # 3. CORS kontrolü
        self.log("info", "\n▶ CORS kontrolü...")
        try:
            r_options = requests.options(admin_url, headers={"Origin": "http://evil.com"}, timeout=self.timeout)
            cors_header = r_options.headers.get("Access-Control-Allow-Origin")
        except Exception as e:
            self.log("warning", f"⚠️ CORS isteği başarısız: {e}")
            cors_header = None

        cors_passed = False
        if cors_header == "http://sss.com":
            self.log("error", "❌ CORS zayıf: Kötü kaynaklara izin veriliyor!")
        elif cors_header:
            self.log("success", f"✅ CORS sınırlandırılmış: {cors_header}")
            cors_passed = True
        else:
            self.log("warning", "⚠️ CORS header yok veya engellenmiş olabilir.")

        # 4. Brute-force testi
        self.log("info", "\n🔢 Brute-force login testi yapılıyor...")
        brute_success = False
        for i in range(1, 4):
            try:
                r = self.session.post(login_url, data={"username": "admin", "password": f"wrongpass{i}"}, timeout=self.timeout)
                if "dashboard" in r.text.lower():
                    brute_success = True
                    break
            except Exception:
                pass

        if brute_success:
            self.log("error", "❌ Brute-force korunması yetersiz!")
        else:
            self.log("success", "✅ Brute-force engellendi.")

        # 5. Directory Traversal testi
        self.log("info", "\n📂 Directory Traversal testi...")
        traversal_url = admin_url + "?file=../../../../etc/passwd"
        try:
            r = self.session.get(traversal_url, timeout=self.timeout)
            if "root:x:" in r.text:
                self.log("error", "❌ Directory Traversal açığı var!")
            else:
                self.log("success", "✅ Dosya erişimi engellendi.")
        except Exception as e:
            self.log("warning", f"⚠️ Directory Traversal testi yapılamadı: {e}")

        # 6. XSS testi
        self.log("info", "\n🧬 XSS testi...")
        xss_payload = "<script>alert('xss')</script>"
        try:
            r = self.session.post(admin_url, data={"search": xss_payload}, timeout=self.timeout)
            if xss_payload in r.text:
                self.log("error", "❌ XSS açığı yansıyor!")
            else:
                self.log("success", "✅ XSS koruması aktif.")
        except Exception as e:
            self.log("warning", f"⚠️ XSS testi yapılamadı: {e}")

        # 7. Open Redirect testi
        self.log("info", "\n📥 Open Redirect testi...")
        redirect_url = login_url + "?redirect=http://evil.com"
        try:
            r = self.session.get(redirect_url, allow_redirects=False, timeout=self.timeout)
            if r.status_code in [301, 302] and "evil.com" in r.headers.get("Location", ""):
                self.log("error", "❌ Open Redirect açığı var!")
            else:
                self.log("success", "✅ Redirect engellenmiş.")
        except Exception as e:
            self.log("warning", f"⚠️ Open Redirect testi yapılamadı: {e}")

        # 8. SSRF testi
        self.log("info", "\n🔎 SSRF testi...")
        ssrf_url = admin_url + "?url=http://sss.com"
        ssrf_open = False
        try:
            r = self.session.get(ssrf_url, timeout=self.timeout)
            if "evil.com" in r.text or r.status_code == 200:
                ssrf_open = True
                self.log("error", "❌ SSRF açığı olası!")
            else:
                self.log("success", "✅ SSRF koruması aktif.")
        except Exception as e:
            self.log("warning", f"⚠️ SSRF testi yapılamadı: {e}")

        # 9. Komut Enjeksiyon testi
        self.log("info", "\n⚙ Komut Enjeksiyon testi...")
        cmd_payload = {"cmd": "echo pentest123"}
        cmd_injection = False
        try:
            r = self.session.post(admin_url, data=cmd_payload, timeout=self.timeout)
            if "pentest123" in r.text:
                self.log("error", "❌ Komut Enjeksiyonu açığı var!")
            else:
                self.log("success", "✅ Komut filtrelenmiş görünüyor.")
                cmd_injection = True
        except Exception as e:
            self.log("warning", f"⚠️ Komut Enjeksiyon testi yapılamadı: {e}")
            cmd_injection = True

        # Risk skoru hesaplama
        risk = 100
        if csrf_passed:
            risk -= 30
        if cors_passed:
            risk -= 20
        if not brute_success:
            risk -= 15
        if not ssrf_open:
            risk -= 15
        if cmd_injection:
            risk -= 10
        risk = max(0, risk)

        self.risk_score_signal.emit(risk)
        self.log("info", f"\n✅ Testler tamamlandı. Risk Skoru: %{risk}")

        self.owasp_result_signal.emit({
            "CSRF": csrf_passed,
            "CORS": cors_passed,
            "BruteForce": not brute_success,
            "SSRF": not ssrf_open,
            "CommandInjection": cmd_injection
        })


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Web Application Security Test Tool 🧠")
        self.setMinimumSize(800, 700)

        self.output = QTextEdit()
        self.output.setReadOnly(True)

        self.raw_label = QLabel("📜 Raw HTTP Response (debug):")
        self.raw_output = QTextEdit()
        self.raw_output.setReadOnly(True)
        self.raw_output.setMaximumHeight(200)

        self.test_button = QPushButton("⏰ Start Tests")
        self.test_button.clicked.connect(self.run_tests)

        self.owasp_table = QTableWidget(5, 2)
        self.owasp_table.setHorizontalHeaderLabels(["OWASP Class", "Status"])
        self.owasp_table.setVerticalHeaderLabels(
            ["CSRF", "CORS", "Brute Force", "SSRF", "Command Injection"])
        self.owasp_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        self.risk_label = QLabel("Risk Score: %0")
        self.risk_label.setAlignment(Qt.AlignCenter)
        self.risk_label.setStyleSheet("font-weight: bold; font-size: 16pt;")

        layout = QVBoxLayout()
        layout.addWidget(self.output)
        layout.addWidget(self.raw_label)
        layout.addWidget(self.raw_output)
        layout.addWidget(self.owasp_table)
        layout.addWidget(self.risk_label)
        layout.addWidget(self.test_button)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def run_tests(self):
        self.output.clear()
        self.raw_output.clear()
        self.owasp_table.clearContents()
        self.risk_label.setText("Risk Score: %0")
        self.test_button.setEnabled(False)

        self.worker = SecurityTester()
        self.worker.log_signal.connect(self.append_output)
        self.worker.raw_response_signal.connect(self.show_raw_response)
        self.worker.owasp_result_signal.connect(self.populate_owasp_table)
        self.worker.risk_score_signal.connect(self.update_risk_score)
        self.worker.finished.connect(lambda: self.test_button.setEnabled(True))
        self.worker.start()

    def append_output(self, level, text):
        # Renkli loglama için
        colors = {
            "info": "black",
            "success": "green",
            "warning": "orange",
            "error": "red"
        }
        color = colors.get(level, "black")
        self.output.setTextColor(Qt.black)  # Varsayılan
        self.output.setTextColor(Qt.GlobalColor(Qt.red) if color=="red" else Qt.black)
        self.output.setTextColor(Qt.GlobalColor(Qt.green) if color=="green" else Qt.black)
        self.output.setTextColor(Qt.GlobalColor(Qt.darkYellow) if color=="orange" else Qt.black)

        # Alternatif, html kullanabiliriz
        self.output.setTextColor(Qt.GlobalColor(Qt.black))  # reset
        html_color = color
        self.output.append(f'<span style="color:{html_color};">{text}</span>')

    def show_raw_response(self, html):
        self.raw_output.setPlainText(html)

    def populate_owasp_table(self, results):
        mapping = {
            "CSRF": "A05:2021 - CSRF",
            "CORS": "A08:2021 - CORS",
            "BruteForce": "A07:2021 - Brute Force",
            "SSRF": "A04:2021 - SSRF",
            "CommandInjection": "A03:2021 - Command Injection"
        }
        for i, key in enumerate(["CSRF", "CORS", "BruteForce", "SSRF", "CommandInjection"]):
            status_item = QTableWidgetItem("✅" if results.get(key, False) else "❌")
            status_item.setTextAlignment(Qt.AlignCenter)
            self.owasp_table.setItem(i, 0, QTableWidgetItem(mapping[key]))
            self.owasp_table.setItem(i, 1, status_item)

    def update_risk_score(self, score):
        self.risk_label.setText(f"Risk Score: %{score}")
        if score > 70:
            color = "red"
        elif score > 40:
            color = "orange"
        else:
            color = "green"
        self.risk_label.setStyleSheet(f"font-weight: bold; font-size: 16pt; color: {color};")
        self.risk_label.setToolTip("Düşük skor daha iyi güvenlik anlamına gelir.")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
