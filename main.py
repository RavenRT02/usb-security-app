import customtkinter as ctk
import base64
from PIL import Image
from io import BytesIO
import CTkMessagebox as msg
import webbrowser
import os
import sys
import subprocess
import winreg as reg
from datetime import datetime as dt
import tkinter.filedialog as fd
import random
import string
import cv2 
import smtplib, re, bcrypt,sqlite3, time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from cryptography.fernet import Fernet
import json
import ctypes
import threading
import pyautogui
import tempfile, shutil
from pathlib import Path

#Works as exe file not when run normally due to microsoft sandbox 
def get_app_data_dir():
    """
    Returns the AppData directory for storing USB security files.
    Creates and hides the folder if it doesn't exist (on Windows).
    """
    appdata = os.environ.get("APPDATA", os.path.expanduser("~"))
    target_dir = os.path.join(appdata, "usb_security")
    print(f"[DEBUG] Target path: {target_dir}")

    if not os.path.exists(target_dir):
        os.makedirs(target_dir)
        print("[DEBUG] Folder created.")
        # Hide the folder (Windows only)
        if sys.platform == "win32":
            try:
                FILE_ATTRIBUTE_HIDDEN = 0x02
                ctypes.windll.kernel32.SetFileAttributesW(target_dir, FILE_ATTRIBUTE_HIDDEN)
                print("[DEBUG] Folder hidden.")
            except Exception as e:
                print(f"[DEBUG] Failed to hide folder: {e}")
    else:
        print("[DEBUG] Folder already exists.")
    return target_dir
folder = get_app_data_dir()

# --- User Management and Registration ---
class UserManager:
    otp_data = {"otp": None, "time": 0}
    db_path = os.path.join(folder, "user_data.db")
    print(f"[DEBUG] Database path: {db_path}")
    db = sqlite3.connect(db_path)
    cursor = db.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL,
        email TEXT NOT NULL,
        password TEXT NOT NULL
    )""")
    db.commit()

    @classmethod
    def is_registered(cls):
        cls.cursor.execute("SELECT COUNT(*) FROM users")
        return cls.cursor.fetchone()[0] >= 1

    @staticmethod
    def hash_password(pwd):
        return bcrypt.hashpw(pwd.encode(), bcrypt.gensalt()).decode()
    
    @staticmethod
    def check_password(pwd, hashed):
        return bcrypt.checkpw(pwd.encode(), hashed.encode())

    @staticmethod
    def validate_password(password):
        return {
            "Uppercase": bool(re.search(r"[A-Z]", password)),
            "Lowercase": bool(re.search(r"[a-z]", password)),
            "Digit": bool(re.search(r"\d", password)),
            "Special": bool(re.search(r"\W", password)),
            "Length": 8 <= len(password) <= 16
        }

    @staticmethod
    def generate_otp():
        return ''.join(random.choices(string.digits, k=6))

    @staticmethod
    def load_smtp_config():

        with open(Info.resource_path("smtp.key"), "rb") as key_f:
            embedded_key = key_f.read()
        try:
            fernet = Fernet(embedded_key)
            with open(Info.resource_path("smtp.enc"), "rb") as enc_file:
                encrypted_data = enc_file.read()
            decrypted_data = fernet.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode("utf-8"))
        except Exception as e:
            raise RuntimeError(f"SMTP configuration load failed: {e}")

    @classmethod
    def send_email(cls, to, subject, body):
        smtp_config = cls.load_smtp_config()
        msg_obj = MIMEMultipart()
        msg_obj['From'] = smtp_config["email_user"]
        msg_obj['To'] = to
        msg_obj['Subject'] = subject
        msg_obj.attach(MIMEText(body, 'plain'))
        try:
            server = smtplib.SMTP(smtp_config["smtp_server"], smtp_config["smtp_port"])
            server.starttls()
            server.login(smtp_config["email_user"], smtp_config["email_pass"])
            server.send_message(msg_obj)
            server.quit()
        except Exception as e:
            msg.CTkMessagebox(title="Email Error", message=f"Failed to send email: {str(e)}", icon="cancel", option_1="OK")

    @classmethod
    def register_user(cls, username, email, pwd):
        hashed_pwd = cls.hash_password(pwd)
        cls.cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                           (username, email, hashed_pwd))
        cls.db.commit()

    @classmethod
    def close_db(cls):
        try:
            cls.cursor.close()
        except Exception:
            pass
        try:
            cls.db.close()
        except Exception:
            pass

class RegisterWindow(ctk.CTkToplevel):
    def __init__(self):
        super().__init__()
        self.title("Register User")
        self.geometry("330x350")
        self.resend_allowed = True
        self.email = None
        self.captcha = ""
        self.otp_timer_label = None
        self.otp_timer_running = False
        self.draw_email_form()

    def draw_email_form(self):
        for widget in self.winfo_children():
            widget.destroy()
        detail_frame = ctk.CTkFrame(self, fg_color="transparent")
        detail_frame.pack(pady=20)
        self.email_label = ctk.CTkLabel(detail_frame, text="Email :")
        self.email_label.grid(row=0, column=0, padx=10, pady=5)
        self.email_entry = ctk.CTkEntry(detail_frame, placeholder_text="Enter Email", width=200)
        self.email_entry.grid(row=0, column=1, padx=10, pady=5)
        self.captcha_label1 = ctk.CTkLabel(detail_frame, text="CAPTCHA :")
        self.captcha_label1.grid(row=1, column=0, padx=10, pady=5)
        self.captcha_entry = ctk.CTkEntry(detail_frame, placeholder_text="Enter CAPTCHA", width=200)
        self.captcha_entry.grid(row=1, column=1, padx=10, pady=5)
        self.captcha = ''.join(random.choices(string.ascii_letters + string.digits, k=5))
        self.captcha_label = ctk.CTkLabel(self, text=f"CAPTCHA: {self.captcha}")
        self.captcha_label.pack(pady=5)
        self.send_button = ctk.CTkButton(self, text="Send OTP", command=self.send_otp)
        self.send_button.pack(pady=10)
        self.otp_timer_label = ctk.CTkLabel(self, text="")
        self.otp_timer_label.pack(pady=2)
        self.update_otp_timer_label()

    def send_otp(self):
        user_input = self.captcha_entry.get().strip()
        if user_input != self.captcha:
            msg.CTkMessagebox(title="Invalid CAPTCHA", message="Please enter the correct CAPTCHA.", icon="cancel", option_1="OK")
            self.captcha = ''.join(random.choices(string.ascii_letters + string.digits, k=5))
            self.captcha_label.configure(text=f"CAPTCHA: {self.captcha}")
            return
        now = time.time()
        remaining = int(120 - (now - UserManager.otp_data["time"]))
        if remaining > 0:
            self.update_otp_timer_label()
            return
        self.email = self.email_entry.get().strip()
        if not re.match(r"[^@]+@[^@]+\.[^@]+", self.email):
            msg.CTkMessagebox(title="Invalid Email", message="Please enter a valid email address.", icon="cancel", option_1="OK")
            return
        otp = UserManager.generate_otp()
        UserManager.otp_data["otp"] = otp
        UserManager.otp_data["time"] = now
        try:
            UserManager.send_email(self.email, "Your OTP for USB Security Registration", f"Your OTP is: {otp}")
            msg.CTkMessagebox(title="OTP Sent", message=f"An OTP has been sent to {self.email}.", icon="check", option_1="OK")
            self.draw_otp_form()
        except Exception as e:
            msg.CTkMessagebox(title="Email Error", message=f"Failed to send OTP: {str(e)}", icon="cancel", option_1="OK")
        self.update_otp_timer_label()
        if not self.otp_timer_running:
            self.otp_timer_running = True
            self.start_otp_timer()

    def enable_resend_otp(self):
        self.resend_allowed = True
        if hasattr(self, "resend_otp_button"):
            self.resend_otp_button.configure(state="normal")

    def start_otp_timer(self):
        def tick():
            self.update_otp_timer_label()
            now = time.time()
            if now - UserManager.otp_data["time"] < 120:
                self.after(1000, tick)
            else:
                self.otp_timer_running = False
                self.update_otp_timer_label()
        tick()

    def draw_otp_form(self):
        for widget in self.winfo_children():
            widget.destroy()
        self.otp_entry = ctk.CTkEntry(self, placeholder_text="Enter OTP")
        self.otp_entry.pack(pady=20)
        ctk.CTkButton(self, text="Verify OTP", command=self.verify_otp).pack(pady=10)

        # CAPTCHA for resend
        self.resend_captcha = ''.join(random.choices(string.ascii_letters + string.digits, k=5))
        self.resend_captcha_label = ctk.CTkLabel(self, text=f"CAPTCHA: {self.resend_captcha}")
        self.resend_captcha_label.pack(pady=2)
        self.resend_captcha_entry = ctk.CTkEntry(self, placeholder_text="Enter CAPTCHA")
        self.resend_captcha_entry.pack(pady=2)

        self.resend_otp_button = ctk.CTkButton(self, text="Resend OTP", command=self.resend_otp)
        self.resend_otp_button.pack(pady=5)

        ctk.CTkButton(self, text="Change Email", command=self.change_email).pack(pady=5)
        self.otp_timer_label = ctk.CTkLabel(self, text="")
        self.otp_timer_label.pack(pady=2)
        self.update_otp_timer_label()
        self.update_resend_button_state()
        if not self.otp_timer_running and int(120 - (time.time() - UserManager.otp_data["time"])) > 0:
            self.otp_timer_running = True
            self.start_otp_timer()

    def update_otp_timer_label(self):
        now = time.time()
        remaining = int(120 - (now - UserManager.otp_data["time"]))
        if remaining > 0:
            mins, secs = divmod(remaining, 60)
            self.otp_timer_label.configure(text=f"Request OTP available in {mins:02d}:{secs:02d}")
        else:
            self.otp_timer_label.configure(text="You can request a new OTP.")
        self.update_resend_button_state()

    def update_resend_button_state(self):
        now = time.time()
        remaining = int(120 - (now - UserManager.otp_data["time"]))
        if hasattr(self, "resend_otp_button"):
            if remaining > 0:
                self.resend_otp_button.configure(state="disabled")
            else:
                self.resend_otp_button.configure(state="normal")    

    def resend_otp(self):
        now = time.time()
        remaining = int(120 - (now - UserManager.otp_data["time"]))
        if remaining > 0:
            return
        user_input = self.resend_captcha_entry.get().strip()
        if user_input != self.resend_captcha:
            msg.CTkMessagebox(title="Invalid CAPTCHA", message="Please enter the correct CAPTCHA.", icon="cancel", option_1="OK")
            self.resend_captcha = ''.join(random.choices(string.ascii_letters + string.digits, k=5))
            self.resend_captcha_label.configure(text=f"CAPTCHA: {self.resend_captcha}")
            self.resend_captcha_entry.delete(0, ctk.END)
            return
        otp = UserManager.generate_otp()
        UserManager.otp_data["otp"] = otp
        UserManager.otp_data["time"] = now
        try:
            UserManager.send_email(self.email, "Your OTP for USB Security Registration", f"Your OTP is: {otp}")
            msg.CTkMessagebox(title="OTP Sent", message=f"An OTP has been sent to {self.email}.", icon="check", option_1="OK")
            # Reset CAPTCHA for next resend
            self.resend_captcha = ''.join(random.choices(string.ascii_letters + string.digits, k=5))
            self.resend_captcha_label.configure(text=f"CAPTCHA: {self.resend_captcha}")
            self.resend_captcha_entry.delete(0, ctk.END)
        except Exception as e:
            msg.CTkMessagebox(title="Email Error", message=f"Failed to send OTP: {str(e)}", icon="cancel", option_1="OK")
        self.update_otp_timer_label()
        if not self.otp_timer_running:
            self.otp_timer_running = True
            self.start_otp_timer() 

    def change_email(self):
        # Reset OTP rate limiting
        UserManager.otp_data["time"] = 0
        self.otp_timer_running = False
        self.draw_email_form()

    def verify_otp(self):
        entered = self.otp_entry.get().strip()
        if entered == UserManager.otp_data["otp"]:
            self.draw_credentials_form()
        else:
            msg.CTkMessagebox(title="Invalid OTP", message="The entered OTP is incorrect.", icon="cancel", option_1="OK")

    def draw_credentials_form(self):
        for widget in self.winfo_children():
            widget.destroy()
        self.username_entry = ctk.CTkEntry(self, placeholder_text="Username")
        self.username_entry.pack(pady=5)
        self.password_entry = ctk.CTkEntry(self, placeholder_text="Password", show="*")
        self.password_entry.pack(pady=5)

        def show_password():
            self.password_entry.configure(show="" if self.password_show.get() else "*")
            self.confirm_entry.configure(show="" if self.password_show.get() else "*")

        self.password_entry.bind("<KeyRelease>", self.check_strength)
        self.confirm_entry = ctk.CTkEntry(self, placeholder_text="Confirm Password", show="*")
        self.confirm_entry.pack(pady=5)
        self.password_show = ctk.CTkCheckBox(self, text="Show Password",checkbox_height=20, checkbox_width=20, 
                                             command=lambda: show_password())
        self.password_show.pack(pady=5)
        self.strength_label = ctk.CTkLabel(self, text="")
        self.strength_label.pack(pady=5)
        ctk.CTkButton(self, text="Register", command=self.register_user).pack(pady=10)
        self.relaunch = ctk.CTkLabel(self, text= "Please re-launch the application after registration")
        self.relaunch.pack(pady=2)
        self.note = ctk.CTkLabel(self, text= "Always launch the application as administrator")
        self.note.pack(pady=2)

    def check_strength(self, event=None):
        pwd = self.password_entry.get()
        rules = UserManager.validate_password(pwd)
        display = "\n".join([f"{k}: {'✔️' if v else '❌'}" for k, v in rules.items()])
        self.strength_label.configure(text=display)

    def register_user(self):
        username = self.username_entry.get().strip()
        pwd = self.password_entry.get().strip()
        confirm = self.confirm_entry.get().strip()
        if pwd != confirm:
            msg.CTkMessagebox(title="Password Mismatch", message="Passwords do not match.", icon="cancel", option_1="OK")
            return
        rules = UserManager.validate_password(pwd)
        if not all(rules.values()):
            msg.CTkMessagebox(title="Weak Password", message="Password must contain uppercase, lowercase, digit, special character, and be 8-16 characters long.", icon="cancel", option_1="OK")
            return
        UserManager.register_user(username, self.email, pwd)
        msg.CTkMessagebox(title="Registration Successful", message="User registered successfully!", icon="check", option_1="OK")
        self.destroy()

class USBLogger:
    log_file = os.path.join(folder, "usb_log.txt")

    @staticmethod
    def log_action(action):
        timestamp = dt.now().strftime("%d-%m-%Y %H:%M:%S")
        with open(USBLogger.log_file, "a") as file:
            file.write(f"{timestamp} - {action}\n")

    @staticmethod
    def capture_failed_attempt_images(reason="login", webcam_enabled=True):
        """Capture intruder images with webcam. If webcam disabled/unavailable, just log it."""
        if not webcam_enabled:
            USBLogger.log_action("Intruder capture skipped — webcam disabled.")
            return

        def run():
            try:
                cam = cv2.VideoCapture(0, cv2.CAP_DSHOW)
                if not cam.isOpened():
                    USBLogger.log_action("Webcam unavailable — capture skipped.")
                    return

                for i in range(3):  # capture a few frames
                    ret, frame = cam.read()
                    if ret:
                        timestamp = dt.now().strftime("%Y%m%d_%H%M%S")
                        filename = os.path.join(folder, f"failed_{reason}_{timestamp}_{i+1}.jpg")
                        cv2.imwrite(filename, frame)
                        USBLogger.log_action(f"Captured webcam image: {filename}")
                    else:
                        USBLogger.log_action("Webcam frame read failed.")
                    time.sleep(1)

                cam.release()
                cv2.destroyAllWindows()

            except Exception as e:
                USBLogger.log_action(f"Webcam capture error: {str(e)}")

        threading.Thread(target=run, daemon=True).start()

    @staticmethod
    def get_log_content():
        try:
            with open(USBLogger.log_file, "r") as file:
                return file.read().strip().splitlines()
        except FileNotFoundError:
            return ["Log file not found. No actions have been logged yet."]

    @staticmethod
    def clear_log():
        timestamp = dt.now().strftime("%d-%m-%Y %H:%M:%S")
        secure_note = f"{timestamp} - Log cleared (secure action)"
        with open(USBLogger.log_file, "w") as file:
            file.write(secure_note + "\n")
        return [secure_note]
    
class USBManager:

    @staticmethod
    def load_smtp_config():
        key_path = Info.resource_path("smtp.key")
        enc_path = Info.resource_path("smtp.enc")
        with open(key_path, "rb") as key_f:
            embedded_key = key_f.read()
        try:
            fernet = Fernet(embedded_key)
            with open(enc_path, "rb") as enc_file:
                encrypted_data = enc_file.read()
            decrypted_data = fernet.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode("utf-8"))
        except Exception as e:
            raise RuntimeError(f"SMTP configuration load failed: {e}")
        
    @staticmethod
    def usb_status():
        reg_path = r"SYSTEM\CurrentControlSet\Services\USBSTOR"
        try:
            with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, reg_path) as key:
                value, _ = reg.QueryValueEx(key, "Start")
            if value == 3:
                status = "USB ports are Enabled"
                msg.CTkMessagebox(title="USB Status", message="USB Storage Devices are Enabled", icon="check", option_1="OK")
            elif value == 4:
                status = "USB ports are Disabled"
                msg.CTkMessagebox(title="USB Status", message="USB Storage Devices are Disabled", icon="cancel", option_1="OK")
            else:
                status = "USB ports status is unknown"
                msg.CTkMessagebox(title="USB Status", message="USB Storage Devices status is unknown", icon="warning", option_1="OK")
        except FileNotFoundError:
            status = "USBSTOR registry key not found"
            msg.CTkMessagebox(title="Error", message="USBSTOR registry key not found. Please run the application as an administrator.", icon="cancel", option_1="OK")
        except Exception as e:
            status = f"An unexpected error occurred: {str(e)}"
            msg.CTkMessagebox(title="Error", message=status, icon="cancel", option_1="OK")
        USBLogger.log_action(f'Checked USB status : {status}')

    @staticmethod
    def enable_usb():
        bat_path = Info.resource_path("enable_usb.bat")
        subprocess.run([bat_path], shell=True)
        USBLogger.log_action('Enabled USB Ports')

    @staticmethod
    def disable_usb():
        bat_path = Info.resource_path("disable_usb.bat")
        subprocess.run([bat_path], shell=True)
        USBLogger.log_action('Disabled USB Ports')

class Info:
    @staticmethod
    def resource_path(relative_path: str) -> str:
        """Return absolute path to resource, works for dev & PyInstaller bundle"""
        try:
            base_path = sys._MEIPASS   # PyInstaller temp folder (admin context)
        except Exception:
            base_path = os.path.abspath(".")  # Fallback in dev
        return os.path.join(base_path, relative_path)

    @staticmethod
    def get_shared_temp() -> str:
        """Return a folder accessible to all users."""
        shared = os.path.join(os.environ.get("PUBLIC", r"C:\Users\Public"), "usb_security", "temp")
        os.makedirs(shared, exist_ok=True)
        return shared

    @staticmethod
    def open_html(filename: str):
        """Safely open an HTML file in the default browser, copying it
        to a shared folder accessible to Admin + Student."""
        src_path = Info.resource_path(filename)

        if not os.path.exists(src_path):
            raise FileNotFoundError(f"Resource not found: {src_path}")

        # Copy into shared public folder
        dst_path = os.path.join(Info.get_shared_temp(), filename)
        shutil.copyfile(src_path, dst_path)

        # Open via file:// URI
        webbrowser.open(Path(dst_path).as_uri())

    @staticmethod
    def open_project_info():
        Info.open_html("project_info.html")

    @staticmethod
    def open_about_app():
        Info.open_html("about_app.html")

class LogWindow:
    def __init__(self, master):
        self.log_content = USBLogger.get_log_content()
        self.log_window = ctk.CTkToplevel(master)
        self.log_window.title("USB Log")
        self.log_window.geometry("750x520")
        self.setup_ui()

    def setup_ui(self):
        control_frame = ctk.CTkFrame(master=self.log_window)
        control_frame.pack(padx=15, pady=(10, 5), fill="x")

        self.search_var = ctk.StringVar()
        self.search_var.trace_add("write", self.filter_log)
        search_entry = ctk.CTkEntry(master=control_frame, textvariable=self.search_var, placeholder_text="Search log...")
        search_entry.pack(side="left", padx=10, pady=5, fill="x", expand=True)

        self.filter_var = ctk.StringVar(value="All")
        filter_options = ["All", "Enabled", "Disabled", "Checked", "Cleared"]
        filter_dropdown = ctk.CTkOptionMenu(master=control_frame, variable=self.filter_var, values=filter_options, command=lambda _: self.filter_log())
        filter_dropdown.pack(side="left", padx=10)

        log_frame = ctk.CTkFrame(master=self.log_window)
        log_frame.pack(padx=15, pady=5, fill="both", expand=True)

        self.log_text = ctk.CTkTextbox(master=log_frame, wrap="word", state="normal", font=("Consolas", 12), fg_color="#2c2f33",
            text_color="white", border_color="#7289da", border_width=1, corner_radius=5)
        self.log_text.grid(row=0, column=0, sticky="nsew")

        log_scrollbar = ctk.CTkScrollbar(master=log_frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scrollbar.set)
        log_scrollbar.grid(row=0, column=1, sticky="ns")

        log_frame.grid_rowconfigure(0, weight=1)
        log_frame.grid_columnconfigure(0, weight=1)

        self.update_log_text(reversed(self.log_content))

        button_frame = ctk.CTkFrame(master=self.log_window, fg_color="transparent")
        button_frame.pack(pady=10)

        clear_button = ctk.CTkButton(master=button_frame, text="Clear Log (Secure)", hover_color="#d15a15", command=self.secure_clear_log)
        clear_button.pack(side="left", padx=10)

        export_button = ctk.CTkButton(master=button_frame, text="Export Log", hover_color="#d15a15", command=self.export_log)
        export_button.pack(side="left", padx=10)

        close_button = ctk.CTkButton(master=button_frame, text="Close", hover_color="#d15a15", command=self.log_window.destroy)
        close_button.pack(side="left", padx=10)

    def filter_log(self, *args):
        search_term = self.search_var.get().lower()
        selected_type = self.filter_var.get()
        filtered = []
        for line in reversed(self.log_content):
            matches_search = search_term in line.lower()
            matches_type = (
                selected_type == "All" or
                (selected_type == "Enabled" and "enabled" in line.lower()) or
                (selected_type == "Disabled" and "disabled" in line.lower()) or
                (selected_type == "Checked" and "checked" in line.lower()) or
                (selected_type == "Cleared" and "cleared" in line.lower())
            )
            if matches_search and matches_type:
                filtered.append(line)
        self.update_log_text(filtered)

    def update_log_text(self, lines):
        self.log_text.configure(state="normal")
        self.log_text.delete("0.0", "end")
        self.log_text.insert("0.0", "\n".join(lines))
        self.log_text.configure(state="disabled")

    def export_log(self):
        export_path = fd.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")], title="Export Log As")
        if export_path:
            with open(export_path, "w") as e_file:
                e_file.write("\n".join(self.log_content))
            msg.CTkMessagebox(title="Export Log", message=f"Log exported to:\n{export_path}", icon="check", option_1="OK")

    def secure_clear_log(self):
        self.log_content = USBLogger.clear_log()
        self.update_log_text(self.log_content)

class LoginWindow:
    def __init__(self, master, on_success):
        self.master = master
        self.on_success = on_success
        self.login_window = ctk.CTkToplevel(master)
        self.login_window.title("Login")
        self.login_window.geometry("370x290")
        self.forgot_window = None 
        self.failed_login_attempts = 0
        self.setup_ui()

    def setup_ui(self):
        def login():
            email = email_entry.get().strip()
            password = log_pass_entry.get().strip()

            if not email or not password:
                msg.CTkMessagebox(title="Input Error", message="Please enter both email and password.", icon="cancel", option_1="OK")
                return

            # Check if user exists by email or username
            emails = [row[0] for row in UserManager.cursor.execute("SELECT email FROM users").fetchall()]
            usernames = [row[0] for row in UserManager.cursor.execute("SELECT username FROM users").fetchall()]
            if email not in emails and email not in usernames:
                msg.CTkMessagebox(title="Login Error", message="Email or Username not registered.", icon="cancel", option_1="OK")
                return

            # Validate password
            hashed_password = UserManager.hash_password(password)
            user_data = UserManager.cursor.execute(
                "SELECT * FROM users WHERE email=? OR username=?",
                (email, email)
            ).fetchone()

            if not user_data or not UserManager.check_password(password, user_data[3]):
                self.failed_login_attempts = getattr(self, "failed_login_attempts", 0) + 1
                msg.CTkMessagebox(title="Login Error", message="Incorrect password.", icon="cancel", option_1="OK")
                USBLogger.log_action(f'Failed login attempt - attempt {self.failed_login_attempts}')
                return

            # Successful login
            msg.CTkMessagebox(title="Login Successful", message="Welcome back!", icon="check", option_1="OK")

            self.login_window.destroy()
            if hasattr(self.master, "deiconify"):
                self.master.deiconify()
            self.on_success() 
            USBLogger.log_action(f'User {user_data[1]} logged in successfully')

        login_frame = ctk.CTkFrame(master=self.login_window, fg_color="transparent")
        login_frame.pack(pady=20)
        email_label = ctk.CTkLabel(master=login_frame, text="Email or Username : ")
        email_label.grid(pady=5, padx=10, row=0, column=0)
        email_label.configure(text_color="#2E86C1", fg_color="transparent", font=("Arial", 12, "bold"))
        email_entry = ctk.CTkEntry(master=login_frame)
        email_entry.configure(placeholder_text="Enter your email or username", width=200)
        email_entry.grid(pady=5, padx=10, row=0, column=1)
        log_pass_label = ctk.CTkLabel(master=login_frame, text="Password : ")
        log_pass_label.grid(pady=5, padx=10, row=1, column=0)
        log_pass_label.configure(text_color="#2E86C1", fg_color="transparent", font=("Arial", 12, "bold"))
        log_pass_entry = ctk.CTkEntry(master=login_frame, show="*", width=200)
        log_pass_entry.grid(pady=5, padx=10, row=1, column=1)
        log_pass_entry.configure(placeholder_text="Enter your password")
        show_password = ctk.CTkCheckBox(master=self.login_window, text="Show Password", checkbox_height=20, checkbox_width=20)
        show_password.pack(pady=1)
        show_password.configure(command=lambda: log_pass_entry.configure(show="" if show_password.get() else "*"))
        login_button = ctk.CTkButton(self.login_window, text="Login", command=login)
        login_button.pack(pady=20)
        self.forgot_button = ctk.CTkButton(self.login_window, text="Forgot Password?", fg_color="#2E86C1", text_color="white",
                                   hover_color="#d15a15", command=self.open_forgot_password)
        self.forgot_button.pack(pady=5)
        self.note = ctk.CTkLabel(self.login_window, text= "Always launch the application as administrator")
        self.note.pack(pady=2)
    
    def open_forgot_password(self):
        if self.forgot_window is not None and self.forgot_window.winfo_exists():
            self.forgot_window.focus()
            return
        self.forgot_button.configure(state="disabled")
        self.forgot_window = ForgotPasswordWindow(self.login_window)
        self.forgot_window.protocol("WM_DELETE_WINDOW", self.on_forgot_close)

    def on_forgot_close(self):
        if self.forgot_window is not None:
            self.forgot_window.destroy()
            self.forgot_window = None
        self.forgot_button.configure(state="normal")

class ForgotPasswordWindow(ctk.CTkToplevel):
    RATE_LIMIT_SECONDS = 120

    def __init__(self, master):
        super().__init__(master)
        self.title("Forgot Password")
        self.geometry("350x320")
        self.email = None
        self.otp = None
        self.otp_sent_time = 0
        self.otp_verified = False
        self.captcha = ""
        self.otp_timer_label = None
        self.otp_timer_running = False
        self.last_otp_request_time = 0
        self.draw_email_form()

    def draw_email_form(self):
        for widget in self.winfo_children():
            widget.destroy()
        ctk.CTkLabel(self, text="Enter your registered email:").pack(pady=10)
        self.email_entry = ctk.CTkEntry(self, placeholder_text="Email", width=200)
        self.email_entry.pack(pady=5)

        #captcha

        self.captcha = ''.join(random.choices(string.ascii_letters + string.digits, k=5))
        self.captcha_label = ctk.CTkLabel(self, text=f"CAPTCHA: {self.captcha}")
        self.captcha_label.pack(pady=2)
        self.captcha_entry = ctk.CTkEntry(self, placeholder_text="Enter CAPTCHA", width=200)
        self.captcha_entry.pack(pady=2)

        self.send_otp_btn = ctk.CTkButton(self, text="Send OTP", command=self.send_otp)
        self.send_otp_btn.pack(pady=10)
        self.otp_timer_label = ctk.CTkLabel(self, text="")
        self.otp_timer_label.pack(pady=2)
        self.update_otp_timer_label()
        if not self.otp_timer_running and int(self.RATE_LIMIT_SECONDS - (time.time() - self.last_otp_request_time)) > 0:
            self.otp_timer_running = True
            self.start_otp_timer()

    def send_otp(self):
        now = time.time()
        remaining = int(self.RATE_LIMIT_SECONDS - (now - self.last_otp_request_time))
        
        if remaining > 0:
            self.update_otp_timer_label()
            return
        user_input = self.captcha_entry.get().strip()
        
        if user_input != self.captcha:
            msg.CTkMessagebox(title="Invalid CAPTCHA", message="Please enter the correct CAPTCHA.", icon="cancel", option_1="OK")
            self.captcha = ''.join(random.choices(string.ascii_letters + string.digits, k=5))
            self.captcha_label.configure(text=f"CAPTCHA: {self.captcha}")
            self.captcha_entry.delete(0, ctk.END)
            return
        email = self.email_entry.get().strip()
        UserManager.cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        user = UserManager.cursor.fetchone()
        
        if not user:
            msg.CTkMessagebox(title="Error", message="Email not registered.", icon="cancel", option_1="OK")
            return
        self.email = email
        self.otp = UserManager.generate_otp()
        self.otp_sent_time = now
        self.last_otp_request_time = now
        
        try:
            UserManager.send_email(
                self.email,
                "Your OTP for USB Security Password Reset",
                f"Your OTP for password reset is: {self.otp}\n\nThis OTP is valid for 5 minutes."
            )
            msg.CTkMessagebox(title="OTP Sent", message=f"An OTP has been sent to {self.email}.", icon="check", option_1="OK")
            self.draw_otp_form()
        
        except Exception as e:
            msg.CTkMessagebox(title="Email Error", message=f"Failed to send OTP: {str(e)}", icon="cancel", option_1="OK")
        self.update_otp_timer_label()
        
        if not self.otp_timer_running:
            self.otp_timer_running = True
            self.start_otp_timer()

    def update_otp_timer_label(self):
        now = time.time()
        remaining = int(self.RATE_LIMIT_SECONDS - (now - self.last_otp_request_time))
        
        if remaining > 0:
            mins, secs = divmod(remaining, 60)
            self.otp_timer_label.configure(text=f"Request OTP available in {mins:02d}:{secs:02d}")
            
            if hasattr(self, "send_otp_btn"):
                self.send_otp_btn.configure(state="disabled")
        
        else:
            self.otp_timer_label.configure(text="You can request a new OTP.")
            
            if hasattr(self, "send_otp_btn"):
                self.send_otp_btn.configure(state="normal")

    def start_otp_timer(self):
        def tick():
            self.update_otp_timer_label()
            now = time.time()
            
            if now - self.last_otp_request_time < self.RATE_LIMIT_SECONDS:
                self.after(1000, tick)
            else:
                self.otp_timer_running = False
                self.update_otp_timer_label()
        tick()


    def draw_otp_form(self):
        for widget in self.winfo_children():
            widget.destroy()
        ctk.CTkLabel(self, text=f"OTP sent to: {self.email}").pack(pady=10)
        self.otp_entry = ctk.CTkEntry(self, placeholder_text="Enter OTP")
        self.otp_entry.pack(pady=5)
        ctk.CTkButton(self, text="Verify OTP", command=self.verify_otp).pack(pady=10)
        ctk.CTkButton(self, text="Back", command=self.draw_email_form).pack(pady=5)

    def verify_otp(self):
        entered = self.otp_entry.get().strip()
        if not self.otp or time.time() - self.otp_sent_time > 300:
            msg.CTkMessagebox(title="OTP Expired", message="OTP expired. Please request a new one.", icon="cancel", option_1="OK")
            self.draw_email_form()
            return
        if entered == self.otp:
            self.otp_verified = True
            self.draw_reset_form()
        else:
            msg.CTkMessagebox(title="Invalid OTP", message="Incorrect OTP.", icon="cancel", option_1="OK")

    def draw_reset_form(self):
        for widget in self.winfo_children():
            widget.destroy()

        ctk.CTkLabel(self, text="Enter New Password:").pack(pady=5)
        self.new_pass_entry = ctk.CTkEntry(self, placeholder_text="New Password", show="*")
        self.new_pass_entry.pack(pady=5)
        self.confirm_pass_entry = ctk.CTkEntry(self, placeholder_text="Confirm Password", show="*")
        self.confirm_pass_entry.pack(pady=5)
        def show_password():
            self.new_pass_entry.configure(show="" if self.password_show.get() else "*")
            self.confirm_pass_entry.configure(show="" if self.password_show.get() else "*")
        self.password_show = ctk.CTkCheckBox(self, text="Show Password",checkbox_height=20, checkbox_width=20, 
                                             command=lambda: show_password())
        self.password_show.pack(pady=5)
        self.strength_label = ctk.CTkLabel(self, text="")
        self.strength_label.pack(pady=5)
        self.new_pass_entry.bind("<KeyRelease>", self.check_strength)
        ctk.CTkButton(self, text="Reset Password", command=self.reset_password).pack(pady=10)

    def check_strength(self, event=None):
        pwd = self.new_pass_entry.get()
        rules = UserManager.validate_password(pwd)
        display = "\n".join([f"{k}: {'✔️' if v else '❌'}" for k, v in rules.items()])
        self.strength_label.configure(text=display)

    def reset_password(self):
        pwd = self.new_pass_entry.get().strip()
        confirm = self.confirm_pass_entry.get().strip()
        if pwd != confirm:
            msg.CTkMessagebox(title="Password Mismatch", message="Passwords do not match.", icon="cancel", option_1="OK")
            return
        rules = UserManager.validate_password(pwd)
        if not all(rules.values()):
            msg.CTkMessagebox(title="Weak Password", message="Password must meet all requirements.", icon="cancel", option_1="OK")
            return
        hashed_pwd = UserManager.hash_password(pwd)
        UserManager.cursor.execute("UPDATE users SET password=? WHERE email=?", (hashed_pwd, self.email))
        UserManager.db.commit()
        msg.CTkMessagebox(title="Success", message="Password reset successfully!", icon="check", option_1="OK")
        self.destroy()

class MainAppWindow:
    def __init__(self, master, webcam_enabled = True):
        self.master = master
        self.main_app = ctk.CTkToplevel(master)
        self.main_app.title("USB Security")
        self.main_app.geometry("600x450")
        self.webcam_enabled = webcam_enabled
        self.setup_ui()

    def setup_ui(self):
        def on_main_close():
            UserManager.close_db()
            self.main_app.destroy()
            self.master.destroy()

        username = UserManager.cursor.execute("SELECT username FROM users").fetchone()[0]

        self.main_app.protocol("WM_DELETE_WINDOW", on_main_close)

        title_frame = ctk.CTkFrame(master=self.main_app, fg_color="transparent", corner_radius=10)
        title_frame.pack(pady=20)

        title = ctk.CTkLabel(master=title_frame, text_color="#2E86C1", text="USB Physical Security", font=("Arial", 20, "bold"))
        title.pack(pady=1)

        subtitle = ctk.CTkLabel(master=title_frame, text_color="#A9603B", text=f'Welcome {username}', font=("Arial", 14))
        subtitle.pack(pady=1)

        button_frame = ctk.CTkFrame(master=self.main_app, fg_color= "transparent", corner_radius=10)
        button_frame.pack(pady=20)

        about_button = ctk.CTkButton(master=button_frame, text="About", hover_color="#d15a15", command=Info.open_about_app)
        about_button.pack(pady=10)

        pinfo_button = ctk.CTkButton(master=button_frame, text="Project Info", hover_color="#d15a15", command=Info.open_project_info)
        pinfo_button.pack(pady=10)

        usb_status_button = ctk.CTkButton(master=button_frame, text="USB Status", hover_color="#d15a15", command=USBManager.usb_status)
        usb_status_button.pack(pady=10)

        check_log_button = ctk.CTkButton(master=button_frame, text="Check Logs", hover_color="#d15a15", command=lambda: LogWindow(self.main_app))
        check_log_button.pack(pady=10)

        usb_frame = ctk.CTkFrame(master=self.main_app)
        usb_frame.pack(pady=10)

        # Icons
        usb_c_64 = "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"
        usb_c_decode = base64.b64decode(usb_c_64)
        usb_c_byte = Image.open(BytesIO(usb_c_decode))
        usb_connect_icon = ctk.CTkImage(light_image=usb_c_byte, size=(32, 32))

        usb_d_64 = "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"
        usb_d_decode = base64.b64decode(usb_d_64)
        usb_d_byte = Image.open(BytesIO(usb_d_decode))
        usb_disconnect_icon = ctk.CTkImage(light_image=usb_d_byte, size=(32, 32))

        con_button = ctk.CTkButton(usb_frame, image=usb_connect_icon, text="Enable USB", compound="left",
                                   fg_color="green", text_color="black", hover_color="#d15a15", command=self.enable_usb)
        con_button.grid(row=0, column=1, pady=10, padx=10)

        discon_button = ctk.CTkButton(usb_frame, image=usb_disconnect_icon, text="Disable USB", compound="left",
                                      fg_color="#a31735", text_color="black", hover_color="#d15a15", command=self.disable_usb)
        discon_button.grid(row=0, column=0, pady=10, padx=10)

    def enable_usb(self):
        PasswordPrompt(self.main_app, USBManager.enable_usb, "Enabled USB Ports", webcam_enabled = self.webcam_enabled)

    def disable_usb(self):
        PasswordPrompt(self.main_app, USBManager.disable_usb, "Disabled USB Ports", webcam_enabled = self.webcam_enabled)

class PasswordPrompt:
    temp_password = None
    temp_password_expiry = 0
    last_request_time = 0
    rate_limit_seconds = 120  # 2 minutes

    def __init__(self, master, action, log_message, webcam_enabled = True):
        self.master = master
        self.action = action
        self.log_message = log_message
        self.webcam_enabled = webcam_enabled
        self.failed_attempts = [0]
        self.password_window = ctk.CTkToplevel(master)
        self.password_window.title("Enter Password")
        self.password_window.geometry("550x250")
        self.timer_label = None
        self.timer_running = False
        self.setup_ui()

    def setup_ui(self):
        password_frame = ctk.CTkFrame(master=self.password_window)
        password_frame.pack(pady=10, padx=20, fill="both", expand=True)
        password_label = ctk.CTkLabel(master=password_frame, text="Enter Password:")
        password_label.pack(pady=5)
        self.password_entry = ctk.CTkEntry(master=password_frame, show="*")
        self.password_entry.pack(pady=5)
        show_password = ctk.CTkCheckBox(master=password_frame, text="Show Password", checkbox_height=20, checkbox_width=20,
                                        command=lambda: self.password_entry.configure(show="" if show_password.get() else "*"))
        show_password.pack(pady=1)
        button_frame = ctk.CTkFrame(master=password_frame)
        button_frame.pack(pady=10)

        get_password_button = ctk.CTkButton(master=button_frame, text="Get password", fg_color="#0ecc3e", text_color="black",
                                            hover_color="#d15a15", command=self.send_temp_password)
        get_password_button.grid(pady=10, padx=5, row=0, column=2)

        submit_button = ctk.CTkButton(master=button_frame, text="Submit", fg_color="#0ecc3e", text_color="black",
                                      hover_color="#d15a15", command=self.check_password)
        submit_button.grid(pady=10, padx=5, row=0, column=0)
        cancel_button = ctk.CTkButton(master=button_frame, text="Cancel", fg_color="#a31735", text_color="black",
                                      hover_color="#d15a15", command=self.password_window.destroy)
        cancel_button.grid(pady=10, padx=5, row=0, column=1)

        self.timer_label = ctk.CTkLabel(master=password_frame, text="")
        self.timer_label.pack(pady=5)
        self.update_timer_label()

    def send_temp_password(self):
        now = time.time()
        if now - PasswordPrompt.last_request_time < PasswordPrompt.rate_limit_seconds:
            self.update_timer_label()
            return

        # Generate a random password
        temp_pwd = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
        PasswordPrompt.temp_password = temp_pwd
        PasswordPrompt.temp_password_expiry = now + 300  # 5 minutes validity
        PasswordPrompt.last_request_time = now

        # Get user email (first user in DB)
        UserManager.cursor.execute("SELECT email FROM users LIMIT 1")
        row = UserManager.cursor.fetchone()
        email = row[0] if row else None

        if not email:
            msg.CTkMessagebox(title="Error", message="No user email found.", icon="cancel", option_1="OK")
            return

        try:
            UserManager.send_email(
                email,
                "Your Temporary USB Action Password",
                f"Your one-time password for USB action is: {temp_pwd}\n\nThis password is valid for 5 minutes."
            )
            msg.CTkMessagebox(title="Password Sent", message=f"A temporary password has been sent to {email}.", icon="check", option_1="OK")
        except Exception as e:
            msg.CTkMessagebox(title="Email Error", message=f"Failed to send password: {str(e)}", icon="cancel", option_1="OK")

        self.update_timer_label()
        if not self.timer_running:
            self.timer_running = True
            self.start_timer()

    def update_timer_label(self):
        now = time.time()
        remaining = int(PasswordPrompt.rate_limit_seconds - (now - PasswordPrompt.last_request_time))
        if remaining > 0:
            mins, secs = divmod(remaining, 60)
            self.timer_label.configure(text=f"Get password available in {mins:02d}:{secs:02d}")
        else:
            self.timer_label.configure(text="You can request a new password.")

    def start_timer(self):
        def tick():
            self.update_timer_label()
            now = time.time()
            if now - PasswordPrompt.last_request_time < PasswordPrompt.rate_limit_seconds:
                self.password_window.after(1000, tick)
            else:
                self.timer_running = False
                self.update_timer_label()
        tick()

    def check_password(self):
        entered = self.password_entry.get()
        now = time.time()
        # Check if temp password is set, not expired, and matches
        if (PasswordPrompt.temp_password and
            now < PasswordPrompt.temp_password_expiry and
            entered == PasswordPrompt.temp_password):

            self.action()
            self.password_window.destroy()

            msg.CTkMessagebox(title="Success", message=f"USB Storage Devices {self.log_message.split()[0]}", icon="check", option_1="OK")
            # Invalidate the temp password after use
            PasswordPrompt.temp_password = None
            PasswordPrompt.temp_password_expiry = 0
            PasswordPrompt.last_request_time = 0
            return
        
        self.failed_attempts[0] += 1
        USBLogger.log_action(f'Incorrect OTP attempt to {self.log_message.lower()}, Attempt - {self.failed_attempts[0]}')

        msg.CTkMessagebox(title="Error", message="Incorrect or expired OTP.", icon="cancel", option_1="OK")

        self.password_entry.delete(0, ctk.END)

        # After 3 failed attempts → capture intruder images
        if self.failed_attempts[0] >= 3:
            USBLogger.capture_failed_attempt_images(reason="usb", webcam_enabled=self.webcam_enabled)
            self.failed_attempts[0] = 0  # reset after capture

class USBApp:

    def __init__(self):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        self.root = ctk.CTk()
       
        self.root.geometry("350x200")
        self.root.title("USB Security App")
        self.register_window = None
        self.login_window = None
        
        self.webcam_enabled = False

        self.setup_ui()

        # Start camera permission check AFTER UI shows
        self.root.after(500, self.check_camera_async)  

        self.root.mainloop()

    def check_webcam(self):

        cam = cv2.VideoCapture(0, cv2.CAP_DSHOW)

        if not cam.isOpened():
            USBLogger.log_action("Webcam not available — intruder detection disabled.")
            msg.CTkMessagebox(
                title="Webcam Disabled",
                message="No camera detected or access denied.\nIntruder detection will be disabled.",
                icon="warning",
                option_1="OK"
            )
            return

        ret, frame = cam.read()
        cam.release()

        if not ret:
            USBLogger.log_action("Webcam access failed — intruder detection disabled.")
            msg.CTkMessagebox(
                title="Webcam Access Failed",
                message="Unable to read from the camera.\nIntruder detection will be disabled.",
                icon="warning",
                option_1="OK"
            )
            return
        self.webcam_enabled = True
        USBLogger.log_action("Webcam available — intruder detection enabled.")

    def setup_ui(self):
        # Remove all widgets if re-calling this method
        for widget in self.root.winfo_children():
            widget.destroy()

        title_label = ctk.CTkLabel(master=self.root, text="USB Physical Security", font=ctk.CTkFont("Arial", 28, "bold"), text_color="#2E86C1")
        title_label.pack(pady=40)

        button_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        button_frame.pack()

        if UserManager.is_registered():
            # Only show Login button if user is registered
            self.login_btn = ctk.CTkButton(button_frame, text="Login", width=100, command=self.launch_login)
            self.login_btn.pack(side="left", padx=20)
        else:
            # Only show Register button if no user is registered
            self.register_btn = ctk.CTkButton(button_frame, text="Register", width=100, command=self.launch_register)
            self.register_btn.pack(side="left", padx=20)

    def check_camera_async(self):
        """Check camera without blocking the UI"""
        def run():
            try:
                cam = cv2.VideoCapture(0, cv2.CAP_DSHOW)  # Faster on Windows
                if not cam.isOpened():
                    self.show_camera_error(
                        "Camera Permission Required",
                        "This app needs access to your webcam for security features.\n\n"
                        "Please allow camera access and restart the app."
                    )
                    return

                ret, _ = cam.read()
                cam.release()

                if not ret:
                    self.show_camera_error("Camera Error","Unable to access the webcam. Please check your camera permissions.")

            except Exception as e:
                self.show_camera_error("Camera Error", f"Unexpected error: {e}")

        threading.Thread(target=run, daemon=True).start()

    def show_camera_error(self, title, message):
        """Show messagebox from UI thread"""
        self.root.after(0, lambda: msg.CTkMessagebox(title=title, message=message, icon="cancel", option_1="OK"))

    def launch_login(self):
        if self.login_window is not None and self.login_window.winfo_exists():
            self.login_window.focus()
            return
        self.login_btn.configure(state="disabled")
        self.login_window = LoginWindow(self.root, self.open_app)
        # Add a protocol handler to re-enable the button when closed
        self.login_window.login_window.protocol("WM_DELETE_WINDOW", self.on_login_close)

    def on_login_close(self):
        if self.login_window is not None:
            self.login_window.login_window.destroy()
            self.login_window = None
        self.setup_ui()

    def launch_register(self):
        if self.register_window is not None and self.register_window.winfo_exists():
            self.register_window.focus()
            return
        self.register_btn.configure(state="disabled")

        def on_register_close():
            self.register_window = None
            self.setup_ui()
            self.launch_login()

        self.register_window = RegisterWindow()
        self.register_window.protocol("WM_DELETE_WINDOW", lambda: [self.register_window.destroy(), on_register_close()])

        # Patch register_user to call on_register_close after success
        orig_register_user = self.register_window.register_user

        def patched_register_user():
            orig_register_user()
            if UserManager.is_registered():
                self.register_window.destroy()
                on_register_close()

        self.register_window.register_user = patched_register_user
        # Patch the Register button to use the patched method
        for widget in self.register_window.winfo_children():
            if isinstance(widget, ctk.CTkButton) and widget.cget("text") == "Register":
                widget.configure(command=self.register_window.register_user)

    def open_app(self):
        self.root.withdraw()
        MainAppWindow(self.root, webcam_enabled= self.webcam_enabled)

# --- App Entry ---
if __name__ == "__main__":
    USBApp()

