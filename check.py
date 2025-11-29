import os
import time
import smtplib
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
from email.message import EmailMessage
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from cryptography.fernet import Fernet
import threading

# -----------------------------
# CONFIGURATION
# -----------------------------
ADMIN_EMAIL = "eshwaran0227@gmail.com"  # REPLACE WITH YOUR EMAIL
EMAIL_PASSWORD = "yrwe apmm dyvb rukr"  # REPLACE WITH YOUR APP PASSWORD
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

# Suspicious File Extensions used by common ransomware
SUSPICIOUS_EXTENSIONS = ['.locked', '.encrypted', '.ransomed', '.payup', '.bitcoin', '.data', '.enc']

# -----------------------------
# Event Handler
# -----------------------------
class RansomwareDetectionHandler(FileSystemEventHandler):
    def __init__(self, log_callback, send_email_callback, decrypt_callback):
        self.log_callback = log_callback
        self.send_email_callback = send_email_callback
        self.decrypt_callback = decrypt_callback

    def on_modified(self, event):
        if not event.is_directory:
            self._check_file(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self._check_file(event.src_path)

    def _check_file(self, file_path):
        _, extension = os.path.splitext(file_path)
        
        # 1. Check for suspicious extensions
        if extension.lower() in SUSPICIOUS_EXTENSIONS:
            self.log_callback(f"[WARNING] Suspicious file detected: {file_path}")
            self.send_email_callback(file_path)
            self.decrypt_callback(os.path.dirname(file_path)) 
            return

        # 2. Check for ransom notes
        ransom_notes = ["README.txt", "DECRYPT_FILES.txt", "HOW_TO_RECOVER.txt"]
        if any(note.lower() in os.path.basename(file_path).lower() for note in ransom_notes):
            self.log_callback(f"[ALERT] Possible ransom note detected: {file_path}")
            self.send_email_callback(file_path)
            self.decrypt_callback(os.path.dirname(file_path))


# -----------------------------
# Main App
# -----------------------------
class RansomwareMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ Ransomware Detection System")
        try:
            self.root.state("zoomed")
        except:
            self.root.attributes('-fullscreen', True)
            
        self.root.configure(bg="#1e1e2e")
        
        # This list will hold the paths (either one folder or multiple files)
        self.active_monitor_paths = [] 

        # Title
        self.title_label = tk.Label(
            root, text="🛡️ Ransomware Detection & Protection",
            font=("Segoe UI", 24, "bold"), fg="#00ffff", bg="#1e1e2e"
        )
        self.title_label.pack(pady=15)
        self.pulse_title(0)

        main_frame = tk.Frame(root, bg="#1e1e2e")
        main_frame.pack(fill="both", expand=True, padx=20, pady=10)

        # --- Monitoring Scope Frame (Unified) ---
        monitor_frame = tk.LabelFrame(main_frame, text="📁 Monitoring Target",
                                     bg="#25253a", fg="#00ffff", font=("Segoe UI", 12, "bold"))
        monitor_frame.pack(fill="x", pady=10)

        tk.Label(monitor_frame, text="Selected Target:", bg="#25253a", fg="white", font=("Segoe UI", 11)).grid(row=0, column=0, padx=10, pady=10, sticky="e")
        
        # Entry to show selection
        self.target_entry = tk.Entry(monitor_frame, width=60, font=("Segoe UI", 11))
        self.target_entry.grid(row=0, column=1, padx=10, pady=10)
        
        # Single "Select Target" Button with Dropdown
        self.select_btn = tk.Button(monitor_frame, text="Select Target ▾", command=self.show_browse_menu,
                                       bg="#0078d7", fg="white", font=("Segoe UI", 10, "bold"), relief="flat", cursor="hand2")
        self.select_btn.grid(row=0, column=2, padx=10, pady=10)

        # Dropdown Menu for the button
        self.browse_menu = tk.Menu(root, tearoff=0, bg="#2d2d44", fg="white", activebackground="#0078d7")
        self.browse_menu.add_command(label="📁 Monitor Entire Folder", command=self.browse_folder)
        self.browse_menu.add_command(label="📄 Monitor Specific Files", command=self.browse_files)

        # --- Email Config ---
        email_frame = tk.LabelFrame(main_frame, text="📧 Alert Email Configuration",
                                    bg="#25253a", fg="#00ffff", font=("Segoe UI", 12, "bold"))
        email_frame.pack(fill="x", pady=10)

        tk.Label(email_frame, text="Recipient Email:", bg="#25253a", fg="white", font=("Segoe UI", 11)).grid(row=0, column=0, padx=10, pady=10, sticky="e")
        self.email_entry = tk.Entry(email_frame, width=50, font=("Segoe UI", 11))
        self.email_entry.grid(row=0, column=1, padx=10, pady=10)

        # Test Email Button
        self.test_email_btn = tk.Button(email_frame, text="Test Email Now", command=lambda: self.send_alert_email("TEST_FILE_CHECK.txt"),
                                       bg="#ffaa00", fg="black", font=("Segoe UI", 10, "bold"))
        self.test_email_btn.grid(row=0, column=2, padx=10, pady=10)

        # Protection Checkbox
        self.protection_var = tk.BooleanVar()
        self.protection_checkbox = tk.Checkbutton(email_frame, text="Activate Auto Decrypt Protection",
                                                  variable=self.protection_var, bg="#25253a", fg="#00ff99",
                                                  selectcolor="#1e1e2e", font=("Segoe UI", 11, "bold"))
        self.protection_checkbox.grid(row=1, column=0, columnspan=3, pady=5)

        # Start Button
        self.start_button = tk.Button(main_frame, text="🚀 Start Monitoring", command=self.start_monitoring,
                                      bg="#00cc66", fg="black", font=("Segoe UI", 13, "bold"),
                                      activebackground="#00ff88", width=30, height=2, relief="flat", cursor="hand2")
        self.start_button.pack(pady=15)
        self.glossy_button_animation(self.start_button)

        # Logs
        log_frame = tk.LabelFrame(main_frame, text="📜 System Logs", bg="#25253a", fg="#00ffff", font=("Segoe UI", 12, "bold"))
        log_frame.pack(fill="both", expand=True, pady=10)

        self.output_text = scrolledtext.ScrolledText(log_frame, width=100, height=20, bg="#1e1e2e", fg="#00ff99",
                                                     insertbackground="white", font=("Consolas", 11))
        self.output_text.pack(padx=5, pady=5, fill="both", expand=True)

        self.observer = None

    # -----------------------------
    # UI Animations & Helpers
    # -----------------------------
    def pulse_title(self, val):
        color = f"#00{255 - val:02x}ff"
        self.title_label.config(fg=color)
        self.root.after(100, self.pulse_title, (val+10) % 255)

    def glossy_button_animation(self, btn):
        def pulse(alpha=0):
            try:
                r = int(0 + alpha//2)
                g = int(204 + alpha//3)
                b = int(102 + alpha//4)
                color = f"#{r:02x}{g:02x}{b:02x}"
                btn.config(bg=color)
                self.root.after(80, pulse, (alpha+15) % 255)
            except: pass
        pulse()

    def show_browse_menu(self):
        try:
            x = self.select_btn.winfo_rootx()
            y = self.select_btn.winfo_rooty() + self.select_btn.winfo_height()
            self.browse_menu.tk_popup(x, y)
        finally:
            self.browse_menu.grab_release()

    def log_message(self, message):
        self.output_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}\n")
        self.output_text.see(tk.END)

    # -----------------------------
    # Browsing Logic
    # -----------------------------
    def browse_folder(self):
        folder_selected = filedialog.askdirectory(title="Select Folder to Monitor")
        if folder_selected:
            self.active_monitor_paths = [folder_selected]
            self.target_entry.delete(0, tk.END)
            self.target_entry.insert(0, f"Folder: {folder_selected}")

    def browse_files(self):
        files = filedialog.askopenfilenames(title="Select Specific Files to Monitor", 
                                            filetypes=[("All Files", "*.*"), ("Images", "*.jpg *.png"), ("Documents", "*.pdf *.docx")])
        if files:
            self.active_monitor_paths = list(files)
            self.target_entry.delete(0, tk.END)
            file_names = [os.path.basename(f) for f in files]
            display_text = ", ".join(file_names) if len(files) < 4 else f"{len(files)} files selected"
            self.target_entry.insert(0, f"Files: {display_text}")

    # -----------------------------
    # Actions
    # -----------------------------
    def send_alert_email(self, suspect_file):
        threading.Thread(target=self._send_email_thread, args=(suspect_file,)).start()

    def _send_email_thread(self, suspect_file):
        recipient = self.email_entry.get().strip()
        if not recipient:
            self.root.after(0, lambda: self.log_message("[EMAIL ERROR] No Recipient Email Entered!"))
            return

        msg = EmailMessage()
        msg["Subject"] = "🚨 Ransomware Alert: Suspicious Activity Detected!"
        msg["From"] = ADMIN_EMAIL
        msg["To"] = recipient
        msg.set_content(f"⚠️ SECURITY ALERT \n\nA suspicious file modification was detected.\n\nFile: {suspect_file}\nTime: {time.ctime()}\n\nImmediate action recommended.")

        try:
            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(ADMIN_EMAIL, EMAIL_PASSWORD)
            server.send_message(msg)
            server.quit()
            self.root.after(0, lambda: self.log_message(f"[EMAIL SENT] Alert sent to {recipient}"))
        except smtplib.SMTPAuthenticationError:
            self.root.after(0, lambda: self.log_message("[EMAIL FAIL] Auth Error! Check App Password."))
        except Exception as e:
            self.root.after(0, lambda: self.log_message(f"[EMAIL FAIL] Error: {e}"))

    def decrypt_files(self, detection_dir):
        """ Decrypts files in the detected directory or file location """
        if not self.protection_var.get():
            return
            
        folder = detection_dir
        if not folder or not os.path.exists(folder): return

        # Try to find password file
        password_file = os.path.join(folder, "password.txt") # Check specific folder
        if not os.path.exists(password_file):
             # Try checking the first monitored path if available
            if self.active_monitor_paths and os.path.isdir(self.active_monitor_paths[0]):
                 password_file = os.path.join(self.active_monitor_paths[0], "password.txt")
        
        if not os.path.exists(password_file):
            self.log_message(f"[DECRYPT FAIL] No password.txt found in {folder}.")
            return

        try:
            with open(password_file, "r") as f:
                lines = f.readlines()
                for line in lines:
                    if "Key:" in line:
                        key = line.split("Key:")[1].strip()
                        break
                else:
                    self.log_message("[DECRYPT FAIL] Key not found in file.")
                    return
            
            cipher = Fernet(key.encode())
            
            # Decrypt files in that folder
            for root, _, files in os.walk(folder):
                for file in files:
                    if file.endswith(".enc"):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, "rb") as f: encrypted_data = f.read()
                            decrypted_data = cipher.decrypt(encrypted_data)
                            original_path = os.path.splitext(file_path)[0]
                            with open(original_path, "wb") as f: f.write(decrypted_data)
                            os.remove(file_path)
                            self.log_message(f"[AUTO-RECOVERY] Decrypted {file}")
                        except: pass
                            
            self.log_message(f"[SUCCESS] Auto-decryption finished.")

        except Exception as e:
            self.log_message(f"[DECRYPT ERROR] {e}")

    def start_monitoring(self):
        # Determine actual paths to watch
        paths_to_watch = set()

        if not self.active_monitor_paths:
            # Check if user manually typed a path
            manual_text = self.target_entry.get().strip()
            if os.path.isdir(manual_text):
                paths_to_watch.add(manual_text)
            else:
                messagebox.showerror("Error", "Please select a Target (Folder or Files) first.")
                return
        else:
            for p in self.active_monitor_paths:
                if os.path.isdir(p):
                    paths_to_watch.add(p)
                elif os.path.isfile(p):
                    paths_to_watch.add(os.path.dirname(p))

        self.log_message(f"🚀 SYSTEM ARMED. Monitoring {len(paths_to_watch)} active locations.")
        
        event_handler = RansomwareDetectionHandler(
            self.log_message, 
            self.send_alert_email, 
            self.decrypt_files
        )
        
        self.observer = Observer()
        for path in paths_to_watch:
            self.observer.schedule(event_handler, path, recursive=True)
            self.log_message(f"   ➤ Watching: {path}")
            
        self.observer.start()
        
        self.start_button.config(state=tk.DISABLED, text="Scanning Active...", bg="#ff4444")
        self.select_btn.config(state=tk.DISABLED)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = RansomwareMonitorApp(root)
    root.mainloop()