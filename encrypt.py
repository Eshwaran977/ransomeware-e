import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import random
import string

# -----------------------------
# Utility Functions
# -----------------------------
def generate_password(length=16):
    """Generates a secure random password."""
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

# -----------------------------
# Logic: Folder Encryption
# -----------------------------
def encrypt_folder(folder):
    """Encrypts all files in the selected folder."""
    password = generate_password()
    key = Fernet.generate_key()
    cipher = Fernet(key)
    password_file = os.path.join(folder, "folder_password.txt")

    try:
        with open(password_file, "w") as f:
            f.write(f"Password: {password}\n")
            f.write(f"Key: {key.decode()}\n")

        encrypted_count = 0
        failed_count = 0

        for root, _, files in os.walk(folder):
            for file in files:
                file_path = os.path.join(root, file)

                # Skip existing encrypted files and the password file
                if file.endswith(".enc") or "password.txt" in file:
                    continue

                try:
                    with open(file_path, "rb") as f:
                        data = f.read()

                    encrypted_data = cipher.encrypt(data)

                    with open(file_path + ".enc", "wb") as f:
                        f.write(encrypted_data)

                    os.remove(file_path)
                    encrypted_count += 1

                except Exception as e:
                    failed_count += 1
                    print(f"[ERROR] Failed to encrypt {file_path}: {e}")

        messagebox.showinfo(
            "Encryption Complete",
            f"✅ Encrypted {encrypted_count} file(s) in folder.\n"
            f"🔑 Key saved in: {password_file}"
        )

    except Exception as e:
        messagebox.showerror("Error", f"An error occurred:\n{e}")

# -----------------------------
# Logic: Specific File Encryption
# -----------------------------
def encrypt_specific_list(file_paths):
    """Encrypts a specific list of selected files (Images, Docs, etc)."""
    if not file_paths:
        return

    # Determine directory of the first file to save the key
    base_dir = os.path.dirname(file_paths[0])
    password = generate_password()
    key = Fernet.generate_key()
    cipher = Fernet(key)
    
    # Save key in the same folder as the files
    password_file = os.path.join(base_dir, "files_password.txt")

    try:
        with open(password_file, "w") as f:
            f.write(f"Password: {password}\n")
            f.write(f"Key: {key.decode()}\n")

        encrypted_count = 0
        failed_count = 0

        for file_path in file_paths:
            # Skip if already encrypted or is the key file
            if file_path.endswith(".enc") or file_path == password_file:
                continue

            try:
                with open(file_path, "rb") as f:
                    data = f.read()

                encrypted_data = cipher.encrypt(data)

                with open(file_path + ".enc", "wb") as f:
                    f.write(encrypted_data)

                os.remove(file_path)
                encrypted_count += 1

            except Exception as e:
                failed_count += 1
                print(f"[ERROR] Failed to encrypt {file_path}: {e}")

        messagebox.showinfo(
            "File Encryption Complete",
            f"✅ Encrypted {encrypted_count} specific file(s).\n"
            f"⚠️ Failed: {failed_count}\n\n"
            f"🔑 Key saved in:\n{password_file}"
        )

    except Exception as e:
        messagebox.showerror("Error", f"An error occurred:\n{e}")

# -----------------------------
# Trigger Functions
# -----------------------------
def select_folder():
    """Trigger for folder selection."""
    folder_selected = filedialog.askdirectory(title="Select Folder to Encrypt")
    if not folder_selected:
        return

    confirm = messagebox.askyesno(
        "Confirm Folder Encryption",
        "Are you sure you want to encrypt ALL files in this folder?"
    )
    if confirm:
        encrypt_folder(folder_selected)

def select_specific_files():
    """Trigger for specific file selection (Images, Docs, etc)."""
    files_selected = filedialog.askopenfilenames(
        title="Select Files to Encrypt",
        filetypes=[
            ("All Files", "*.*"),
            ("Images", "*.png;*.jpg;*.jpeg;*.bmp;*.gif"),
            ("Documents", "*.txt;*.pdf;*.docx;*.xlsx"),
            ("Videos", "*.mp4;*.mkv;*.avi")
        ]
    )
    
    if not files_selected:
        return

    confirm = messagebox.askyesno(
        "Confirm File Encryption",
        f"Are you sure you want to encrypt {len(files_selected)} specific file(s)?"
    )
    if confirm:
        encrypt_specific_list(files_selected)

def show_options_menu(root, btn):
    """Displays the dropdown menu under the button."""
    menu = tk.Menu(root, tearoff=0, bg="#2d2d44", fg="white", font=("Segoe UI", 11), activebackground="#ff5555")
    
    menu.add_command(label="📁  Encrypt Entire Folder", command=select_folder)
    menu.add_separator()
    menu.add_command(label="📄  Encrypt Specific Files", command=select_specific_files)
    menu.add_command(label="🖼️  Encrypt Images", command=select_specific_files) 

    # Calculate position
    try:
        x = btn.winfo_rootx()
        y = btn.winfo_rooty() + btn.winfo_height()
        menu.tk_popup(x, y)
    finally:
        menu.grab_release()

# -----------------------------
# UI Setup
# -----------------------------
def setup_ui():
    root = tk.Tk()
    root.title("🔒 Secure File & Image Encryption")
    root.configure(bg="#1e1e2e")
    root.state('zoomed') 
    root.attributes('-alpha', 0.0)

    # Fade-in animation
    def fade_in(alpha=0.0):
        if alpha < 1.0:
            alpha += 0.05
            root.attributes('-alpha', alpha)
            root.after(30, fade_in, alpha)
    fade_in()

    # Main center frame
    main_frame = tk.Frame(root, bg="#1e1e2e")
    main_frame.place(relx=0.5, rely=0.5, anchor="center")

    # Title
    title_label = tk.Label(
        main_frame,
        text="Encryption Utility",
        font=("Segoe UI", 32, "bold"),
        fg="#ff5555",
        bg="#1e1e2e"
    )
    title_label.pack(pady=(0, 10))

    # Description
    desc_label = tk.Label(
        main_frame,
        text="Select an entire folder or specific images/files to encrypt.",
        font=("Segoe UI", 14),
        fg="#cccccc",
        bg="#1e1e2e"
    )
    desc_label.pack(pady=(0, 40))

    # --- Single Unified Button ---
    select_btn = tk.Button(
        main_frame,
        text="Select Target to Encrypt ▾",
        command=lambda: show_options_menu(root, select_btn),
        bg="#ff5555",
        fg="white",
        activebackground="#ff7777",
        activeforeground="white",
        font=("Segoe UI", 14, "bold"),
        width=35,
        height=2,
        relief="flat",
        cursor="hand2"
    )
    select_btn.pack(pady=10)

    # Hover Effects
    def on_enter(e):
        select_btn.config(bg="#ff7777")

    def on_leave(e):
        select_btn.config(bg="#ff5555")

    select_btn.bind("<Enter>", on_enter)
    select_btn.bind("<Leave>", on_leave)

    # Animations (Pulse Title)
    def pulse_title(bright=0):
        color = f"#ff{int(85 + bright//3):02x}{int(85 + bright//5):02x}"
        title_label.config(fg=color)
        root.after(100, pulse_title, (bright + 20) % 255)
    pulse_title()

    # Footer
    footer = tk.Label(
        root,
        text="⚠️ Save the generated password key file! Without it, data is lost forever.",
        font=("Segoe UI", 11),
        fg="#aaaaaa",
        bg="#1e1e2e"
    )
    footer.pack(side="bottom", pady=20)

    root.mainloop()

if __name__ == "__main__":
    setup_ui()