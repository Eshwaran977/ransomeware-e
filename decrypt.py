import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet

# -----------------------------
# Utility Functions
# -----------------------------
def load_key_from_file(key_path):
    """Reads the actual encryption key from the generated text file."""
    try:
        with open(key_path, "r") as f:
            lines = f.readlines()
            # Look for the line starting with "Key: "
            for line in lines:
                if line.startswith("Key: "):
                    return line.split("Key: ")[1].strip()
        return None
    except Exception:
        return None
import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet

# -----------------------------
# Utility Functions
# -----------------------------
def load_key_from_file(key_path):
    """Reads the actual encryption key from the generated text file."""
    try:
        with open(key_path, "r") as f:
            lines = f.readlines()
            # Look for the line starting with "Key: "
            for line in lines:
                if line.startswith("Key: "):
                    return line.split("Key: ")[1].strip()
        return None
    except Exception:
        return None

# -----------------------------
# Logic: Decryption
# -----------------------------
def get_decryption_key(folder):
    """Attempts to find the key file automatically, or asks user."""
    candidates = ["folder_password.txt", "files_password.txt", "password.txt"]
    for c in candidates:
        p = os.path.join(folder, c)
        if os.path.exists(p):
            return load_key_from_file(p)
    
    # Not found automatically, ask user
    messagebox.showwarning("Key Not Found", "Could not auto-detect password file.\nPlease select the 'password.txt' file containing the key.")
    key_file = filedialog.askopenfilename(title="Select Password/Key File", filetypes=[("Text Files", "*.txt")])
    if key_file:
        return load_key_from_file(key_file)
    return None

def decrypt_folder(folder):
    """Decrypts all .enc files in a folder."""
    key_str = get_decryption_key(folder)
    if not key_str: return

    try:
        cipher = Fernet(key_str.encode())
        count = 0
        for root, _, files in os.walk(folder):
            for file in files:
                if not file.endswith(".enc"): continue
                
                file_path = os.path.join(root, file)
                original_path = os.path.splitext(file_path)[0]
                
                try:
                    with open(file_path, "rb") as f: encrypted_data = f.read()
                    decrypted_data = cipher.decrypt(encrypted_data)
                    with open(original_path, "wb") as f: f.write(decrypted_data)
                    os.remove(file_path)
                    count += 1
                except Exception as e: print(f"Failed {file}: {e}")

        messagebox.showinfo("Decryption Complete", f"✅ Successfully decrypted {count} files.")
    except Exception as e:
        messagebox.showerror("Decryption Failed", f"Invalid Key or Corrupt Data.\n{e}")

def decrypt_files(file_paths):
    """Decrypts specific selected .enc files."""
    if not file_paths: return
    
    # Try to find key in the folder of the first file
    base_dir = os.path.dirname(file_paths[0])
    key_str = get_decryption_key(base_dir)
    if not key_str: return

    try:
        cipher = Fernet(key_str.encode())
        count = 0
        for file_path in file_paths:
            if not file_path.endswith(".enc"): continue
            
            original_path = os.path.splitext(file_path)[0]
            try:
                with open(file_path, "rb") as f: encrypted_data = f.read()
                decrypted_data = cipher.decrypt(encrypted_data)
                with open(original_path, "wb") as f: f.write(decrypted_data)
                os.remove(file_path)
                count += 1
            except Exception: pass

        messagebox.showinfo("Decryption Complete", f"✅ Successfully decrypted {count} files.")
    except Exception as e:
        messagebox.showerror("Decryption Failed", f"Invalid Key or Corrupt Data.\n{e}")

# -----------------------------
# Trigger Functions
# -----------------------------
def trigger_decrypt_folder():
    f = filedialog.askdirectory(title="Select Folder to Decrypt")
    if f: decrypt_folder(f)

def trigger_decrypt_files():
    f = filedialog.askopenfilenames(
        title="Select Encrypted Files", 
        filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")]
    )
    if f: decrypt_files(f)

def show_options_menu(root, btn):
    """Displays the dropdown menu under the button."""
    menu = tk.Menu(root, tearoff=0, bg="#2d2d44", fg="white", font=("Segoe UI", 11), activebackground="#0078d7")
    
    menu.add_command(label="📁  Decrypt Entire Folder", command=trigger_decrypt_folder)
    menu.add_separator()
    menu.add_command(label="📄  Decrypt Specific Files", command=trigger_decrypt_files)
    menu.add_command(label="🖼️  Decrypt Images", command=trigger_decrypt_files) # Reuses file logic, just a UX choice

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
    root.title("🔓 CyberLock: Decryptor")
    root.configure(bg="#121212")
    try:
        root.state('zoomed') # Windows
    except:
        root.attributes('-fullscreen', True) # Linux/Mac fallback
    
    # Styles
    btn_font = ("Segoe UI", 14, "bold")
    
    # Title
    tk.Label(root, text="CYBERLOCK DECRYPTOR", font=("Segoe UI", 30, "bold"), fg="#00ff88", bg="#121212").pack(pady=40)
    tk.Label(root, text="Select target to restore below", font=("Segoe UI", 12), fg="#888888", bg="#121212").pack(pady=(0,30))

    # Center Frame
    main_frame = tk.Frame(root, bg="#1e1e2e", padx=40, pady=40)
    main_frame.place(relx=0.5, rely=0.5, anchor="center")
    
    # Icon/Label
    tk.Label(main_frame, text="🔓", font=("Segoe UI", 40), fg="#00ff88", bg="#1e1e2e").pack(pady=(0, 20))

    # Single Unified Button
    select_btn = tk.Button(main_frame, text="Select Target to Decrypt ▾", 
                           command=lambda: show_options_menu(root, select_btn), 
                           bg="#00cc66", fg="black", font=btn_font, width=35, height=2, relief="flat", cursor="hand2")
    select_btn.pack(pady=15)

    # Hover effect
    select_btn.bind("<Enter>", lambda e: select_btn.config(bg="#00ff88"))
    select_btn.bind("<Leave>", lambda e: select_btn.config(bg="#00cc66"))

    # Footer
    tk.Label(root, text="Ensure the original 'password.txt' key file is in the same folder as your files.", 
             fg="#666666", bg="#121212", font=("Segoe UI", 10)).pack(side="bottom", pady=20)

    root.mainloop()

if __name__ == "__main__":
    setup_ui()
# -----------------------------
# Logic: Decryption
# -----------------------------
def get_decryption_key(folder):
    """Attempts to find the key file automatically, or asks user."""
    candidates = ["folder_password.txt", "files_password.txt"]
    for c in candidates:
        p = os.path.join(folder, c)
        if os.path.exists(p):
            return load_key_from_file(p)
    
    # Not found automatically, ask user
    messagebox.showwarning("Key Not Found", "Could not auto-detect password file.\nPlease select the 'password.txt' file containing the key.")
    key_file = filedialog.askopenfilename(title="Select Password/Key File", filetypes=[("Text Files", "*.txt")])
    if key_file:
        return load_key_from_file(key_file)
    return None

def decrypt_folder(folder):
    """Decrypts all .enc files in a folder."""
    key_str = get_decryption_key(folder)
    if not key_str: return

    try:
        cipher = Fernet(key_str.encode())
        count = 0
        for root, _, files in os.walk(folder):
            for file in files:
                if not file.endswith(".enc"): continue
                
                file_path = os.path.join(root, file)
                original_path = os.path.splitext(file_path)[0]
                
                try:
                    with open(file_path, "rb") as f: encrypted_data = f.read()
                    decrypted_data = cipher.decrypt(encrypted_data)
                    with open(original_path, "wb") as f: f.write(decrypted_data)
                    os.remove(file_path)
                    count += 1
                except Exception as e: print(f"Failed {file}: {e}")

        messagebox.showinfo("Decryption Complete", f"✅ Successfully decrypted {count} files.")
    except Exception as e:
        messagebox.showerror("Decryption Failed", f"Invalid Key or Corrupt Data.\n{e}")

def decrypt_files(file_paths):
    """Decrypts specific selected .enc files."""
    if not file_paths: return
    
    # Try to find key in the folder of the first file
    base_dir = os.path.dirname(file_paths[0])
    key_str = get_decryption_key(base_dir)
    if not key_str: return

    try:
        cipher = Fernet(key_str.encode())
        count = 0
        for file_path in file_paths:
            if not file_path.endswith(".enc"): continue
            
            original_path = os.path.splitext(file_path)[0]
            try:
                with open(file_path, "rb") as f: encrypted_data = f.read()
                decrypted_data = cipher.decrypt(encrypted_data)
                with open(original_path, "wb") as f: f.write(decrypted_data)
                os.remove(file_path)
                count += 1
            except Exception: pass

        messagebox.showinfo("Decryption Complete", f"✅ Successfully decrypted {count} files.")
    except Exception as e:
        messagebox.showerror("Decryption Failed", f"Invalid Key or Corrupt Data.\n{e}")

# -----------------------------
# Trigger Functions
# -----------------------------
def trigger_decrypt_folder():
    f = filedialog.askdirectory(title="Select Folder to Decrypt")
    if f: decrypt_folder(f)

def trigger_decrypt_files():
    f = filedialog.askopenfilenames(title="Select .enc Files to Decrypt", filetypes=[("Encrypted", "*.enc")])
    if f: decrypt_files(f)

# -----------------------------
# UI Setup
# -----------------------------
def setup_ui():
    root = tk.Tk()
    root.title("🔓 CyberLock: Decryptor")
    root.configure(bg="#121212")
    try:
        root.state('zoomed') # Windows
    except:
        root.attributes('-fullscreen', True) # Linux/Mac fallback
    
    # Styles
    btn_font = ("Segoe UI", 14, "bold")
    
    # Title
    tk.Label(root, text="CYBERLOCK DECRYPTOR", font=("Segoe UI", 30, "bold"), fg="#00ff88", bg="#121212").pack(pady=40)
    tk.Label(root, text="Select files or folders to restore below", font=("Segoe UI", 12), fg="#888888", bg="#121212").pack(pady=(0,30))

    # Center Frame
    main_frame = tk.Frame(root, bg="#1e1e2e", padx=40, pady=40)
    main_frame.place(relx=0.5, rely=0.5, anchor="center")
    
    # Icon/Label
    tk.Label(main_frame, text="🔓", font=("Segoe UI", 40), fg="#00ff88", bg="#1e1e2e").pack(pady=(0, 20))

    # Buttons
    tk.Button(main_frame, text="Decrypt Entire Folder", command=trigger_decrypt_folder, 
              bg="#00cc66", fg="black", font=btn_font, width=30, height=2).pack(pady=15)
              
    tk.Button(main_frame, text="Decrypt Specific Files", command=trigger_decrypt_files, 
              bg="#00aa55", fg="black", font=btn_font, width=30, height=2).pack(pady=15)

    # Footer
    tk.Label(root, text="Ensure the original 'password.txt' key file is in the same folder as your files.", 
             fg="#666666", bg="#121212", font=("Segoe UI", 10)).pack(side="bottom", pady=20)

    root.mainloop()

if __name__ == "__main__":
    setup_ui()