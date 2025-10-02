import os
import zipfile
import shutil
import sqlite3
import sys
from datetime import datetime
from tkinter import *
from tkinter import filedialog, messagebox, ttk
from cryptography.fernet import Fernet
from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive
from mega import Mega
import importlib.metadata
import threading
import time
from tenacity import retry, stop_after_attempt, wait_fixed, retry_if_exception_type
import requests
from PIL import Image, ImageTk

# ========================
# Configuration
# ========================

import os

# Use:
MEGA_EMAIL = os.getenv('MEGA_EMAIL')
MEGA_PASSWORD = os.getenv('MEGA_PASSWORD')
PCLOUD_EMAIL = os.getenv('PCLOUD_EMAIL')
PCLOUD_PASSWORD = os.getenv('PCLOUD_PASSWORD')

# Add a check:
if not all([MEGA_EMAIL, MEGA_PASSWORD, PCLOUD_EMAIL, PCLOUD_PASSWORD]):
    raise ValueError("Please set MEGA_EMAIL, MEGA_PASSWORD, PCLOUD_EMAIL, and PCLOUD_PASSWORD as environment variables.")
# ========================
# Dependency Check
# ========================
required = {'cryptography', 'pydrive2', 'mega.py', 'tenacity', 'requests', 'pillow'}
installed = {dist.metadata['Name'].lower() for dist in importlib.metadata.distributions()}
missing = required - installed
if missing:
    messagebox.showerror("Dependency Error", f"Missing dependencies: {missing}. Install with 'pip install {' '.join(required)}' and restart.")
    sys.exit(1)

# ========================
# Crypto Key Handling
# ========================
def load_or_generate_key():
    key_file = "key.key"
    if not os.path.exists(key_file):
        key = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(key)
    with open(key_file, "rb") as f:
        key = f.read()
    return key

# ========================
# Encryption / Decryption
# ========================
def encrypt_file(file_path, fernet):
    try:
        with open(file_path, 'rb') as file:
            original = file.read()
        encrypted = fernet.encrypt(original)
        with open(file_path, 'wb') as encrypted_file:
            encrypted_file.write(encrypted)
    except Exception as e:
        raise Exception(f"Encryption failed: {str(e)}")

def decrypt_file(file_path, fernet, output_path):
    try:
        with open(file_path, 'rb') as file:
            encrypted = file.read()
        decrypted = fernet.decrypt(encrypted)
        with open(output_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted)
    except Exception as e:
        raise Exception(f"Decryption failed: {str(e)}")

# ========================
# Zipping / Unzipping
# ========================
def zip_folder(folder_path, output_path):
    try:
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, _, files in os.walk(folder_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, folder_path)
                    zipf.write(file_path, arcname)
    except Exception as e:
        raise Exception(f"Zipping failed: {str(e)}")

def unzip_folder(zip_path, extract_path):
    try:
        with zipfile.ZipFile(zip_path, 'r') as zipf:
            zipf.extractall(extract_path)
    except Exception as e:
        raise Exception(f"Unzipping failed: {str(e)}")

# ========================
# Cloud Upload Functions
# ========================
def authenticate_drive():
    if not os.path.exists("client_secrets.json"):
        messagebox.showerror("Authentication Error", "client_secrets.json not found! Please download it from Google Cloud Console.")
        sys.exit(1)
    gauth = GoogleAuth()
    gauth.LocalWebserverAuth()
    return GoogleDrive(gauth)

def upload_to_drive(filepath, status_callback=None):
    try:
        drive = authenticate_drive()
        file_drive = drive.CreateFile({'title': os.path.basename(filepath)})
        file_drive.SetContentFile(filepath)
        file_drive.Upload()
        if status_callback:
            status_callback("Uploaded to Google Drive")
        return "Uploaded to Google Drive"
    except Exception as e:
        error_msg = f"Drive Upload Failed: {str(e)}"
        if status_callback:
            status_callback(error_msg)
        return error_msg

@retry(stop=stop_after_attempt(3), wait=wait_fixed(5), retry=retry_if_exception_type(Exception))
def upload_to_mega(filepath, status_callback=None, progress_callback=None):
    try:
        mega = Mega()
        m = mega.login(MEGA_EMAIL, MEGA_PASSWORD)
        with open(filepath, 'rb') as f:
            file_size = os.path.getsize(filepath)
            if status_callback:
                status_callback(f"Starting Mega upload for {os.path.basename(filepath)} ({file_size / (1024*1024):.2f} MB)...")
            m.upload(filepath)
            if progress_callback:
                for i in range(1, 101):
                    time.sleep(0.1)
                    progress_callback(i)
            if status_callback:
                status_callback("Uploaded to Mega")
            return "Uploaded to Mega"
    except Exception as e:
        error_msg = f"Mega Upload Failed: {str(e)}"
        if status_callback:
            status_callback(error_msg)
        return error_msg

@retry(stop=stop_after_attempt(3), wait=wait_fixed(5), retry=retry_if_exception_type(Exception))
def upload_to_pcloud(filepath, status_callback=None, progress_callback=None):
    try:
        auth_url = f"https://api.pcloud.com/login?getauth=1&logout=1&username={PCLOUD_EMAIL}&password={PCLOUD_PASSWORD}"
        auth_res = requests.get(auth_url).json()
        if 'auth' not in auth_res:
            error_msg = f"pCloud Auth Failed: {auth_res.get('error', 'Unknown Error')}"
            if status_callback:
                status_callback(error_msg)
            return error_msg
        auth_token = auth_res['auth']
        upload_url = f"https://api.pcloud.com/uploadfile?auth={auth_token}&folderid=0&filename={os.path.basename(filepath)}"
        with open(filepath, 'rb') as f:
            file_size = os.path.getsize(filepath)
            if status_callback:
                status_callback(f"Starting pCloud upload for {os.path.basename(filepath)} ({file_size / (1024*1024):.2f} MB)...")
            upload_res = requests.post(upload_url, files={'file': f}).json()
            if progress_callback:
                for i in range(1, 101):
                    time.sleep(0.1)
                    progress_callback(i)
            if upload_res.get('result') != 0:
                error_msg = f"pCloud Upload Failed: {upload_res.get('error', 'Unknown')}"
                if status_callback:
                    status_callback(error_msg)
                return error_msg
            if status_callback:
                status_callback("Uploaded to pCloud")
            return "Uploaded to pCloud"
    except Exception as e:
        error_msg = f"pCloud Upload Error: {str(e)}"
        if status_callback:
            status_callback(error_msg)
        return error_msg

# ========================
# Database Logging
# ========================
def init_db():
    conn = sqlite3.connect("backup_log.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS logs 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, time TEXT, cloud TEXT)''')
    conn.commit()
    conn.close()

def log_backup(filename, cloud_status):
    conn = sqlite3.connect("backup_log.db")
    c = conn.cursor()
    c.execute("INSERT INTO logs (filename, time, cloud) VALUES (?, ?, ?)", 
              (filename, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), cloud_status))
    conn.commit()
    conn.close()

def get_logs():
    conn = sqlite3.connect("backup_log.db")
    c = conn.cursor()
    c.execute("SELECT * FROM logs")
    data = c.fetchall()
    conn.close()
    return data

def clear_logs():
    conn = sqlite3.connect("backup_log.db")
    c = conn.cursor()
    c.execute("DELETE FROM logs")
    conn.commit()
    conn.close()

# ========================
# Tkinter Application
# ========================
class BackupApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Backup Tool")
        self.root.geometry("600x650")
        self.root.configure(bg="#f0f0f0")
        self.root.resizable(True, True)
        self.upload_cancelled = False

        # Apply modern theme
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TButton", padding=6, font=("Arial", 10), background="#4CAF50", foreground="white")
        style.configure("TCheckbutton", font=("Arial", 10))
        style.configure("TProgressbar", thickness=20)

        self.key = load_or_generate_key()
        self.fernet = Fernet(self.key)
        self.file_path = ""

        # Load icons (ensure these files exist or remove icon code)
        try:
            self.backup_icon = ImageTk.PhotoImage(Image.open("backup.png").resize((20, 20)))
            self.restore_icon = ImageTk.PhotoImage(Image.open("restore.png").resize((20, 20)))
            self.logs_icon = ImageTk.PhotoImage(Image.open("logs.png").resize((20, 20)))
            self.clear_icon = ImageTk.PhotoImage(Image.open("clear.png").resize((20, 20)))
        except:
            self.backup_icon = self.restore_icon = self.logs_icon = self.clear_icon = None

        # Main container
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.grid(row=0, column=0, sticky="nsew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        # Title
        ttk.Label(main_frame, text="Secure Backup Tool", font=("Arial", 18, "bold")).grid(row=0, column=0, columnspan=2, pady=10)

        # Backup Frame
        backup_frame = ttk.LabelFrame(main_frame, text="Backup Options", padding=10)
        backup_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=5)
        
        ttk.Button(backup_frame, text="Select Folder", command=self.select_folder, 
                  image=self.backup_icon, compound="left").grid(row=0, column=0, sticky="ew", padx=5)
        self.folder_label = ttk.Label(backup_frame, text="No folder selected", font=("Arial", 10))
        self.folder_label.grid(row=0, column=1, sticky="w", padx=5)

        # Cloud Options
        cloud_frame = ttk.LabelFrame(main_frame, text="Cloud Storage", padding=10)
        cloud_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=5)
        
        self.cloud_var = IntVar()
        self.mega_var = IntVar()
        self.pcloud_var = IntVar()
        
        ttk.Checkbutton(cloud_frame, text="Google Drive", variable=self.cloud_var).grid(row=0, column=0, sticky="w", padx=5)
        ttk.Checkbutton(cloud_frame, text="Mega.nz", variable=self.mega_var).grid(row=1, column=0, sticky="w", padx=5)
        ttk.Checkbutton(cloud_frame, text="pCloud", variable=self.pcloud_var).grid(row=2, column=0, sticky="w", padx=5)

        # Action Buttons
        action_frame = ttk.Frame(main_frame)
        action_frame.grid(row=3, column=0, columnspan=2, pady=10)
        
        ttk.Button(action_frame, text="Backup Now", command=self.backup_now, 
                  image=self.backup_icon, compound="left").grid(row=0, column=0, padx=5)
        ttk.Button(action_frame, text="Restore Backup", command=self.select_restore_file, 
                  image=self.restore_icon, compound="left").grid(row=0, column=1, padx=5)
        ttk.Button(action_frame, text="View Logs", command=self.show_logs, 
                  image=self.logs_icon, compound="left").grid(row=0, column=2, padx=5)
        self.cancel_button = ttk.Button(action_frame, text="Cancel Upload", command=self.cancel_upload, state="disabled")
        self.cancel_button.grid(row=0, column=3, padx=5)

        # Status and Progress
        status_frame = ttk.LabelFrame(main_frame, text="Status", padding=10)
        status_frame.grid(row=4, column=0, columnspan=2, sticky="ew", pady=5)
        
        self.status = ttk.Label(status_frame, text="Ready", font=("Arial", 10))
        self.status.grid(row=0, column=0, sticky="w")
        self.progress_label = ttk.Label(status_frame, text="Progress: 0%", font=("Arial", 10))
        self.progress_label.grid(row=1, column=0, sticky="w", pady=5)
        self.progress_bar = ttk.Progressbar(status_frame, orient="horizontal", length=400, mode="determinate")
        self.progress_bar.grid(row=2, column=0, sticky="ew", pady=5)

        # Status Bar
        self.status_bar = ttk.Label(main_frame, text="Idle", font=("Arial", 8), relief="sunken", anchor="w")
        self.status_bar.grid(row=5, column=0, columnspan=2, sticky="ew", pady=5)

        # Tooltips
        self.create_tooltip(backup_frame, "Select a folder to back up")
        self.create_tooltip(action_frame, "Start the backup process")
        self.create_tooltip(cloud_frame, "Select cloud storage options")

    def create_tooltip(self, widget, text):
        def enter(event):
            x, y, _, _ = widget.bbox("insert")
            x += widget.winfo_rootx() + 25
            y += widget.winfo_rooty() + 20
            self.tooltip = Toplevel(widget)
            self.tooltip.wm_overrideredirect(True)
            self.tooltip.wm_geometry(f"+{x}+{y}")
            label = Label(self.tooltip, text=text, background="yellow", relief="solid", borderwidth=1)
            label.pack()
        def leave(event):
            if hasattr(self, 'tooltip'):
                self.tooltip.destroy()
        widget.bind("<Enter>", enter)
        widget.bind("<Leave>", leave)

    def select_folder(self):
        self.file_path = filedialog.askdirectory()
        if self.file_path:
            self.folder_label.config(text=f"Selected: {os.path.basename(self.file_path)}")
            self.status_bar.config(text=f"Selected folder: {self.file_path}")
        else:
            self.folder_label.config(text="No folder selected")
            self.status_bar.config(text="No folder selected")

    def select_restore_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("ZIP files", "*.zip")])
        if file_path:
            self.restore_backup(file_path)
        else:
            self.status.config(text="No file selected")
            self.status_bar.config(text="No restore file selected")

    def cancel_upload(self):
        self.upload_cancelled = True
        self.cancel_button.config(state="disabled")
        self.status.config(text="Upload cancelled")
        self.status_bar.config(text="Upload cancelled by user")

    def update_progress(self, percent):
        self.progress_bar["value"] = percent
        self.progress_label.config(text=f"Progress: {percent}%")
        self.root.update()

    def backup_now(self):
        if not self.file_path:
            messagebox.showwarning("Warning", "Please select a folder first!")
            return

        self.upload_cancelled = False
        self.cancel_button.config(state="normal")
        try:
            backup_dir = "backups"
            os.makedirs(backup_dir, exist_ok=True)
            zip_name = os.path.join(backup_dir, f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip")

            self.status.config(text="Creating ZIP file...")
            self.progress_bar["value"] = 0
            self.progress_label.config(text="Progress: 0%")
            self.status_bar.config(text=f"Zipping {os.path.basename(self.file_path)}...")
            self.root.update()
            zip_folder(self.file_path, zip_name)

            self.status.config(text="Encrypting backup...")
            self.status_bar.config(text="Encrypting backup...")
            self.root.update()
            encrypt_file(zip_name, self.fernet)

            cloud_status = "Local only"
            file_size = os.path.getsize(zip_name) / (1024 * 1024)  # MB

            if self.cloud_var.get() and not self.upload_cancelled:
                self.status.config(text="Uploading to Google Drive...")
                self.status_bar.config(text=f"Uploading to Google Drive ({file_size:.2f} MB)...")
                self.root.update()
                drive_status = upload_to_drive(
                    zip_name,
                    status_callback=lambda msg: self.root.after(0, self.status.config, {'text': msg})
                )
                cloud_status += f", {drive_status}"
                if "Failed" in drive_status:
                    self.root.after(0, messagebox.showerror, "Drive Error", drive_status)

            if self.mega_var.get() and not self.upload_cancelled:
                self.status.config(text="Starting Mega upload...")
                self.progress_bar["value"] = 0
                self.progress_label.config(text="Progress: 0%")
                self.status_bar.config(text=f"Uploading to Mega.nz ({file_size:.2f} MB)...")
                self.root.update()
                def mega_upload_thread():
                    if self.upload_cancelled:
                        self.root.after(0, self.status.config, {'text': "Mega upload cancelled"})
                        return
                    result = upload_to_mega(
                        zip_name,
                        status_callback=lambda msg: self.root.after(0, self.status.config, {'text': msg}),
                        progress_callback=lambda percent: self.root.after(0, self.update_progress, percent)
                    )
                    if "Failed" in result:
                        self.root.after(0, messagebox.showerror, "Mega.nz Error", result)
                    self.root.after(0, self.status.config, {'text': f"Backup Done! {cloud_status + ', ' + result}"})
                    self.root.after(0, self.status_bar.config, {'text': f"Backup completed: {cloud_status + ', ' + result}"})
                    log_backup(zip_name, cloud_status + f", {result}")
                    self.root.after(0, self.cancel_button.config, {'state': 'disabled'})

                threading.Thread(target=mega_upload_thread, daemon=True).start()
                time.sleep(1)
                while threading.active_count() > 1 and not self.upload_cancelled:
                    self.root.update()
                    time.sleep(0.1)
            else:
                log_backup(zip_name, cloud_status)
                self.status.config(text=f"Backup Done! {cloud_status}")
                self.status_bar.config(text=f"Backup completed: {cloud_status}")
                self.progress_bar["value"] = 0
                self.progress_label.config(text="Progress: 0%")
                self.cancel_button.config(state="disabled")

            if self.pcloud_var.get() and not self.upload_cancelled:
                self.status.config(text="Starting pCloud upload...")
                self.progress_bar["value"] = 0
                self.progress_label.config(text="Progress: 0%")
                self.status_bar.config(text=f"Uploading to pCloud ({file_size:.2f} MB)...")
                self.root.update()
                def pcloud_upload_thread():
                    if self.upload_cancelled:
                        self.root.after(0, self.status.config, {'text': "pCloud upload cancelled"})
                        return
                    result = upload_to_pcloud(
                        zip_name,
                        status_callback=lambda msg: self.root.after(0, self.status.config, {'text': msg}),
                        progress_callback=lambda percent: self.root.after(0, self.update_progress, percent)
                    )
                    if "Failed" in result or "Error" in result:
                        self.root.after(0, messagebox.showerror, "pCloud Error", result)
                    self.root.after(0, self.status.config, {'text': f"Backup Done! {cloud_status + ', ' + result}"})
                    self.root.after(0, self.status_bar.config, {'text': f"Backup completed: {cloud_status + ', ' + result}"})
                    log_backup(zip_name, cloud_status + f", {result}")
                    self.root.after(0, self.cancel_button.config, {'state': 'disabled'})

                threading.Thread(target=pcloud_upload_thread, daemon=True).start()
                time.sleep(1)
                while threading.active_count() > 1 and not self.upload_cancelled:
                    self.root.update()
                    time.sleep(0.1)
            else:
                log_backup(zip_name, cloud_status)
                self.status.config(text=f"Backup Done! {cloud_status}")
                self.status_bar.config(text=f"Backup completed: {cloud_status}")
                self.progress_bar["value"] = 0
                self.progress_label.config(text="Progress: 0%")
                self.cancel_button.config(state="disabled")

        except Exception as e:
            self.status.config(text="Backup failed")
            self.status_bar.config(text=f"Backup failed: {str(e)}")
            self.progress_bar["value"] = 0
            self.progress_label.config(text="Progress: 0%")
            self.cancel_button.config(state="disabled")
            messagebox.showerror("Error", f"Backup failed: {str(e)}")

    def restore_backup(self, zip_path):
        try:
            extract_dir = filedialog.askdirectory(title="Select folder to restore files")
            if not extract_dir:
                self.status.config(text="No restore folder selected")
                self.status_bar.config(text="No restore folder selected")
                return

            temp_dir = "temp_decrypt"
            os.makedirs(temp_dir, exist_ok=True)
            decrypted_zip = os.path.join(temp_dir, "decrypted.zip")

            self.status.config(text="Decrypting backup...")
            self.status_bar.config(text="Decrypting backup...")
            self.progress_bar["value"] = 0
            self.progress_label.config(text="Progress: 0%")
            self.root.update()
            decrypt_file(zip_path, self.fernet, decrypted_zip)

            self.status.config(text="Extracting files...")
            self.status_bar.config(text="Extracting files...")
            self.root.update()
            unzip_folder(decrypted_zip, extract_dir)

            shutil.rmtree(temp_dir, ignore_errors=True)
            self.status.config(text="Restore completed!")
            self.status_bar.config(text="Restore completed successfully")
            self.progress_bar["value"] = 0
            self.progress_label.config(text="Progress: 0%")
            messagebox.showinfo("Success", "Files restored successfully!")
        except Exception as e:
            self.status.config(text="Restore failed")
            self.status_bar.config(text=f"Restore failed: {str(e)}")
            self.progress_bar["value"] = 0
            self.progress_label.config(text="Progress: 0%")
            messagebox.showerror("Error", f"Restore failed: {str(e)}")
            shutil.rmtree("temp_decrypt", ignore_errors=True)

    def show_logs(self):
        logs = get_logs()
        log_win = Toplevel(self.root)
        log_win.title("Backup Logs")
        log_win.geometry("700x400")
        log_win.configure(bg="#f0f0f0")

        log_frame = ttk.Frame(log_win, padding=10)
        log_frame.pack(fill="both", expand=True)

        # Log display
        log_text = Text(log_frame, height=15, width=80, font=("Arial", 10))
        log_text.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=log_text.yview)
        scrollbar.pack(side="right", fill="y")
        log_text.config(yscrollcommand=scrollbar.set)

        for log in logs:
            log_text.insert("end", f"ID: {log[0]} | File: {log[1]} | Time: {log[2]} | Cloud: {log[3]}\n")
        log_text.config(state="disabled")

        # Clear logs button
        ttk.Button(log_win, text="Clear Logs", command=self.clear_logs, 
                  image=self.clear_icon, compound="left").pack(pady=5)

    def clear_logs(self):
        if messagebox.askyesno("Confirm", "Are you sure you want to clear all logs?"):
            clear_logs()
            self.show_logs()
            self.status_bar.config(text="Logs cleared")

# ========================
# Login Screen
# ========================
def check_login():
    entered = password_entry.get()
    if entered == "admin123":
        login_window.destroy()
        root = Tk()
        app = BackupApp(root)
        root.mainloop()
    else:
        messagebox.showerror("Error", "Incorrect password")

init_db()

login_window = Tk()
login_window.title("Login")
login_window.geometry("300x200")
login_window.configure(bg="#f0f0f0")
style = ttk.Style()
style.theme_use('clam')
style.configure("TButton", padding=6, font=("Arial", 10), background="#4CAF50", foreground="white")
style.configure("TLabel", font=("Arial", 12), background="#f0f0f0")
style.configure("TEntry", font=("Arial", 12))
 
ttk.Label(login_window, text="Secure Backup Login", font=("Arial", 14, "bold")).pack(pady=20)
ttk.Label(login_window, text="Enter Password:").pack()
password_entry = ttk.Entry(login_window, show="*", font=("Arial", 12))
password_entry.pack(pady=10)
ttk.Button(login_window, text="Login", command=check_login).pack(pady=10)

login_window.mainloop()
