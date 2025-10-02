# Secure Backup Tool

*A Desktop Application for Encrypted Folder Backups with Cloud Synchronization*

## Overview

The **Secure Backup Tool** is a secure, user-friendly desktop application built with Python and Tkinter, designed to protect and manage your important folders through automated backups. It encrypts files using industry-standard Fernet symmetric encryption, compresses them into ZIP archives, and optionally uploads to multiple cloud services (Google Drive, Mega, and pCloud). Restoration is straightforward, with decryption and extraction handled seamlessly.

This tool is ideal for personal or small-team use, addressing needs like data protection against loss, ransomware, or hardware failure. It includes logging for audit trails, progress tracking, and a simple login for access control. All operations are local-first, with cloud sync as an enhancement.

**Key Goals:**
- Strong encryption for privacy.
- Multi-cloud support for redundancy.
- Easy-to-use GUI with real-time status updates.
- Reliable retries and error handling for robust backups.

## Features

### Core Features
- **Folder Backup**: Select any folder, zip it with compression, and encrypt the archive.
- **Encryption/Decryption**: Uses Fernet (AES-based) for secure, reversible protection. Key auto-generated and stored locally (`key.key`).
- **Cloud Synchronization**: Upload encrypted backups to Google Drive, Mega, or pCloud with progress bars and status feedback.
- **Restore Functionality**: Decrypt and extract backups to a chosen directory.
- **Logging System**: SQLite-based logs track all operations (ID, file, timestamp, cloud provider) with view/clear options.
- **Progress Tracking**: Visual progress bar and status labels during long operations.
- **Retry Logic**: Automatic retries (up to 3 attempts) for failed uploads using Tenacity.

### Security & Usability
- **Simple Login**: Password-protected access (default: `admin123` – change in code for production).
- **Local Storage**: Backups saved to configurable directory (`backups/` by default).
- **Cross-Platform**: Works on Windows, macOS, and Linux.
- **GUI Enhancements**: Modern Tkinter interface with icons, scrollbars, and threaded operations to avoid freezing.

### Limitations (Current)
- Cloud credentials are hardcoded (Mega/pCloud) – update for security.
- Google Drive requires OAuth setup via `client_secrets.json`.
- No scheduled backups (manual only).

## Tech Stack

- **Backend**: Python 3.12+
- **GUI**: Tkinter (with ttk for styling) + PIL (Pillow) for icons/images
- **Encryption**: Cryptography (Fernet for symmetric encryption)
- **Cloud Integration**:
  - Google Drive: PyDrive2 (OAuth2 authentication)
  - Mega: mega.py
  - pCloud: Built-in API via requests
- **Archiving**: Built-in `zipfile` and `shutil`
- **Database**: SQLite (for logs: `backups.db` auto-created)
- **Utilities**: Tenacity (retries), Requests (API calls), Threading (non-blocking UI)
- **Dependencies**: `cryptography`, `pydrive2`, `mega.py`, `tenacity`, `requests`, `pillow` (install via pip)

## Installation

1. **Clone the Repository**:
   ```
   git clone https://github.com/yourusername/secure-backup-tool.git
   cd secure-backup-tool
   ```

2. **Install Python Dependencies**:
   ```
   pip install cryptography pydrive2 mega.py tenacity requests pillow
   ```
   - Note: `mega.py` might install as `mega` – check with `pip list`.

3. **Google Drive Setup** (Optional, for Drive uploads):
   - Create a project in [Google Cloud Console](https://console.cloud.google.com).
   - Enable Drive API and download `client_secrets.json` (OAuth 2.0 credentials).
   - Place it in the project root.

4. **Update Credentials** (Security Step):
   - Edit `project.py`: Replace `MEGA_EMAIL`, `MEGA_PASSWORD`, `PCLOUD_EMAIL`, `PCLOUD_PASSWORD` with your own.
   - Change default login password in `check_login()` for better security.

5. **Run the Application**:
   ```
   python project.py
   ```
   - First run generates `key.key` (encryption key) and `backups/` folder.
   - Login with `admin123` (or your updated password).

## Usage

### Getting Started
1. **Login**: Enter the password to access the main dashboard.
2. **Backup a Folder**:
   - Click "Backup Folder" > Select source folder.
   - Choose cloud provider (or local-only).
   - Click "Start Backup" – watch progress and status.
3. **Restore a Backup**:
   - Click "Restore Backup" > Select encrypted ZIP file.
   - Choose extraction folder > Confirm.
4. **View Logs**:
   - Click "View Logs" to see operation history in a new window.
   - Use "Clear Logs" to reset.

### Example Workflow
- Backup: Select `Documents/` → Encrypt & ZIP → Upload to Mega.
- Status: "Encrypting... 50% → Uploading... Success!"
- Restore: Select `backup_2025-10-02.zip` → Decrypt to `Restored_Documents/`.

### File Structure After Run
- `backups/`: Encrypted ZIP files (e.g., `backup_YYYY-MM-DD_HH-MM-SS.zip`).
- `backups.db`: Log database.
- `key.key`: Your encryption key (keep safe!).
- `client_secrets.json`: Google Drive config (git-ignore this).

**Pro Tip**: Backup your `key.key` file separately – losing it means permanent data loss!


## Database Schema (Logs)

SQLite table `logs` (auto-created):
- `id` (INTEGER PRIMARY KEY)
- `file_path` (TEXT)
- `timestamp` (TEXT)
- `cloud_provider` (TEXT)
- `status` (TEXT)

Query example: `SELECT * FROM logs ORDER BY timestamp DESC;`

## Potential Improvements
- Add scheduled backups via cron/APScheduler.
- Support more clouds (e.g., Dropbox, OneDrive).
- Key management: Password-protect the key or use hardware keys.
- Multi-threaded parallel uploads.
- Web-based version with Flask.

## Contributing

Contributions welcome! Fork, branch, commit, and PR:
1. Fork the repo.
2. Create branch: `git checkout -b feature/cool-feature`.
3. Commit: `git commit -m "Add cool feature"`.
4. Push: `git push origin feature/cool-feature`.
5. Open Pull Request.

Issues? Open a GitHub Issue with details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Developed by **Avneet Kaur**, B.Tech (CSE), 6th Semester.
- Inspired by secure backup needs in academic projects! 🔒

---

*Last Updated: July 06, 2025*  
