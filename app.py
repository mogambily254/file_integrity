import os
import hashlib
import time
from datetime import datetime

class FileIntegrityMonitor:
    def __init__(self, directory, interval=10):
        self.directory = directory
        self.interval = interval
        self.file_hashes = {}

    def calculate_hash(self, file_path):
        """Calculate SHA256 hash of a file."""
        hash_func = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(4096):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except Exception as e:
            print(f"Error hashing file {file_path}: {e}")
            return None

    def scan_files(self):
        """Scan the directory and calculate file hashes."""
        current_files = {}
        for root, _, files in os.walk(self.directory):
            for file in files:
                file_path = os.path.join(root, file)
                file_hash = self.calculate_hash(file_path)
                if file_hash:
                    current_files[file_path] = file_hash
        return current_files

    def detect_changes(self, current_files):
        """Compare current file hashes with the baseline and detect changes."""
        added = set(current_files.keys()) - set(self.file_hashes.keys())
        removed = set(self.file_hashes.keys()) - set(current_files.keys())
        modified = {
            file for file in current_files.keys() & self.file_hashes.keys()
            if self.file_hashes[file] != current_files[file]
        }

        if added:
            print(f"[{datetime.now()}] Added: {', '.join(added)}")
        if removed:
            print(f"[{datetime.now()}] Removed: {', '.join(removed)}")
        if modified:
            print(f"[{datetime.now()}] Modified: {', '.join(modified)}")

        # Update baseline
        self.file_hashes = current_files

    def monitor(self):
        """Start monitoring the directory for changes."""
        print(f"Starting File Integrity Monitor on '{self.directory}'")
        while True:
            current_files = self.scan_files()
            self.detect_changes(current_files)
            time.sleep(self.interval)

if __name__ == "__main__":
    directory_to_monitor = input("Enter the directory to monitor: ")
    interval = int(input("Enter monitoring interval (seconds): "))

    if not os.path.exists(directory_to_monitor):
        print("The specified directory does not exist.")
    else:
        fim = FileIntegrityMonitor(directory_to_monitor, interval)
        fim.monitor()
