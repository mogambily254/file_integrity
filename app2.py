import os
import hashlib
import time
import logging
from datetime import datetime

# Configure logging
LOG_FILE = "monitor.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

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
            logging.error(f"Error hashing file {file_path}: {e}")
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
            message = f"Added: {', '.join(added)}"
            logging.info(message)
            print(f"[{datetime.now()}] {message}")

        if removed:
            message = f"Removed: {', '.join(removed)}"
            logging.info(message)
            print(f"[{datetime.now()}] {message}")

        if modified:
            message = f"Modified: {', '.join(modified)}"
            logging.info(message)
            print(f"[{datetime.now()}] {message}")

        # Update baseline
        self.file_hashes = current_files

    def monitor(self):
        """Start monitoring the directory for changes."""
        logging.info(f"Starting File Integrity Monitor on '{self.directory}'")
        print(f"Monitoring '{self.directory}'... Logs saved to {LOG_FILE}")

        while True:
            current_files = self.scan_files()
            self.detect_changes(current_files)
            time.sleep(self.interval)

if __name__ == "__main__":
    directory_to_monitor = input("Enter the directory to monitor: ")
    interval = int(input("Enter monitoring interval (seconds): "))

    if not os.path.exists(directory_to_monitor):
        print("The specified directory does not exist.")
        logging.error(f"Invalid directory: {directory_to_monitor}")
    else:
        fim = FileIntegrityMonitor(directory_to_monitor, interval)
        fim.monitor()
