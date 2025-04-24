import os
import hashlib
import time
import threading
import logging
from datetime import datetime
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO

# Configure logging
LOG_FILE = "monitor.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

class FileIntegrityMonitor:
    def __init__(self, directory, interval=3):
        self.directory = directory
        self.interval = interval
        self.file_hashes = {}
        self.running = False

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

        changes = []

        if added:
            message = f"Added: {', '.join(added)}"
            logging.info(message)
            changes.append(message)

        if removed:
            message = f"Removed: {', '.join(removed)}"
            logging.info(message)
            changes.append(message)

        if modified:
            message = f"Modified: {', '.join(modified)}"
            logging.info(message)
            changes.append(message)

        # Send updates to the web interface
        for change in changes:
            socketio.emit("log_update", {"message": f"[{datetime.now()}] {change}"})

        # Update baseline
        self.file_hashes = current_files

    def monitor(self):
        """Start monitoring the directory for changes."""
        self.running = True
        logging.info(f"Monitoring started on '{self.directory}'")
        socketio.emit("log_update", {"message": f"Monitoring started on '{self.directory}'"})

        while self.running:
            current_files = self.scan_files()
            self.detect_changes(current_files)
            time.sleep(self.interval)

    def stop(self):
        """Stop monitoring."""
        self.running = False
        logging.info("Monitoring stopped.")
        socketio.emit("log_update", {"message": "Monitoring stopped."})

monitor = None
monitor_thread = None

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/start", methods=["POST"])
def start_monitoring():
    global monitor, monitor_thread
    directory = request.json.get("directory")
    interval = request.json.get("interval", 3)

    if not os.path.exists(directory):
        return jsonify({"status": "error", "message": "Invalid directory"}), 400

    if monitor and monitor.running:
        return jsonify({"status": "error", "message": "Monitoring is already running"}), 400

    monitor = FileIntegrityMonitor(directory, interval)
    monitor_thread = threading.Thread(target=monitor.monitor)
    monitor_thread.daemon = True
    monitor_thread.start()

    return jsonify({"status": "success", "message": "Monitoring started"})

@app.route("/stop", methods=["POST"])
def stop_monitoring():
    global monitor
    if monitor and monitor.running:
        monitor.stop()
        return jsonify({"status": "success", "message": "Monitoring stopped"})
    return jsonify({"status": "error", "message": "Monitoring is not running"}), 400

@app.route("/logs")
def get_logs():
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as log_file:
            logs = log_file.readlines()
        return jsonify({"logs": logs})
    return jsonify({"logs": []})

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
