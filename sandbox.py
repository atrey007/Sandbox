import os
import psutil
import logging
import scapy.all as scapy
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk, filedialog
import re
import subprocess

# NEW IMPORTS FOR SHELL MONITORING
import win32api
import win32con
import win32process
import win32gui

# Set up logging
logging.basicConfig(filename="sandbox_log.txt", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Define paths
PROC_MON_PATH = r"C:\Users\shash\OneDrive\Desktop\Procmon.exe"
LOG_FILE_PATH = os.path.join(os.getcwd(), "procmon.pml")

# NEW SHELL MONITORING CONFIGURATION
SHELL_PROCESS_NAMES = [
    "cmd.exe", 
    "powershell.exe", 
    "bash.exe",
    "wsl.exe",          # For WSL terminals
    "conhost.exe",      # Windows Console Host
    "Code.exe",         # VS Code's integrated terminal
    "WindowsTerminal.exe" # Windows Terminal
]
SUSPICIOUS_PATTERNS = [
    r"rm\s+-rf",                     # More specific rm -rf
    r"format\s+[A-Z]:",             # Drive formatting
    r"(wget|curl)\s+http",          # Suspicious downloads
    r"echo\s+.*\|\s*sh",           # Pipe to shell
    r"reg\s+add\s+HKLM",           # Registry modification
    r"schtasks\s+/create",         # Scheduled tasks
    r"Invoke-WebRequest\s+-",      # PowerShell web requests
    r"Start-Process\s+-WindowStyle\s+Hidden",  # Hidden processes
    r"iex\s+\(New-Object\s+Net.WebClient\)",   # Remote code execution
    r"-e\s+[A-Za-z0-9+/]{50,}"     # Long base64 commands
]
WARNING_THRESHOLD = 15  # Commands/minute

# Apple-style design constants
APPLE_COLORS = {
    "windowBg": "#f5f5f7",
    "widgetBg": "#ffffff",
    "primary": "#0071e3",
    "secondary": "#34c759",
    "danger": "#ff3b30",
    "textPrimary": "#1d1d1f",
    "textSecondary": "#86868b",
    "border": "#d2d2d7",
    "systemGray": "#8e8e93",
    "hoverEffect": "#f2f2f2"
}

FONT_REGULAR = ('Helvetica', 12)
FONT_BOLD = ('Helvetica', 14, 'bold')
FONT_CODE = ('Menlo', 10)
START_ICON = "▶️"
STOP_ICON = "⏹️"
TRASH_ICON = "🗑️"

# NEW FUNCTION TO GET FOLDER PATH VIA GUI
def get_monitoring_folder():
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    
    while True:
        folder_path = filedialog.askdirectory(
            title="Select Folder to Monitor",
            initialdir=os.path.expanduser("~"))
        
        if not folder_path:  # User clicked cancel
            if messagebox.askretrycancel("No Folder Selected", "You must select a folder to monitor. Try again?"):
                continue
            else:
                logging.error("User canceled folder selection")
                root.destroy()
                raise SystemExit("No folder selected - exiting")
        
        # Validate the selected path
        if not os.path.isdir(folder_path):
            messagebox.showerror("Invalid Folder", "The selected path is not a valid directory. Please try again.")
            continue
        
        root.destroy()
        return os.path.normpath(folder_path)

# Get the folder path from user input
test_folder_path = get_monitoring_folder()
logging.info(f"Monitoring folder set to: {test_folder_path}")

# ProcMon Functions
def start_procmon():
    try:
        subprocess.run([PROC_MON_PATH, "/minimized", "/quiet", "/backingfile", LOG_FILE_PATH], check=True)
        logging.info("ProcMon started.")
    except Exception as e:
        logging.error(f"Error starting ProcMon: {str(e)}")

def stop_procmon():
    try:
        subprocess.run([PROC_MON_PATH, "/terminate"], check=True)
        logging.info("ProcMon terminated and log saved.")
    except Exception as e:
        logging.error(f"Error stopping ProcMon: {str(e)}")

# Thread management
class MonitoringControl:
    def __init__(self):
        self.threads = {}
        self.stop_events = {}
        
    def start_monitoring(self, name, target):
        if name in self.threads:
            self.stop_monitoring(name)
        self.stop_events[name] = threading.Event()
        thread = threading.Thread(
            target=target, 
            args=(self.stop_events[name],),
            daemon=True
        )
        self.threads[name] = thread
        thread.start()
        logging.info(f"Started {name.replace('_', ' ')}")
    
    def stop_monitoring(self, name):
        if name in self.stop_events:
            self.stop_events[name].set()
            del self.threads[name]
            del self.stop_events[name]
            logging.info(f"Stopped {name.replace('_', ' ')}")

monitor_control = MonitoringControl()

# NEW SHELL MONITORING FUNCTIONS
def analyze_process_tree(pid):
    """Check for suspicious parent processes with exceptions"""
    suspicious_parents = ["excel.exe", "chrome.exe", "winword.exe"]
    trusted_parents = ["code.exe", "devenv.exe", "pycharm.exe", "explorer.exe" , "WindowsTerminal.exe" ,  "conhost.exe"]
    
    try:
        process = psutil.Process(pid)
        parent = process.parent()
        
        if not parent:
            return False  # No parent process
        
        # Check for trusted parent processes
        if parent.name().lower() in trusted_parents:
            return False  # Skip alerts from IDEs
            
        return parent.name().lower() in suspicious_parents
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        logging.debug(f"Error analyzing process tree for PID {pid}: {e}")
        return False

def check_hidden_window(pid):
    try:
        process = psutil.Process(pid)
        cmdline = " ".join(process.cmdline()).lower()
        
        # Whitelist specific patterns
        if any(pattern in cmdline for pattern in [
            "vs\\workbench\\contrib\\terminal",
            "jetbrains",
            "shellIntegration.ps1",
            "notepad.exe",
            "sublime_text.exe"
        ]):
            return False

        # Check if the process has a window handle
        hwnds = win32process.EnumProcessWindows(pid)
        if not hwnds:
            return False  # No window handle found

        # Check if the window is visible
        is_visible = win32gui.IsWindowVisible(hwnds[0])
        return not is_visible

    except Exception as e:
        logging.debug(f"Error checking hidden window for PID {pid}: {e}")
        return False

def monitor_shell_commands(stop_event):
    logging.info("Shell monitoring started.")
    logging.debug("DEBUG: Shell monitoring function is running.")
    previous_commands = set()
    command_counts = {}
    last_reset_time = time.time()

    while not stop_event.is_set():
        try:
            current_time = time.time()
            if current_time - last_reset_time >= 60:
                logging.debug("Resetting command counts.")
                for key, count in command_counts.items():
                    if count > WARNING_THRESHOLD:
                        logging.warning(f"[SHELL MALWARE] High command frequency ({count}/min): {key}")
                command_counts.clear()
                last_reset_time = current_time

            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    process_name = proc.info['name'].lower()
                    if process_name not in SHELL_PROCESS_NAMES:
                        logging.debug(f"Skipping non-shell process: {process_name}")
                        continue

                    logging.debug(f"Found shell process: {process_name} (PID: {proc.info['pid']})")
                    cmdline = " ".join(proc.info['cmdline'])
                    if not cmdline or cmdline in previous_commands:
                        logging.debug(f"Skipping duplicate or empty command: {cmdline}")
                        continue

                    logging.debug(f"New command detected: {cmdline}")
                    previous_commands.add(cmdline)
                    logging.info(f"Shell Command: {cmdline}")

                    for pattern in SUSPICIOUS_PATTERNS:
                        if re.search(pattern, cmdline, re.IGNORECASE):
                            logging.warning(f"[SHELL MALWARE] Suspicious command: {cmdline}")
                            logging.debug(f"Matched pattern: {pattern}")

                    if analyze_process_tree(proc.info['pid']):
                        logging.warning(f"[SHELL MALWARE] Unusual parent process for: {cmdline}")

                    if check_hidden_window(proc.info['pid']):
                        logging.warning(f"[SHELL MALWARE] Hidden window process: {cmdline}")

                    key = f"{proc.info['name']}-{proc.info['pid']}"
                    command_counts[key] = command_counts.get(key, 0) + 1

                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    logging.debug(f"Error accessing process: {e}")

        except Exception as e:
            logging.error(f"Shell monitoring error: {str(e)}")
        
        time.sleep(2)

# Existing monitoring functions (unchanged)
class FileChangeHandler(FileSystemEventHandler):
    def on_modified(self, event): logging.info(f"File modified: {event.src_path}")
    def on_created(self, event): logging.info(f"File created: {event.src_path}")
    def on_deleted(self, event): logging.info(f"File deleted: {event.src_path}")

def monitor_file_system(stop_event):
    if not os.path.exists(test_folder_path):
        logging.error(f"Path does not exist: {test_folder_path}")
        return
    observer = Observer()
    try:
        event_handler = FileChangeHandler()
        observer.schedule(event_handler, test_folder_path, recursive=True)
        observer.start()
        while not stop_event.is_set():
            time.sleep(1)
    finally:
        observer.stop()
        observer.join()

def monitor_disk_usage(stop_event):
    try:
        while not stop_event.is_set():
            usage = psutil.disk_usage(test_folder_path)
            logging.info(f"Disk Usage - Total: {usage.total//(1024**3)}GB, Used: {usage.used//(1024**3)}GB")
            time.sleep(10)
    except Exception as e:
        logging.error(f"Disk monitoring error: {str(e)}")

def monitor_memory_usage(stop_event, threshold=80):
    try:
        while not stop_event.is_set():
            for proc in psutil.process_iter(['pid', 'name', 'memory_percent', 'cwd']):
                try:
                    if proc.info['cwd'] == test_folder_path:
                        memory_percent = proc.memory_percent()
                        logging.info(f"Memory: {proc.info['name']} ({memory_percent}%)")
                        if memory_percent > threshold: 
                            logging.warning(f"Memory threshold exceeded!")
                except: pass
            time.sleep(10)
    except Exception as e:
        logging.error(f"Memory monitoring error: {str(e)}")

def monitor_processes(stop_event):
    try:
        # Normalize and prepare the target path for comparison
        target_path = os.path.normpath(test_folder_path).lower()
        logging.info(f"[PROCESS MONITOR] Starting monitoring for path: {target_path}")
        
        while not stop_event.is_set():
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'cwd']):
                try:
                    # Get process info with error handling
                    proc_info = proc.info
                    proc_name = proc_info.get('name', 'unknown')
                    proc_cwd = proc_info.get('cwd', '')
                    
                    # Skip processes without CWD
                    if not proc_cwd:
                        continue
                        
                    # Normalize and compare paths
                    proc_cwd_normalized = os.path.normpath(proc_cwd).lower()
                    logging.debug(f"[PROCESS CHECK] {proc_name} ({proc_info['pid']}) - CWD: {proc_cwd_normalized}")

                    if proc_cwd_normalized == target_path:
                        log_msg = f"Process: {proc_name} (PID: {proc_info['pid']}, CPU: {proc_info['cpu_percent']}%)"
                        logging.info(log_msg)
                        
                except Exception as e:
                    logging.debug(f"[PROCESS ERROR] Error checking {proc_name}: {str(e)}")
                    
            time.sleep(5)
            
    except Exception as e:
        logging.error(f"Process monitoring error: {str(e)}")
def monitor_network(stop_event):
    def packet_callback(packet): 
        if not stop_event.is_set():
            logging.info(f"Packet: {packet.summary()}")
    try:
        scapy.sniff(prn=packet_callback, store=False, stop_filter=lambda _: stop_event.is_set())
    except Exception as e:
        logging.error(f"Network monitoring error: {str(e)}")

def terminate_high_cpu_processes(stop_event, threshold=90):
    try:
        while not stop_event.is_set():
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'cwd']):
                try:
                    if proc.info['cwd'] == test_folder_path and proc.info['cpu_percent'] > threshold:
                        logging.warning(f"Terminating: {proc.info['name']}")
                        proc.terminate()
                except: pass
            time.sleep(5)
    except Exception as e:
        logging.error(f"Termination error: {str(e)}")

# GUI Implementation
class SandboxGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Sandbox Monitoring System")
        self.geometry("1000x800")
        self.configure(bg=APPLE_COLORS["windowBg"])
        
        # Configure styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Base styles
        self.style.configure(".", font=FONT_REGULAR, background=APPLE_COLORS["windowBg"])
        self.style.configure("TButton", padding=8, relief="flat", borderwidth=0)
        
        # Button styles
        self.style.configure("Start.TButton", 
                           background=APPLE_COLORS["primary"], 
                           foreground="white")
        self.style.map("Start.TButton",
            background=[("active", "#0063b8")]
        )
        
        self.style.configure("Stop.TButton", 
                           background=APPLE_COLORS["danger"], 
                           foreground="white")
        self.style.map("Stop.TButton",
            background=[("active", "#cc2a24")]
        )
        
        self.style.configure("Clean.TButton", 
                           background=APPLE_COLORS["windowBg"],
                           foreground=APPLE_COLORS["textSecondary"])
        self.style.map("Clean.TButton",
            foreground=[('active', APPLE_COLORS["primary"])]
        )

        # Main container
        main_frame = ttk.Frame(self, padding=20)
        main_frame.pack(expand=True, fill="both")

        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill="x", pady=(0, 20))
        ttk.Label(header_frame, text="Sandbox Monitoring System", 
                font=FONT_BOLD, foreground=APPLE_COLORS["primary"]).pack(side="left")

        # Display monitored folder with change button
        folder_frame = ttk.Frame(main_frame)
        folder_frame.pack(fill="x", pady=(0, 10))
        ttk.Label(folder_frame, text="Monitoring Folder:", font=FONT_REGULAR).pack(side="left")
        self.folder_label = ttk.Label(folder_frame, text=test_folder_path, font=FONT_CODE, 
                                    foreground=APPLE_COLORS["textSecondary"], width=60)
        self.folder_label.pack(side="left", padx=5)
        ttk.Button(folder_frame, text="Change", command=self.change_monitoring_folder,
                 style="Clean.TButton").pack(side="right")

        # Monitoring controls
        control_frame = ttk.LabelFrame(main_frame, text=" Monitoring Controls ", padding=15)
        control_frame.pack(fill="x", pady=10)

        # UPDATED MONITORS LIST WITH SHELL MONITORING
        monitors = [
            ("Process Monitoring", monitor_processes),
            ("File System Monitoring", monitor_file_system),
            ("Disk Usage Monitoring", monitor_disk_usage),
            ("Memory Usage Monitoring", monitor_memory_usage),
            ("Network Monitoring", monitor_network),
            ("Process Termination", terminate_high_cpu_processes),
            ("Shell Monitoring", monitor_shell_commands)  # NEW MONITORING COMPONENT
        ]

        for row, (label, func) in enumerate(monitors):
            ttk.Button(control_frame,
                      text=f"{START_ICON} {label}",
                      command=lambda f=func, l=label: self.start_monitoring(f, l),
                      style="Start.TButton"
                     ).grid(row=row, column=0, padx=5, pady=5, sticky="ew")
            
            ttk.Button(control_frame,
                      text=f"{STOP_ICON} Stop",
                      command=lambda l=label: self.stop_monitoring(l),
                      style="Stop.TButton"
                     ).grid(row=row, column=1, padx=5, pady=5, sticky="ew")

        # ProcMon controls
        procmon_frame = ttk.Frame(control_frame)
        procmon_frame.grid(row=len(monitors), columnspan=2, pady=10, sticky="ew")
        ttk.Button(procmon_frame, text=f"{START_ICON} Start ProcMon",
                 command=start_procmon, style="Start.TButton").pack(side="left", padx=5)
        ttk.Button(procmon_frame, text=f"{STOP_ICON} Stop ProcMon",
                 command=stop_procmon, style="Stop.TButton").pack(side="left", padx=5)

        # Log section
        log_frame = ttk.LabelFrame(main_frame, text=" System Logs ", padding=15)
        log_frame.pack(expand=True, fill="both", pady=10)

        # Log header
        log_header = ttk.Frame(log_frame)
        log_header.pack(fill="x", pady=(0, 10))
        ttk.Label(log_header, text="Live Logs", font=FONT_REGULAR).pack(side="left")
        ttk.Button(log_header, text=TRASH_ICON, command=self.clear_logs,
                 style="Clean.TButton").pack(side="right")

        # Log display with malware alerts
        self.log_display = scrolledtext.ScrolledText(
            log_frame,
            font=FONT_CODE,
            bg=APPLE_COLORS["widgetBg"],
            fg=APPLE_COLORS["textPrimary"],
            insertbackground=APPLE_COLORS["textPrimary"],
            highlightthickness=0,
            wrap="word"
        )
        self.log_display.pack(expand=True, fill="both")
        self.log_display.config(state="disabled")
        self.log_display.tag_configure("alert", foreground="red", font=FONT_BOLD)  # NEW ALERT STYLING

        # Start log updater
        self.update_logs()
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def change_monitoring_folder(self):
        """Allow user to change the monitoring folder during runtime"""
        global test_folder_path
        
        new_path = filedialog.askdirectory(
            title="Select New Folder to Monitor",
            initialdir=os.path.expanduser("~"))
        
        if not new_path:  # User clicked cancel
            return
            
        if not os.path.isdir(new_path):
            messagebox.showerror("Invalid Folder", "The selected path is not a valid directory.")
            return
        
        # Stop all monitoring before changing folder
        for monitor in list(monitor_control.threads.keys()):
            monitor_control.stop_monitoring(monitor)
        
        # Update the folder path
        test_folder_path = os.path.normpath(new_path)
        self.folder_label.config(text=test_folder_path)
        logging.info(f"Monitoring folder changed to: {test_folder_path}")
        messagebox.showinfo("Folder Changed", f"Now monitoring: {test_folder_path}")

    def start_monitoring(self, func, label):
        monitor_name = label.replace(" ", "_")
        monitor_control.start_monitoring(monitor_name, func)

    def stop_monitoring(self, label):
        monitor_name = label.replace(" ", "_")
        monitor_control.stop_monitoring(monitor_name)

    def clear_logs(self):
        self.log_display.config(state="normal")
        self.log_display.delete(1.0, tk.END)
        self.log_display.config(state="disabled")
        try:
            with open("sandbox_log.txt", "w") as f:
                f.write("")
            logging.info("Logs cleared by user")
        except Exception as e:
            logging.error(f"Error clearing logs: {str(e)}")
            messagebox.showerror("Error", f"Failed to clear logs: {str(e)}")

    def update_logs(self):
        self.log_display.config(state="normal")
        self.log_display.delete(1.0, tk.END)
        try:
            with open("sandbox_log.txt", "r") as f:
                for line in f.readlines():
                    if "[SHELL MALWARE]" in line:
                        self.log_display.insert(tk.END, line, "alert")
                    else:
                        self.log_display.insert(tk.END, line)
        except FileNotFoundError:
            pass
        self.log_display.config(state="disabled")
        self.after(1000, self.update_logs)

    def on_close(self):
        for monitor in list(monitor_control.threads.keys()):
            monitor_control.stop_monitoring(monitor)
        try:
            with open("sandbox_log.txt", "w") as f:
                f.write("")
            logging.info("Application closed")
        except Exception as e:
            logging.error(f"Error on exit: {str(e)}")
        self.destroy()

if __name__ == "__main__":
    app = SandboxGUI()
    app.mainloop()
