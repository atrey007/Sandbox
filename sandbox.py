import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time

# Set up logging
logging.basicConfig(filename="sandbox_log.txt", level=logging.INFO)

# File System Monitoring
class FileChangeHandler(FileSystemEventHandler):
    def on_modified(self, event):
        logging.info(f"File modified: {event.src_path}")
    def on_created(self, event):
        logging.info(f"File created: {event.src_path}")
    def on_deleted(self, event):
        logging.info(f"File deleted: {event.src_path}")

def monitor_file_system(path_to_watch):
    event_handler = FileChangeHandler()
    observer = Observer()
    observer.schedule(event_handler, path=path_to_watch, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    # Specify the directory you want to monitor
    monitor_file_system(r"C:\Users\shash\OneDrive\Desktop\TEST FOLDER")
