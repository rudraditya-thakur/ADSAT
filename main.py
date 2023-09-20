import os
import re
import configparser
import time
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import yara

config = configparser.ConfigParser()
config.read('config.ini')

YARA_FILE_PATH = os.path.join(os.getcwd(),config["YARA"]["FolderName"])
pattern = r'\.(.*)'
file_dict = {}
i = 0
for root, _, files in os.walk(YARA_FILE_PATH):
    i += 1
    for filename in files:
        if filename.endswith(".yar") or filename.endswith(".yara"):
            file_path = os.path.join(root, filename)
            filename = f"namespace{1}"
            file_dict[filename] = file_path
rules = yara.compile(filepaths=file_dict)

LOGGING_FILE_NAME = config["LOGGING"]["FileSystemLoggingName"]
LOGGING_FILE_PATH = os.path.join(os.getcwd(),LOGGING_FILE_NAME)

logging.basicConfig(filename=LOGGING_FILE_PATH,level=logging.INFO,format='%(asctime)s - %(message)s')

class SystemFileHandler(FileSystemEventHandler):
    def on_moved(self, event):
        if os.path.exists(event.src_path):
            if not event.is_directory:
                logging.info(f'Moved: {event.src_path}')
            elif event.is_directory:
                logging.info(f'Moved: {event.src_path}')
    def on_created(self, event):
        if os.path.exists(event.src_path):
            if not event.is_directory:
                logging.info(f'Created: {event.src_path}')
                matches = rules.match(event.src_path)
                if matches:
                    logging.info(f"Matched YARA rule in {event.src_path}:")
                    for match in matches: logging.info(f"Rule: {match.rule}")
            elif event.is_directory:
                logging.info(f'Created: {event.src_path}')
    def on_deleted(self, event):
        if not event.is_directory:
            logging.info(f'Deleted: {event.src_path}')
        elif event.is_directory:
            logging.info(f'Deleted: {event.src_path}')
    def on_modified(self, event):
        if os.path.exists(event.src_path):
            if not event.is_directory:
                logging.info(f'Modified: {event.src_path}')
                matches = rules.match(event.src_path)
                if matches:
                    logging.info(f"Matched YARA rule in {event.src_path}:")
                    for match in matches: logging.info(f"Rule: {match.rule}")
            elif event.is_directory:
                logging.info(f'Modified: {event.src_path}')

if __name__ == "__main__":
    path = config["SYSTEM"]["PathToMonitor"]
    observer = Observer()
    observer.schedule(SystemFileHandler(),path,recursive=True if config["DEFAULT"]["MonitorSubdirectories"] == "yes" else False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()