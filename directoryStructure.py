import os
import configparser
from fastapi import APIRouter

def get_directory_size(directory):
    total = 0
    try:
        for entry in os.scandir(directory):
            if entry.is_file():
                total += entry.stat().st_size
            elif entry.is_dir():
                try:
                    total += get_directory_size(entry.path)
                except FileNotFoundError:
                    pass
    except NotADirectoryError:
        return os.path.getsize(directory)
    except PermissionError:
        return 0
    return total

def get_size_format(b, factor=1024, suffix="B"):
    for unit in ["", "K", "M", "G", "T", "P", "E", "Z"]:
        if b < factor:
            return f"{b:.2f}{unit}{suffix}"
        b /= factor
    return f"{b:.2f}Y{suffix}"

router = APIRouter(
    prefix="/directory"
)

config = configparser.ConfigParser()
config.read('config.ini')

@router.get("/struct")
def directoryStruct():
    folder_path = config["SYSTEM"]["PathToMonitor"]
    directory_sizes = []
    names = []
    for directory in os.listdir(folder_path):
        directory = os.path.join(folder_path, directory)
        directory_size = get_directory_size(directory)
        if directory_size == 0:
            continue
        directory_sizes.append(directory_size)
        names.append(os.path.basename(directory))
    info = dict(zip(names,directory_sizes))
    info["Total"] = get_size_format(sum(directory_sizes))
    return info