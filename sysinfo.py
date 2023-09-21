import psutil
import platform
from datetime import datetime
from fastapi import APIRouter

router = APIRouter(
    prefix="/sys"
)

def get_size(bytes, suffix="B"):
    factor = 1024
    for unit in ["", "K", "M", "G", "T", "P"]:
        if bytes < factor:
            return f"{bytes:.2f}{unit}{suffix}"
        bytes /= factor

@router.get("/sysinfo")
def systemInfo():
    uname = platform.uname()
    return {"System" : uname.system,
    "Node Name" : uname.node,
    "Release" : uname.release,
    "Version" : uname.version,
    "Machine" : uname.machine,
    "Processor" : uname.processor}

@router.get("/bootInfo")
def bootInfo():
    boot_time_timestamp = psutil.boot_time()
    bt = datetime.fromtimestamp(boot_time_timestamp)
    return{"Boot Time" :  f"{bt.year}/{bt.month}/{bt.day} {bt.hour}:{bt.minute}:{bt.second}"}

@router.get("/cpuInfo")
def cpuInfo():
    cpufreq = psutil.cpu_freq()
    info = {"Physical cores": psutil.cpu_count(logical=False),
        "Total cores" : psutil.cpu_count(logical=True),
        "Max Frequency" : f"{cpufreq.max:.2f}Mhz",
        "Min Frequency" : f"{cpufreq.min:.2f}Mhz",
        "Current Frequency" : f"{cpufreq.current:.2f}Mhz"
    }
    for i, percentage in enumerate(psutil.cpu_percent(percpu=True, interval=1)):
        info[f"Core {i}"] = f"{percentage}%"
    info["Total CPU Usage"] = f"{psutil.cpu_percent()}%"
    return info

@router.get("/memInfo")
def memInfo():
    svmem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    info = {
        "Virtual Memomry": 
            {"Total" : f"{get_size(svmem.total)}",
            "Available" : f"{get_size(svmem.available)}",
            "Used" : f"{get_size(svmem.used)}",
            "Percentage" : f"{svmem.percent}%"},
        "swap":
            {"Total" : f"{get_size(swap.total)}",
            "Free" : f"{get_size(swap.free)}",
            "Used" : f"{get_size(swap.used)}",
            "Percentage" : f"{swap.percent}%"}
    }
    return info

@router.get("/diskInfo")
def diskInfo():
    partitions = psutil.disk_partitions()
    i = 0
    info = {}
    for partition in partitions:
        a = {}
        i += 1
        a = { "Device" : f"{partition.device}",
        "Mountpoint" : f"{partition.mountpoint}",
        "File system type" : f"{partition.fstype}"}
        try:
            partition_usage = psutil.disk_usage(partition.mountpoint)
        except PermissionError:
            continue
        a["Total Size"] = f"{get_size(partition_usage.total)}"
        a["Used"] = f"{get_size(partition_usage.used)}"
        a["Free"] = f"{get_size(partition_usage.free)}"
        a["Percentage"] = f"{partition_usage.percent}%"
        info[f"Device{i}"] = a
    disk_io = psutil.disk_io_counters()
    info["Total read"] =  f"{get_size(disk_io.read_bytes)}"
    info["Total write"] =  f"{get_size(disk_io.write_bytes)}"
    return info

