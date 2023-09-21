import psutil
import time
from scapy.all import *
from collections import defaultdict
import pandas as pd
from fastapi import APIRouter

router = APIRouter(
    prefix="/net"
)

UPDATE_DELAY = 1

def get_size(bytes, suffix="B"):
    factor = 1024
    for unit in ["", "K", "M", "G", "T", "P"]:
        if bytes < factor:
            return f"{bytes:.2f}{unit}{suffix}"
        bytes /= factor


@router.get("/netusage")
def networkInfo():
    io = psutil.net_io_counters()
    bytes_sent, bytes_recv = io.bytes_sent, io.bytes_recv
    io_2 = psutil.net_io_counters()
    us, ds = io_2.bytes_sent - bytes_sent, io_2.bytes_recv - bytes_recv
    n_usage = {"Upload" : get_size(io_2.bytes_sent),
              "Download" : get_size(io_2.bytes_recv),
              "Upload Speed": get_size(us / UPDATE_DELAY),
              "Download Speed": get_size(ds / UPDATE_DELAY),
              "bytes_sent" : io_2.bytes_sent,
              "bytes_recv" : io_2.bytes_recv
              }
    return n_usage


@router.get("/netusagePI")
async def netUsagePi():
    io = psutil.net_io_counters(pernic=True)
    io_2 = psutil.net_io_counters(pernic=True)
    data = {}
    i = 0
    for iface, iface_io in io.items():
        i+= 1
        upload_speed, download_speed = io_2[iface].bytes_sent - iface_io.bytes_sent, io_2[iface].bytes_recv - iface_io.bytes_recv
        data[f"iface{i}"] = {
            "iface": iface, "Download": get_size(io_2[iface].bytes_recv),
            "Upload": get_size(io_2[iface].bytes_sent),
            "Upload Speed": f"{get_size(upload_speed / UPDATE_DELAY)}/s",
            "Download Speed": f"{get_size(download_speed / UPDATE_DELAY)}/s",
        }
    return data