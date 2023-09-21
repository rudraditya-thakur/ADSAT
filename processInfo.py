import psutil
from fastapi import APIRouter

router = APIRouter(
    prefix="/process"
)

@router.get("/Processes")
def getListOfProcessSortedByMemory():
    listOfProcObjects = []
    for proc in psutil.process_iter():
       try:
           pinfo = proc.as_dict(attrs=['pid', 'name', 'username'])
           pinfo['vms'] = proc.memory_info().vms / (1024 * 1024)
           listOfProcObjects.append(pinfo);
       except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
           pass
    listOfProcObjects = sorted(listOfProcObjects, key=lambda procObj: procObj['vms'], reverse=True)
    return {
        "Processes" : listOfProcObjects,
    }