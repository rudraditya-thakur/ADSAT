from fastapi import FastAPI
import sysinfo
import processInfo
import directoryStructure
import networkInfo
from fastapi import Request
from sse_starlette.sse import EventSourceResponse
import uvicorn
from sh import tail
from fastapi.middleware.cors import CORSMiddleware
import time
import os
import configparser

# Creating Application
app = FastAPI()

# Adding Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost","http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

config = configparser.ConfigParser()
config.read('config.ini')

# Adding Routers
app.include_router(sysinfo.router)
app.include_router(processInfo.router)
app.include_router(directoryStructure.router)
app.include_router(networkInfo.router)

@app.get("/")
async def home():
    return {
        "message" : "hello",
    }

LOGGING_FILE_NAME = config["LOGGING"]["FileSystemLoggingName"]
LOGFILE = os.path.join(os.getcwd(),LOGGING_FILE_NAME)

async def logGenerator(request):
    for line in tail("-f",LOGFILE,_iter=True):
        if await request.is_disconnected():
            print("client disconnected")
            break
        yield line
        time.sleep(0.5)

@app.get('/stream-logs')
async def run(request: Request):
    event_generator = logGenerator(request)
    return EventSourceResponse(event_generator)

uvicorn.run(app, host="127.0.0.1", port=8000)