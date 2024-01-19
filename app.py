from fastapi import FastAPI, WebSocket
import sysinfo
import processInfo
import directoryStructure
import networkInfo
from fastapi.middleware.cors import CORSMiddleware
import os
import configparser
import asyncio

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

config = configparser.ConfigParser()
config.read('config.ini')

app.include_router(sysinfo.router)
app.include_router(processInfo.router)
app.include_router(directoryStructure.router)
app.include_router(networkInfo.router)

LOGGING_FILE_NAME = config["LOGGING"]["FileSystemLoggingName"]
LOGFILE = os.path.join(os.getcwd(), LOGGING_FILE_NAME)

async def logGenerator(websocket):
    with open(LOGFILE, 'r') as log_file:
        while True:
            line = log_file.readline()
            if not line:
                await asyncio.sleep(0.1)  # Sleep briefly to avoid busy-waiting
                continue

            await websocket.send_text(line)

@app.websocket("/stream-logs")
async def stream_logs(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            await logGenerator(websocket)
    except Exception as e:
        print(f"WebSocket Error: {e}")
    finally:
        await websocket.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)


