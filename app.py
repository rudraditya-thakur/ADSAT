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