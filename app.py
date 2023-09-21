from fastapi import FastAPI
import sysinfo
import processInfo

# Creating Application
app = FastAPI()

# Adding Routers
app.include_router(sysinfo.router)
app.include_router(processInfo.router)

@app.get("/")
async def home():
    return {
        "message" : "hello",
    }