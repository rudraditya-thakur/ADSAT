from fastapi import FastAPI
import sysinfo

app = FastAPI()
app.include_router(sysinfo.router)
@app.get("/")
async def home():
    return {
        "message" : "hello",
    }