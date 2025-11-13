from fastapi import FastAPI
from api.routes.cve import router as cve_router

app = FastAPI(title="NVD Data API")

app.include_router(cve_router)

@app.get("/health")
async def health():
    return {"status": "ok"}
