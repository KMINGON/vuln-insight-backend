from fastapi import FastAPI

from api.routes.analysis import router as analysis_router
from api.routes.cve import router as cve_router

app = FastAPI(title="NVD Data API")

app.include_router(cve_router)
app.include_router(analysis_router)

@app.get("/health")
async def health():
    return {"status": "ok"}
