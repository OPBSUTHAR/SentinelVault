"""SentinelVault FastAPI application."""
from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .api import router as api_router
from .config import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("sentinelvault")

app = FastAPI(
    title="SentinelVault API",
    description="AI-powered password manager — zero-knowledge vault, breach monitoring, health scoring.",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url=None,
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api")

# Serve the built React frontend when present (production / single-process mode).
FRONTEND_DIST = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"

if (FRONTEND_DIST / "assets").is_dir():
    app.mount("/assets", StaticFiles(directory=str(FRONTEND_DIST / "assets")), name="assets")


@app.get("/{full_path:path}", include_in_schema=False)
def spa_fallback(full_path: str):
    if full_path.startswith(("api/", "assets/")):
        return JSONResponse(status_code=404, content={"detail": "Not found"})
    candidate = (FRONTEND_DIST / full_path).resolve()
    if str(candidate).startswith(str(FRONTEND_DIST.resolve())) and candidate.is_file():
        return FileResponse(str(candidate))
    index_file = FRONTEND_DIST / "index.html"
    if index_file.is_file():
        return FileResponse(str(index_file))
    return JSONResponse(
        status_code=200,
        content={
            "app": settings.APP_NAME,
            "message": "SentinelVault API is running. Build the React frontend (frontend/) to see the UI, "
                       "or use the Vite dev server on port 5176.",
            "docs": "/api/docs",
        },
    )


@app.on_event("startup")
async def on_startup() -> None:
    logger.info("SentinelVault API started — docs at /api/docs")
