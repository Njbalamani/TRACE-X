"""TRACE-X — AI-powered cyber investigation assistant. FastAPI application."""
from __future__ import annotations

import logging
import os

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import router as api_router
from app.database.database import init_db
from app.services.storage import ensure_dirs

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("trace-x")

ALLOWED_ORIGINS = [o.strip() for o in os.environ.get(
    "TRACE_X_CORS_ORIGINS", "http://localhost:5173,http://localhost:4173,http://127.0.0.1:5173,http://127.0.0.1:4173"
).split(",") if o.strip()]

app = FastAPI(
    title="TRACE-X API",
    description="AI-powered cyber investigation assistant with evidence-to-conclusion "
                "traceability and a blockchain-style tamper-evident integrity ledger.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Never leak stack traces to users; log the full detail server-side."""
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal error occurred. The incident has been logged."},
    )


@app.on_event("startup")
def startup() -> None:
    init_db()
    ensure_dirs()
    logger.info("TRACE-X backend started. Evidence storage and database ready.")


@app.get("/api/health")
def health():
    return {"status": "ok", "app": "TRACE-X"}


app.include_router(api_router, prefix="/api")
