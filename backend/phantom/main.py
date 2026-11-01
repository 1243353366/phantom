"""PHANTOM API entrypoint.

    uvicorn phantom.main:app --reload
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from phantom import __version__
from phantom.api.mirror_routes import console as mirror_console
from phantom.api.mirror_routes import decoy as mirror_decoy
from phantom.api.routes import router
from phantom.api.shadow_routes import router as shadow_router
from phantom.db import init_db


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(
    lifespan=lifespan,
    title="PHANTOM",
    version=__version__,
    description=(
        "Privacy intelligence and relationship mapping. Local-first, "
        "metadata-first, provenance-required."
    ),
)

# Local development only. PHANTOM is not a hosted service.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)
app.include_router(mirror_console)
app.include_router(mirror_decoy)
app.include_router(shadow_router)
