"""FastAPI application factory for CHYing Agent Web Dashboard."""

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .routes import dashboard, challenges, executions, writeups

# web-ui/dist 构建产物目录
_STATIC_DIR = Path(__file__).parent.parent.parent / "web-ui" / "dist"


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="CHYing Agent Dashboard",
        description="Web Dashboard API for CHYing Agent",
        version="1.0.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"])
    app.include_router(challenges.router, prefix="/api/challenges", tags=["Challenges"])
    app.include_router(executions.router, prefix="/api/executions", tags=["Executions"])
    app.include_router(writeups.router, prefix="/api/writeups", tags=["Writeups"])

    # Serve Vue SPA static files if built
    if _STATIC_DIR.exists():
        # Mount assets directory for CSS/JS chunks
        assets_dir = _STATIC_DIR / "assets"
        if assets_dir.exists():
            app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

        # Serve other static files (vite.svg, etc.)
        @app.get("/vite.svg")
        async def vite_svg():
            svg = _STATIC_DIR / "vite.svg"
            if svg.exists():
                return FileResponse(str(svg), media_type="image/svg+xml")

        # SPA fallback: serve index.html for all non-API routes
        @app.get("/{full_path:path}")
        async def spa_fallback(request: Request, full_path: str):
            # Skip API routes
            if full_path.startswith("api/"):
                return
            # Try to serve exact static file first
            static_file = _STATIC_DIR / full_path
            if static_file.is_file():
                return FileResponse(str(static_file))
            # Fallback to index.html for SPA routing
            return FileResponse(str(_STATIC_DIR / "index.html"))

    return app
