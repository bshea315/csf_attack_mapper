"""API routes package."""
from app.api.routes import auth, ingest, detections, mappings, analytics, exports

__all__ = ["auth", "ingest", "detections", "mappings", "analytics", "exports"]
