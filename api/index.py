"""
Vercel serverless entrypoint.

Vercel's @vercel/python builder serves the ASGI `app` exported here; the
rewrite in vercel.json routes every path to this function.

Note: serverless invocations are short-lived and ASGI lifespan startup may not
run, so database tables/seeds are NOT created automatically here. Initialize
the schema once against your external Postgres before/after the first deploy
(see the deployment notes), then load seeds via POST /api/attacks/seed.
"""

from src.api.server import app  # noqa: F401
