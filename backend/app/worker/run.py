"""
Entrypoint: `python -m app.worker.run`
Starts an RQ worker listening on the "analysis" queue. Swappable for Celery
without changing tasks.py's signature if the team prefers it later.
"""
import logging

import redis
from rq import Worker, Queue

from app.core.config import get_settings
from app.db.session import Base, engine

logging.basicConfig(level="INFO")
logger = logging.getLogger("clonedetector.worker.run")

settings = get_settings()

if __name__ == "__main__":
    # Ensure tables exist even if the worker starts before the API container.
    Base.metadata.create_all(bind=engine)

    conn = redis.from_url(settings.REDIS_URL)
    queue = Queue("analysis", connection=conn)
    logger.info("Worker starting, listening on queue 'analysis'")
    worker = Worker([queue], connection=conn)
    worker.work()
