#!/usr/bin/env python3
"""
Sentinel Scanner — GitHub Actions Job Consumer
==============================================
Triggered by repository_dispatch from Vercel. Pulls Celery v2 messages from
the Redis queue, decodes them, and calls the real task functions directly
(importing them from tasks.py — no Celery worker process needed).

Usage:
    python consume_jobs.py <queue> [--timeout SECONDS]

    queue:     Redis queue name (fast_network_scans, heavy_sast_scans, periodic_cron_scans)
    --timeout: Max seconds to keep processing (default 600 for GitHub Actions limit)

Architecture:
    Vercel LPUSH → Redis queue → GitHub Actions pulls → tasks.py functions
"""

import os
import sys
import json
import base64
import time
import argparse
from datetime import datetime

import redis

# ── Parse args ──────────────────────────────────────────────────────────
parser = argparse.ArgumentParser(description="Consume Celery jobs from Redis")
parser.add_argument("queue", help="Redis queue name to consume from")
parser.add_argument(
    "--timeout",
    type=int,
    default=600,
    help="Max seconds to keep processing (default 600)",
)
parser.add_argument(
    "--idle-exit",
    type=int,
    default=15,
    help="Seconds of idle queue before exiting (default 15)",
)
args = parser.parse_args()

QUEUE = args.queue
TIMEOUT = args.timeout
IDLE_EXIT = args.idle_exit

# ── Redis connection ────────────────────────────────────────────────────
REDIS_URL = os.environ.get("REDIS_URL", os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0"))
REDIS_URL = REDIS_URL.replace("rediss://", "redis://")  # redis-py <5 doesn't support rediss directly

r = redis.Redis.from_url(REDIS_URL, ssl_cert_reqs=None)
print(f"[Worker] Connected to Redis. Listening on queue: {QUEUE}")
print(f"[Worker] Timeout: {TIMEOUT}s, idle exit: {IDLE_EXIT}s")

# ── Import task functions (lazy — after Redis is up) ────────────────────
# Set LOCAL_SANDBOX_DEV so tasks don't try to spawn remote sandboxes
os.environ.setdefault("LOCAL_SANDBOX_DEV", "true")
os.environ.setdefault("INSIDE_SANDBOX_RUNNER", "true")

from celery_app import celery_app  # noqa: E402
import tasks  # noqa: E402 — imports register all @celery_app.task functions


def decode_celery_message(raw: bytes) -> dict | None:
    """
    Decode a Celery v2 protocol message from Redis.
    Returns {task_name, task_id, args, kwargs} or None on failure.
    """
    try:
        msg = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None

    body_b64 = msg.get("body")
    headers = msg.get("headers", {})

    if not body_b64:
        return None

    try:
        body_json = base64.b64decode(body_b64).decode("utf-8")
        body_data = json.loads(body_json)
        # Celery body: [args, kwargs, {}]
        task_args = body_data[0] if len(body_data) > 0 else []
        task_kwargs = body_data[1] if len(body_data) > 1 else {}
    except Exception:
        return None

    return {
        "task_name": headers.get("task", ""),
        "task_id": headers.get("id", ""),
        "args": task_args,
        "kwargs": task_kwargs,
    }


def run_task(task_name: str, args: list, kwargs: dict) -> bool:
    """
    Look up the registered Celery task and call its function directly.
    Returns True on success, False on failure.
    """
    try:
        task = celery_app.tasks.get(task_name)
    except Exception:
        print(f"[Worker] Task not found in registry: {task_name}")
        return False

    if task is None:
        print(f"[Worker] Task not registered: {task_name}")
        return False

    print(f"[Worker] Running task: {task_name} with args={args}, kwargs={kwargs}")
    try:
        # Call the underlying task function (not .delay() — that would
        # re-queue it; we want to run it synchronously right here)
        task_func = task.__call__
        result = task_func(*args, **kwargs)
        print(f"[Worker] Task completed: {task_name} → {result}")
        return True
    except Exception as exc:
        print(f"[Worker] Task failed: {task_name} → {exc}")
        import traceback
        traceback.print_exc()
        return False


def main():
    start_time = time.time()
    last_job_time = time.time()
    jobs_processed = 0

    while True:
        elapsed = time.time() - start_time
        idle_time = time.time() - last_job_time

        # Exit conditions
        if elapsed > TIMEOUT:
            print(f"[Worker] Timeout reached ({TIMEOUT}s). Exiting.")
            break
        if idle_time > IDLE_EXIT:
            print(f"[Worker] Queue idle for {IDLE_EXIT}s. Exiting.")
            break

        # Pull one job from queue (blocking with short timeout)
        result = r.blpop(QUEUE, timeout=5)
        if result is None:
            # No job available within timeout — keep waiting
            print(f"[Worker] No jobs in queue '{QUEUE}'. Waiting... ({int(idle_time)}s idle)")
            time.sleep(2)
            continue

        queue_name, raw_message = result
        last_job_time = time.time()

        decoded = decode_celery_message(raw_message)
        if decoded is None:
            print(f"[Worker] Failed to decode message. Skipping.")
            continue

        print(
            f"[Worker] Job pulled: {decoded['task_name']} "
            f"(id={decoded['task_id'][:8]}...) "
            f"at {datetime.utcnow().isoformat()}"
        )

        success = run_task(
            task_name=decoded["task_name"],
            args=decoded["args"],
            kwargs=decoded["kwargs"],
        )

        if success:
            jobs_processed += 1

    print(f"[Worker] Finished. Processed {jobs_processed} jobs in "
          f"{time.time() - start_time:.1f}s.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
