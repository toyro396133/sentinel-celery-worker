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
# NOTE: keep the scheme as-is. Upstash requires TLS on the socket endpoint
# (rediss://...), so stripping rediss→redis would break the connection.
# redis-py >= 5 supports rediss:// natively; ssl_cert_reqs=None is fine for
# the managed certs Upstash serves.
if REDIS_URL.startswith(("http://", "https://")):
    raise SystemExit(
        "[Worker] REDIS_URL is an Upstash REST URL — the worker needs the "
        "socket URL (rediss://default:<token>@<endpoint>:6379) instead."
    )

r = None


def connect_redis():
    """Open a fresh Redis connection and verify it responds.

    Upstash serves rediss:// over TLS and closes idle sockets, so a
    long-running scan can outlive the connection (next command raises
    TimeoutError). The worker therefore reconnects after every job instead
    of reusing a stale socket.
    """
    global r
    r = redis.Redis.from_url(
        REDIS_URL,
        ssl_cert_reqs=None,
        socket_timeout=30,
        socket_connect_timeout=10,
        retry_on_timeout=True,
    )
    r.ping()
    print(f"[Worker] Connected to Redis. Listening on queue: {QUEUE}")
    return r


connect_redis()
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


CELERY_RESULT_KEY_PREFIX = "celery-task-meta-"


def write_result_meta(task_id: str, status: str, result=None, traceback_str: str = None):
    """
    Write the Celery result-backend meta key (celery-task-meta-<id>) so the
    Next.js polling endpoint (getCeleryTaskResult) sees SUCCESS/FAILURE
    instead of PENDING. Without this, public scan jobs would hang at PENDING
    forever even after the task runs to completion.
    """
    if not task_id:
        return
    meta = {"status": status, "result": result, "traceback": traceback_str}
    try:
        # TTL 24h: long enough for the polling window, short enough to avoid
        # unbounded key growth in the shared Redis instance.
        r.set(f"{CELERY_RESULT_KEY_PREFIX}{task_id}", json.dumps(meta, default=str), ex=86400)
        print(f"[Worker] Wrote result meta for {task_id}: {status}")
    except Exception as exc:
        print(f"[Worker] Failed to write result meta for {task_id}: {exc}")


def run_task(task_name: str, args: list, kwargs: dict, task_id: str = None) -> tuple:
    """
    Look up the registered Celery task and call its function directly.
    Returns (success: bool, result_value) so callers can persist the
    Celery result-backend meta.
    """
    try:
        task = celery_app.tasks.get(task_name)
    except Exception:
        print(f"[Worker] Task not found in registry: {task_name}")
        return False, None

    if task is None:
        print(f"[Worker] Task not registered: {task_name}")
        return False, None

    print(f"[Worker] Running task: {task_name} with args={args}, kwargs={kwargs}")
    try:
        # Call the underlying task function (not .delay() — that would
        # re-queue it; we want to run it synchronously right here)
        task_func = task.__call__
        result = task_func(*args, **kwargs)
        print(f"[Worker] Task completed: {task_name}")
        write_result_meta(task_id, "SUCCESS", result=result)
        return True, result
    except Exception as exc:
        print(f"[Worker] Task failed: {task_name} → {exc}")
        import traceback
        traceback.print_exc()
        write_result_meta(task_id, "FAILURE", traceback_str=traceback.format_exc())
        return False, None


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

        # Ensure a live connection (fresh socket — Upstash closes idle TLS
        # connections, so a stale one raises TimeoutError on the next poll).
        if r is None:
            try:
                connect_redis()
            except Exception as exc:
                print(f"[Worker] Initial connect failed: {exc}. Retrying in 5s...")
                time.sleep(5)
                continue

        # Pull one job from queue (blocking with short timeout)
        try:
            result = r.blpop(QUEUE, timeout=5)
        except redis.RedisError as exc:
            print(f"[Worker] Redis poll error: {exc}. Reconnecting...")
            try:
                r.close()
            except Exception:
                pass
            r = None
            continue

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

        # Fresh connection for task execution + meta write: the BLPOP above
        # may have run on a socket that dies during a long scan.
        try:
            r.close()
        except Exception:
            pass
        try:
            connect_redis()
        except Exception as exc:
            print(f"[Worker] Pre-task reconnect failed: {exc}")
            r = None

        success, _result = run_task(
            task_name=decoded["task_name"],
            args=decoded["args"],
            kwargs=decoded["kwargs"],
            task_id=decoded["task_id"],
        )

        if success:
            jobs_processed += 1

    print(f"[Worker] Finished. Processed {jobs_processed} jobs in "
          f"{time.time() - start_time:.1f}s.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
