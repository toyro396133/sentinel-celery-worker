"""
Celery task dispatcher invoked by Node.js (celery-client.ts).
Usage: python dispatch.py <task_name> <json_args> [json_kwargs]
"""
import sys
import json
import os

os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")

from celery_app import celery_app  # noqa: E402


def main():
    if len(sys.argv) < 3:
        print(json.dumps({"ok": False, "error": "Usage: dispatch.py <task_name> <json_args> [json_kwargs]"}))
        sys.exit(1)

    task_name = sys.argv[1]
    args = json.loads(sys.argv[2]) if len(sys.argv) > 2 else []
    kwargs = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}

    # Resolve queue from the registered Celery task (avoids duplicating the
    # queue= declarations on the @celery_app.task decorators in tasks.py).
    try:
        queue = celery_app.tasks[task_name].queue
    except (KeyError, AttributeError):
        queue = "fast_network_scans"

    try:
        result = celery_app.send_task(task_name, args=args, kwargs=kwargs, queue=queue)
        print(json.dumps({"ok": True, "taskId": result.id}))
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        sys.exit(1)


if __name__ == "__main__":
    main()
