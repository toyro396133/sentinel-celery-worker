import os
from celery import Celery
from celery.schedules import crontab
from kombu import Queue, Exchange

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
celery_app = Celery("tasks", broker=REDIS_URL, backend=REDIS_URL)

# Configure task queues with explicit exchange mapping and autoprovisioning
celery_app.conf.task_queues = (
    Queue("fast_network_scans", Exchange("fast_network_scans"), routing_key="fast_network_scans"),
    Queue("heavy_sast_scans", Exchange("heavy_sast_scans"), routing_key="heavy_sast_scans"),
    Queue("periodic_cron_scans", Exchange("periodic_cron_scans"), routing_key="periodic_cron_scans"),
)
celery_app.conf.task_create_missing_queues = True

# Dynamic Scheduled Auditing Configuration (Celery Beat Schedule)
celery_app.conf.beat_schedule = {
    "weekly-automated-audits": {
        "task": "celery-worker.tasks.auto_schedule_re_scans",
        "schedule": crontab(day_of_week="sunday", hour=0, minute=0), # Every Sunday at Midnight
    },
    "daily-sla-compliance-check": {
        "task": "celery-worker.tasks.check_and_alert_sla_breaches",
        "schedule": crontab(hour=1, minute=0),                     # Every day at 1:00 AM
    }
}
