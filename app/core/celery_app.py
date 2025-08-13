from celery import Celery
from kombu import Exchange, Queue
import os

from app.core.config import settings

# Create Celery instance
celery_app = Celery(
    "fastapi_clerk_auth",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=[
        "app.tasks.email_tasks",
        "app.tasks.user_tasks",
        "app.tasks.analytics_tasks",
        "app.tasks.export_tasks",
        "app.tasks.cleanup_tasks"
    ]
)

# Configure Celery
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=30 * 60,  # 30 minutes
    task_soft_time_limit=25 * 60,  # 25 minutes
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=1000,
    result_expires=3600,
    
    # Task routing
    task_routes={
        "app.tasks.email_tasks.*": {"queue": "email"},
        "app.tasks.user_tasks.*": {"queue": "user"},
        "app.tasks.analytics_tasks.*": {"queue": "analytics"},
        "app.tasks.export_tasks.*": {"queue": "export"},
        "app.tasks.cleanup_tasks.*": {"queue": "cleanup"}
    },
    
    # Queue configuration
    task_queues=(
        Queue("default", Exchange("default"), routing_key="default"),
        Queue("email", Exchange("email"), routing_key="email"),
        Queue("user", Exchange("user"), routing_key="user"),
        Queue("analytics", Exchange("analytics"), routing_key="analytics"),
        Queue("export", Exchange("export"), routing_key="export"),
        Queue("cleanup", Exchange("cleanup"), routing_key="cleanup"),
    ),
    
    # Beat schedule for periodic tasks
    beat_schedule={
        "cleanup-expired-sessions": {
            "task": "app.tasks.cleanup_tasks.cleanup_expired_sessions",
            "schedule": 3600.0,  # Every hour
        },
        "cleanup-expired-tokens": {
            "task": "app.tasks.cleanup_tasks.cleanup_expired_tokens",
            "schedule": 1800.0,  # Every 30 minutes
        },
        "process-analytics": {
            "task": "app.tasks.analytics_tasks.process_daily_analytics",
            "schedule": 86400.0,  # Daily
        },
        "cleanup-old-notifications": {
            "task": "app.tasks.cleanup_tasks.cleanup_old_notifications",
            "schedule": 86400.0,  # Daily
        },
        "check-suspicious-activity": {
            "task": "app.tasks.user_tasks.check_suspicious_activity",
            "schedule": 300.0,  # Every 5 minutes
        }
    }
)

# Set Redis configuration for better performance
celery_app.conf.broker_transport_options = {
    "visibility_timeout": 3600,
    "fanout_prefix": True,
    "fanout_patterns": True,
    "socket_keepalive": True,
    "socket_keepalive_options": {
        1: 3,  # TCP_KEEPIDLE
        2: 3,  # TCP_KEEPINTVL
        3: 3,  # TCP_KEEPCNT
    }
}