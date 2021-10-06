import os

from celery import Celery

# Set the default Django settings module for the 'celery' program.
from django.conf import settings

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'birthday_1.settings')

app = Celery('birthday_1')

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
# - namespace='CELERY' means all celery-related configuration keys
#   should have a `CELERY_` prefix.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django apps.
app.autodiscover_tasks(lambda: settings.INSTALLED_APPS)


app.conf.beat_schedule = {
    'congratulate_to_schedule': {
        'task': 'congratulation.tasks.to_schedule',
        'schedule': 300.0
    }
}
