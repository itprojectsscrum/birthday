from django.conf.urls import url

from polls import consumer

urlpatterns = [
    url(r'^ws/task_status/(?P<task_id>[\w-]+)/?$', consumer.TaskStatusConsumer.as_asgi()),
]