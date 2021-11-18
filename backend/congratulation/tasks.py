from django.conf import settings
from celery import shared_task
from datetime import datetime, timedelta

from authentication.utils import Util
from .models import Congratulate


@shared_task
def to_schedule():
    congratulates = Congratulate.objects. \
        filter(alert_datetime__gte=datetime.now()). \
        filter(alert_datetime__lt=datetime.now() + timedelta(minutes=1))  # As app.conf.beat_schedule
    for congratulate in congratulates:
        # import logging
        # logger = logging.getLogger(__name__)
        # logger.info(f'{congratulate.owner.is_verified=} {congratulate.notify_by_email=} {congratulate.bday_name=} {congratulate.comment=} {congratulate.owner.email=}')
        if congratulate:
            if congratulate.owner.is_verified and congratulate.notify_by_email:
                email_send.apply_async(
                    args=(
                        f'Congratulate {congratulate.bday_name}',
                        f'Congratulate {congratulate.bday_name}. \nComment: {congratulate.comment}',
                        congratulate.owner.email
                    ),
                    eta=congratulate.alert_datetime
                )


@shared_task
def email_send(subject, body, to):
    data = {
        'email_subject': subject,
        'email_body': body,
        'to_email': to
    }

    print(f' send email {data=}')
    Util.send_email(data)
