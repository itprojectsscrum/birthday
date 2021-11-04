from django.core import mail
from django.core.mail import EmailMessage
from mock import patch
from unittest import TestCase

from ..utils import Util, EmailThread


class TestSendEmail(TestCase):

    def test_send_message(self):
        data = {
            'email_subject': "Test email",
            'email_body': "Test message",
            'to_email': "to@email.com",
        }
        with patch.object(Util, 'send_email') as mock_email:
            thing = Util()
            thing.send_email(data)
        mock_email.assert_called_once_with(
            {'email_subject': 'Test email', 'email_body': 'Test message', 'to_email': 'to@email.com'}
        )

    def test_send_email(self):
        data = {
            'email_subject': "Test email",
            'email_body': "Test message",
            'to_email': "to@email.com",
        }
        email = EmailThread(
            EmailMessage(
                subject=data['email_subject'],
                body=data['email_body'],
                to=[data['to_email']]
            )
        )
        email.start()

        assert len(mail.outbox) == 1, "Inbox is not empty"
        assert mail.outbox[0].subject == data['email_subject']
        assert mail.outbox[0].body == data['email_body']
        assert mail.outbox[0].to == [data['to_email']]
