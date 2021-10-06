release: python manage.py makemigrations --no-input
release: python manage.py migrate --no-input

web: gunicorn birthday_1.wsgi

worker: celery -A birthday_1 worker -events -loglevel info --pool=solo
beat: celery -A birthday_1 beat