release: python manage.py makemigrations --no-input
release: python manage.py migrate --no-input

web: gunicorn birthday.wsgi

worker: celery -A birthday worker -events -loglevel info --pool=solo
beat: celery -A birthday beat