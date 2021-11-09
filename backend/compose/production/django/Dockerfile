FROM python:3.8

ENV PYTHONUNBUFFERED 1

RUN apt-get update \
  # dependencies for building Python packages
  && apt-get install -y build-essential netcat \
  # psycopg2 dependencies
  && apt-get install -y libpq-dev \
  # Translations dependencies
  && apt-get install -y gettext \
  # cleaning up unused files
  && apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
  && rm -rf /var/lib/apt/lists/*

RUN addgroup --system django \
    && adduser --system --ingroup django django

# Requirements are installed here to ensure they will be cached.
COPY ./requirements.txt /requirements.txt
RUN apt-get -y clean && apt-get -y update \
  && apt-get install -y python3-brlapi \
  && apt-get install -y command-not-found \
  && apt-get install -y python3-cupshelpers \
  && apt-get install -y distro-info-data \
  && apt-get install -y duplicity \
  && apt-get install -y python3-louis \
  && apt-get install -y openshot-qt \
  && apt-get install -y python3-apt \
  && apt-get install -y python3-debian \
  && apt-get install -y python3-sip \
  && apt-get install -y python3-systemd \
  && apt-get install -y ufw \
  && apt-get install -y unattended-upgrades \
  && apt-get install -y zlib1g-dev \
  && apt-get install -y libcups2-dev \
  && /usr/local/bin/python -m pip install --upgrade pip \
  && pip install -r /requirements.txt

COPY ./compose/production/django/entrypoint /entrypoint
RUN chmod +x /entrypoint
RUN chown django /entrypoint

COPY ./compose/production/django/start /start
RUN chmod +x /start
RUN chown django /start

COPY ./compose/production/django/celery/worker/start /start-celeryworker
RUN chmod +x /start-celeryworker
RUN chown django /start-celeryworker

COPY ./compose/production/django/celery/beat/start /start-celerybeat
RUN chmod +x /start-celerybeat
RUN chown django /start-celerybeat

COPY ./compose/production/django/celery/flower/start /start-flower
RUN chmod +x /start-flower

RUN mkdir /app

WORKDIR /app

# copy project code
COPY . .

RUN chown -R django:django /app

USER django

ENTRYPOINT ["/entrypoint"]