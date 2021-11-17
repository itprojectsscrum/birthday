# pull official base image
FROM python:3.8

# set work directory
WORKDIR /usr/src/app

# set environment variables
ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1

# install dependencies
RUN apt-get -y clean && apt-get -y update \
  # dependencies for building Python packages
  && apt-get install -y build-essential \
  # psycopg2 dependencies
  && apt-get install -y libpq-dev \
  # Translations dependencies
  && apt-get install -y gettext \
  # Additional dependencies
  && apt-get install -y procps telnet \
  # cleaning up unused files
  && apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
  && rm -rf /var/lib/apt/lists/*

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

# copy project
COPY ./compose/local/django/entrypoint /entrypoint
RUN chmod +x /entrypoint

COPY ./compose/local/django/start /start
RUN chmod +x /start

COPY ./compose/local/django/celery/worker/start /start-celeryworker
RUN chmod +x /start-celeryworker

COPY ./compose/local/django/celery/beat/start /start-celerybeat
RUN chmod +x /start-celerybeat

COPY ./compose/local/django/celery/flower/start /start-flower
RUN chmod +x /start-flower

WORKDIR /app

ENTRYPOINT ["/entrypoint"]