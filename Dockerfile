FROM python:3.12

# 필요한 패키지 설치
RUN apt-get update && apt-get install -y curl

# Python 패키지 설치
COPY requirements.txt /requirements.txt
RUN pip3 install -r requirements.txt

WORKDIR /home/our_journey/
COPY . .

EXPOSE 8000

# Django 명령어
CMD ["bash", "-c", "python3 manage.py collectstatic --noinput --settings=config.settings.local &&\
     python3 manage.py migrate --settings=config.settings.local &&\
     gunicorn config.wsgi --env DJANGO_SETTINGS_MODULE=config.settings.local --bind 0.0.0.0:8000 --workers=5 --timeout 180"]

