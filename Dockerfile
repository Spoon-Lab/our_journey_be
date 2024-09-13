FROM python:3.12

# 필요한 패키지 설치 및 wait-for-it.sh 다운로드
RUN apt-get update && apt-get install -y curl

# wait-for-it.sh 스크립트를 다운로드하고 실행 권한 부여
RUN curl -o /wait-for-it.sh https://raw.githubusercontent.com/vishnubob/wait-for-it/master/wait-for-it.sh && \
    chmod +x /wait-for-it.sh

COPY requirements.txt /requirements.txt
RUN pip3 install -r requirements.txt

WORKDIR /home/our_journey/
COPY . .

EXPOSE 8000

# MySQL이 준비될 때까지 대기 후 Django 명령어
CMD ["bash", "-c", "/wait-for-it.sh mysql_service:3306 -- python3 manage.py collectstatic --noinput --settings=config.settings.local &&\
     python3 manage.py migrate --settings=config.settings.local &&\
     gunicorn config.wsgi --env DJANGO_SETTINGS_MODULE=config.settings.local --bind 0.0.0.0:8000 --workers=3 --timeout 180"]

