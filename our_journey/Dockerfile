FROM python:3.12

COPY ./requirements.txt /requirements.txt
RUN pip3 install --trusted-host pypi.python.org -r requirements.txt

WORKDIR /home/our_journey/
COPY . .

EXPOSE 8000

CMD ["bash", "-c", "python3 manage.py collectstatic --noinput --settings=config.settings.deploy &&\
     python3 manage.py migrate --settings=config.settings.deploy &&\
     gunicorn config.wsgi --env DJANGO_SETTINGS_MODULE=config.settings.deploy --bind 0.0.0.0:8000 --workers=3 --timeout 180"]
