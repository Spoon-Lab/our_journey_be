from .base import *
from .manage_secret.local import read_env

import environ

env = environ.Env(DEBUG=(bool, False))

# 환경변수 파일 읽어오기
environ.Env.read_env(env_file=os.path.join(BASE_DIR, ".env"))

SECRET_KEY = env("DJANGO_SECRET_KEY")

MYSQL_PASSWORD = env("MYSQL_PASSWORD")

DEBUG = False

ALLOWED_HOSTS = ["*"]


CSRF_TRUSTED_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]

CORS_ALLOW_CREDENTIALS = True

CORS_ALLOW_METHODS = ["GET", "POST", "PUT", "HEAD", "OPTIONS", "DELETE"]

CORS_ORIGIN_ALLOW_ALL = True

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.mysql",
        "NAME": "ourjourney_authdb",
        "USER": "root",
        "PASSWORD": MYSQL_PASSWORD,
        "HOST": "mysql_service",  # MySQL 컨테이너 이름
        "PORT": "3306",
    }
}


if DEBUG:
    STATICFILES_DIRS = [
        os.path.join(BASE_DIR, "static"),
    ]
else:
    STATIC_ROOT = os.path.join(BASE_DIR, "static")
