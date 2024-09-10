from .base import *

import environ

env = environ.Env(DEBUG=(bool, False))

# 환경변수 파일 읽어오기
environ.Env.read_env(env_file=os.path.join(BASE_DIR, ".env"))

SECRET_KEY = env("DJANGO_SECRET_KEY")

MYSQL_PASSWORD = env("MYSQL_PASSWORD")

DEBUG = True
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
        "HOST": "localhost",  # MySQL 컨테이너 이름
        "PORT": "3306",
    },
    "external_db": {
        "ENGINE": "django.db.backends.mysql",  # 외부 DB 엔진
        "NAME": "ourjourney_main_db",
        "USER": "root",
        "PASSWORD": "root1234",
        "HOST": "mysql_service",  # 외부 DB의 호스트 주소
        "PORT": "3306",  # 외부 DB 포트
    },
}


if DEBUG:
    STATICFILES_DIRS = [
        os.path.join(BASE_DIR, "static"),
    ]
else:
    STATIC_ROOT = os.path.join(BASE_DIR, "static")
