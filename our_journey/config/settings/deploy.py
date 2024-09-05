import os

from .base import *
from .manage_secret.local import read_env

DEBUG = False

ALLOWED_HOSTS = [
    "127.0.0.1",
    "43.200.104.224",
]

# CORS 관련 추가
CSRF_TRUSTED_ORIGINS = [
    "http://localhost:3000",
]

CORS_ALLOW_CREDENTIALS = True

CORS_ORIGIN_WHITELIST = [
    "http://localhost:3000",
]

SECURE_CROSS_ORIGIN_OPENER_POLICY = None

env = read_env(base_dir=BASE_DIR)

SECRET_KEY = env["DJANGO_SECRET_KEY"]

MYSQL_PASSWORD = env["MYSQL_PASSWORD"]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.mysql",
        "NAME": "ourjourney_authdb",
        "USER": "root",
        "PASSWORD": MYSQL_PASSWORD,
        "HOST": "host.docker.internal",
        "PORT": "3306",
    }
}

if DEBUG:
    STATICFILES_DIRS = [
        os.path.join(BASE_DIR, "static"),
    ]
else:
    STATIC_ROOT = os.path.join(BASE_DIR, "static")
