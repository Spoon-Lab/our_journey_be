from .base import *
from .manage_secret.local import read_env

DEBUG = True

ALLOWED_HOSTS = ["*"]

env = read_env(base_dir=BASE_DIR)

SECRET_KEY = env["DJANGO_SECRET_KEY"]

CSRF_TRUSTED_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]

CORS_ALLOW_CREDENTIALS = True

CORS_ALLOW_METHODS = ["GET", "POST", "PUT", "HEAD", "OPTIONS", "DELETE"]

CORS_ORIGIN_ALLOW_ALL = True

DB_PASSWORD = env["DB_PASSWORD"]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.mysql",
        "NAME": "ourjourney_authdb",
        "USER": "root",
        "PASSWORD": DB_PASSWORD,
        "HOST": "127.0.0.1",
        "PORT": "3306",
    }
}


if DEBUG:
    STATICFILES_DIRS = [
        os.path.join(BASE_DIR, "static"),
    ]
else:
    STATIC_ROOT = os.path.join(BASE_DIR, "static")
