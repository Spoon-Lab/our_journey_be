import environ

from .base import *

env = environ.Env(DEBUG=(bool, False))


DEBUG = False

# 환경변수 파일 읽어오기
environ.Env.read_env(env_file=os.path.join(BASE_DIR, ".env"))

SECRET_KEY = env("DJANGO_SECRET_KEY")

MYSQL_PASSWORD = env("MYSQL_PASSWORD")
MYSQL_HOST = env("MYSQL_HOST")

ALLOWED_HOSTS = ["3.38.47.219", "127.0.0.1"]


CSRF_TRUSTED_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:8000",
    "http://localhost:8080",
    "http://127.0.0.1:8000",
]

CORS_ALLOW_CREDENTIALS = True

CORS_ALLOW_METHODS = ["GET", "POST", "PUT", "HEAD", "OPTIONS", "DELETE"]

CORS_ORIGIN_ALLOW_ALL = True

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.mysql",
        "NAME": "ourjourney_auth_db",
        "USER": "root",
        "PASSWORD": MYSQL_PASSWORD,
        "HOST": MYSQL_HOST,
        "PORT": "3306",
    },
    "main_db": {
        "ENGINE": "django.db.backends.mysql",
        "NAME": "ourjourney_main_db",
        "USER": "root",
        "PASSWORD": MYSQL_PASSWORD,
        "HOST": MYSQL_HOST,
        "PORT": "3306",
    },
}

CLIENT_ID = env("CLIENT_ID")
GOOGLE_SECRET = env("GOOGLE_SECRET")
EMAIL_HOST_USER = env("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = env("EMAIL_HOST_PASSWORD")
DEFAULT_FROM_EMAIL = EMAIL_HOST_USER

S3_BUCKET_NAME = env("S3_BUCKET_NAME")
S3_ACCESS_KEY = env("S3_ACCESS_KEY")
S3_SECRET_KEY = env("S3_SECRET_KEY")

# 구글 OAuth2 설정
SOCIALACCOUNT_PROVIDERS = {
    "google": {
        "SCOPE": ["profile", "email"],
        "AUTH_PARAMS": {"access_type": "online"},
        "CLIENT_ID": CLIENT_ID,
        "SECRET": GOOGLE_SECRET,
    }
}

if DEBUG:
    STATICFILES_DIRS = [
        os.path.join(BASE_DIR, "static"),
    ]
else:
    STATIC_ROOT = os.path.join(BASE_DIR, "static")
