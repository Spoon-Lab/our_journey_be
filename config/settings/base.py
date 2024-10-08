import os
from datetime import timedelta
from pathlib import Path

import pymysql
import sentry_sdk

pymysql.install_as_MySQLdb()

BASE_DIR = Path(__file__).resolve().parent.parent.parent

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.sites",
    "corsheaders",
    "apps.authapp",
    "apps.photoapp",
    "allauth",
    "allauth.account",
    "allauth.socialaccount",
    "allauth.socialaccount.providers.google",
    "rest_framework",
    "rest_framework.authtoken",
    "rest_framework_simplejwt",
    "rest_framework_simplejwt.token_blacklist",
    "dj_rest_auth",
    "dj_rest_auth.registration",
    "drf_spectacular",
    # "drf_standardized_errors",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "allauth.account.middleware.AccountMiddleware",
]

ROOT_URLCONF = "config.urls"

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

SITE_ID = 6

AUTHENTICATION_BACKENDS = (
    "apps.authapp.custom_auth.EmailBackend",
    "django.contrib.auth.backends.ModelBackend",
    # "allauth.account.auth_backends.AuthenticationBackend",
)

# rest-auth 회원가입 필드 custom
REST_AUTH_REGISTER_SERIALIZERS = {
    "REGISTER_SERIALIZER": "apps.authapp.serializers.CustomRegisterSerializer",
}

# Allauth 설정
LOGIN_REDIRECT_URL = "/auth/google/callback/"
# 로그아웃 시
ACCOUNT_LOGOUT_REDIRECT_URL = "/"

AUTH_USER_MODEL = "authapp.User"

EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
# 로컬 테스트 시
# EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"

EMAIL_HOST = "smtp.gmail.com"
EMAIL_PORT = "587"

EMAIL_USE_TLS = True


ACCOUNT_CONFIRM_EMAIL_ON_GET = True  # 유저가 링크 클릭 시 회원가입 완료
ACCOUNT_USER_MODEL_USERNAME_FIELD = None
ACCOUNT_EMAIL_REQUIRED = True
ACCOUNT_USERNAME_REQUIRED = False
ACCOUNT_AUTHENTICATION_METHOD = "email"

# 회원가입 시 이메일 인증 강제
ACCOUNT_EMAIL_VERIFICATION = "mandatory"

# 사이트와 관련한 자동응답을 받을 이메일 주소,'webmaster@localhost'
EMAIL_CONFIRMATION_AUTHENTICATED_REDIRECT_URL = "/"

# 이메일 인증 만료 기간(일 기준)
ACCOUNT_EMAIL_CONFIRMATION_EXPIRE_DAYS = 1

ACCOUNT_EMAIL_SUBJECT_PREFIX = "아워 저니(Our Journey) "

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        # "dj_rest_auth.jwt_auth.JWTCookieAuthentication",
        "rest_framework_simplejwt.authentication.JWTAuthentication",  # JWT 인증 클래스 우선
    ],
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    # "EXCEPTION_HANDLER": "config.utils.custom_exception_handler",
}


REST_AUTH = {
    "USE_JWT": True,
    # 2차에 프론트 로그아웃 로직 쿠키로 변경하면 다시 주석 해제할 것
    # "JWT_AUTH_COOKIE": "access",
    # "JWT_AUTH_REFRESH_COOKIE": "refresh_token",
    # "JWT_AUTH_HTTPONLY": True,
    "SESSION_LOGIN": False,
}


SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(
        minutes=5
    ),  # Access 토큰 유효기간 (production에서는 더 짧게)
    "REFRESH_TOKEN_LIFETIME": timedelta(days=1),  # Refresh 토큰 유효기간
    "ROTATE_REFRESH_TOKENS": False,
    "BLACKLIST_AFTER_ROTATION": True,  # 이전에 사용된 Refresh 토큰을 블랙리스트에 추가
    "AUTH_COOKIE_SECURE": True,  # 프로덕션 환경에서는 반드시 True로 설정
    "AUTH_HEADER_TYPES": ("Bearer",),
    # "AUTH_COOKIE_HTTP_ONLY": True,  # 클라이언트 자바스크립트에서 접근 불가
    "AUTH_COOKIE_PATH": "/",  # 쿠키의 유효 경로
}

sentry_sdk.init(
    dsn="https://153978f09ca2a454959514196326bb34@o4508064670154752.ingest.us.sentry.io/4508064673955840",
    # Set traces_sample_rate to 1.0 to capture 100%
    # of transactions for tracing.
    traces_sample_rate=1.0,
    # Set profiles_sample_rate to 1.0 to profile 100%
    # of sampled transactions.
    # We recommend adjusting this value in production.
    profiles_sample_rate=1.0,
)

REST_AUTH_SERIALIZERS = {
    "TOKEN_SERIALIZER": "dj_rest_auth.serializers.JWTSerializer",
    "REGISTER_SERIALIZER": "apps.authapp.serializers.CustomRegisterSerializer",
    "LOGIN_SERIALIZER": "apps.authapp.serializers.CustomLoginSerializer",
}

SPECTACULAR_SETTINGS = {
    "TITLE": "Our Journey Auth API",
    "DESCRIPTION": "",
    "VERSION": "1.0.0",
    "SERVE_INCLUDE_SCHEMA": False,
    # OTHER SETTINGS
}

# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

S3_URI = "https://spoon-ourjourney.s3.ap-northeast-2.amazonaws.com"

# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = "ko-kr"

TIME_ZONE = "Asia/Seoul"

USE_I18N = True

USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL = "static/"

MEDIA_URL = "/media/"
MEDIA_ROOT = os.path.join(BASE_DIR, "media")

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
