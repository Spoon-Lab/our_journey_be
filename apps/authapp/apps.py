from django.apps import AppConfig
from django.contrib.auth import get_user_model
from django.db.models.signals import post_migrate


def create_superuser(sender, **kwargs):
    User = get_user_model()
    password = "adminpassword"

    # 슈퍼유저가 존재하지 않는 경우에만 새 슈퍼유저 생성
    if not User.objects.filter(is_superuser=True).exists():
        User.objects.create_superuser(email="admin@example.com", password=password)
        print("Superuser created with email: admin@example.com")
    else:
        print("Superuser already exists.")


class AuthappConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.authapp"

    # 마이그레이션 후 자동으로 슈퍼유저를 생성하도록 ready 메서드에 신호 연결
    def ready(self):
        post_migrate.connect(create_superuser, sender=self)
