from allauth.account.adapter import get_adapter
from dj_rest_auth.registration.serializers import RegisterSerializer
from dj_rest_auth.serializers import LoginSerializer
from django.contrib.auth import authenticate
from rest_framework import serializers
from django.utils.translation import gettext_lazy as _
from .models import User


class CustomRegisterSerializer(RegisterSerializer):
    username = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # 폼에서 username 필드 제거
        if "username" in self.fields:
            self.fields.pop("username")

    def get_cleaned_data(self):
        return {
            "email": self.validated_data.get("email", ""),
            "password1": self.validated_data.get("password1", ""),
        }

    def save(self, request):
        adapter = get_adapter()
        user = adapter.new_user(request)
        self.cleaned_data = self.get_cleaned_data()
        print(self.cleaned_data)
        user = adapter.save_user(request, user, self, commit=False)
        if "password1" in self.cleaned_data:
            try:
                adapter.clean_password(self.cleaned_data["password1"], user=user)
            except DjangoValidationError as exc:
                raise serializers.ValidationError(
                    detail=serializers.as_serializer_error(exc)
                )
        user.save()
        self.custom_signup(request, user)
        setup_user_email(request, user, [])
        return user


class CustomLoginSerializer(LoginSerializer):
    username = None  # username 필드를 비활성화
    email = serializers.EmailField(required=True, allow_blank=False)

    def validate(self, attrs):
        # email과 password로 사용자 인증 처리
        email = attrs.get("email")
        password = attrs.get("password")

        if email and password:
            user = authenticate(
                request=self.context.get("request"), email=email, password=password
            )
            print(user)

            if not user:
                # 사용자 객체가 없으면 자격 증명이 잘못된 것
                if User.objects.filter(email=email).exists():
                    raise serializers.ValidationError(
                        {"password": _("Incorrect password. Please try again.")}
                    )
                else:
                    raise serializers.ValidationError(
                        {"email": _("No account found with this email address.")}
                    )
        else:
            raise serializers.ValidationError(_('Must include "email" and "password".'))

        attrs["user"] = user
        return attrs


class UserSerializer(serializers.Serializer):
    pk = serializers.IntegerField()
    email = serializers.EmailField()


class JWTResponseSerializer(serializers.Serializer):
    access = serializers.CharField()
    refresh = serializers.CharField(allow_blank=True, required=False)
    user = UserSerializer()


class UserCertificateSerializer(serializers.Serializer):
    user_id = serializers.IntegerField()
    email = serializers.EmailField()
    authentication = serializers.BooleanField()
    authorization = serializers.ChoiceField(
        choices=[("admin", "Admin"), ("general", "General")]
    )
