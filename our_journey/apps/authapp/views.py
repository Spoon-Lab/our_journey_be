import requests
from allauth.account.models import (
    EmailConfirmation,
    EmailConfirmationHMAC,
    EmailAddress,
)
from dj_rest_auth.views import LoginView
from django.conf import settings
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.db import connections
from django.http import JsonResponse, HttpResponseRedirect
from django.shortcuts import redirect
import jwt
from drf_spectacular.utils import extend_schema, OpenApiExample, OpenApiResponse
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils.translation import gettext_lazy as _

from .serializers import CustomLoginSerializer, JWTResponseSerializer


class CustomLoginView(LoginView):
    permission_classes = (AllowAny,)
    serializer_class = CustomLoginSerializer

    def get_response(self):
        data = {
            "access": str(self.access_token),
            "refresh": str(self.refresh_token),
            "user": {
                "pk": self.user.pk,
                "email": self.user.email,
            },
        }

        return Response(data, status=status.HTTP_200_OK)

    @extend_schema(
        responses={
            200: OpenApiResponse(
                response=JWTResponseSerializer, description="JWT login response"
            ),
            400: OpenApiResponse(description="Invalid credentials or validation error"),
            403: OpenApiResponse(
                description="Email verification is required to log in."
            ),
        },
    )
    def post(self, request, *args, **kwargs):
        self.request = request
        self.serializer = self.get_serializer(data=self.request.data)
        self.serializer.is_valid(raise_exception=True)

        self.login()
        # admin 계정이 아니고, 인증 메일 확인하기 전이면 403
        if (
            not self.request.user.is_superuser
            and EmailAddress.objects.filter(
                email=self.user.email, verified=False
            ).exists()
        ):
            return Response(
                {"detail": _("Email verification is required to log in.")},
                status=status.HTTP_403_FORBIDDEN,  # Forbidden 응답
            )

        return self.get_response()


class GoogleAuthenticateAPIView(APIView):
    def post(self, request):
        token = request.data.get("token")

        try:
            # 구글 토큰 검증
            idinfo = id_token.verify_oauth2_token(
                token, google_requests.Request(), GOOGLE_CLIENT_ID
            )

            # 구글 사용자 ID 및 이메일 추출
            google_user_id = idinfo["sub"]
            email = idinfo.get("email")
            name = idinfo.get("name")

            # 이미 있는 사용자인지 확인, 없으면 생성
            user, created = User.objects.get_or_create(
                email=email, defaults={"username": email, "first_name": name}
            )

            if created:
                # 새로운 사용자 생성 시 추가 작업 (예: 권한 설정)
                user.set_unusable_password()  # 비밀번호 없이 소셜 로그인으로만 로그인 가능하게 설정
                user.save()

            # JWT 발급 또는 사용자 정보 응답
            return Response(
                {
                    "message": "User authenticated successfully",
                    "user_id": user.id,
                    "email": user.email,
                    "username": user.username,
                }
            )

        except ValueError:
            return Response({"error": "Invalid token"}, status=400)


@login_required
def auth_redirect_view(request):
    user = request.user

    # JWT 토큰 생성
    refresh = RefreshToken.for_user(user)
    access_token = str(refresh.access_token)
    refresh_token = str(refresh)

    context = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user_id": user.id,
    }
    return JsonResponse(context)


class UserAuthenticationView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        token = request.auth  # 요청에서 Bearer 토큰 값

        # 첫 번째 케이스: 토큰이 없을 때
        if token is None:
            return JsonResponse(
                {
                    "error": "Token is missing",
                    "authentication": False,
                    "authorization": "",
                },
                status=401,
            )

        # 두 번째 케이스: 토큰은 있지만 연관된 user_id가 없을 때
        if not user.is_authenticated:
            return JsonResponse(
                {
                    "error": "Invalid token or user not found",
                    "authentication": False,
                    "authorization": "",
                },
                status=401,
            )

        # authorization 필드 설정: 관리자 여부에 따라 값 설정
        authorization_status = "admin" if user.is_staff else "general"

        response_data = {
            "user_id": user.id,
            "email": user.email,
            "authentication": True,
            "authorization": authorization_status,
        }
        return JsonResponse(response_data)


class ConfirmEmailView(APIView):
    permission_classes = [AllowAny]

    def get(self, *args, **kwargs):
        self.object = confirmation = self.get_object()
        confirmation.confirm(self.request)

        return HttpResponseRedirect(redirect_to="/#/email-confirmed")

    def get_object(self, queryset=None):
        key = self.kwargs["key"]
        email_confirmation = EmailConfirmationHMAC.from_key(key)
        if not email_confirmation:
            if queryset is None:
                queryset = self.get_queryset()
            try:
                email_confirmation = queryset.get(key=key.lower())
            except EmailConfirmation.DoesNotExist:
                # A React Router Route will handle the failure scenario
                # return Response({"detail":"login fail"})
                return HttpResponseRedirect(redirect_to="/")
        return email_confirmation

    def get_queryset(self):
        qs = EmailConfirmation.objects.all_valid()
        qs = qs.select_related("email_address__user")
        return qs


class AdminCategoryAPIView(APIView):
    permission_classes = [IsAdminUser]  # Django Admin 계정만 접근 가능

    @extend_schema(
        request={
            "application/json": {
                "type": "object",
                "properties": {"category_name": {"type": "string"}},
            }
        },
        responses={
            201: OpenApiResponse(description="Category created successfully."),
            400: OpenApiResponse(description="Invalid credentials or validation error"),
            403: OpenApiResponse(description="This action is not permitted."),
        },
    )
    def post(self, request):
        category_name = request.data.get("category_name")

        # name 값이 없으면 에러 처리
        if not category_name:
            return Response(
                {"detail": "Category name is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            # 외부 DB에 새로운 카테고리 추가
            with connections["external_db"].cursor() as cursor:
                cursor.execute(
                    "INSERT INTO category (name) VALUES (%s)", [category_name]
                )

            return Response(
                {"detail": f"Category '{category_name}' created successfully."},
                status=status.HTTP_201_CREATED,
            )
        except Exception as e:
            return Response(
                {"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
