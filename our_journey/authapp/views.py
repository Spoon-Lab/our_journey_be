import requests
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import redirect
import jwt
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken


@login_required
def auth_redirect_view(request):
    user = request.user

    # JWT 토큰 생성
    refresh = RefreshToken.for_user(user)
    access_token = str(refresh.access_token)
    refresh_token = str(refresh)

    # 필요한 경우 이 토큰을 템플릿에 전달하거나 JSON 응답으로 반환할 수 있습니다.
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
        authorization_status = "admin" if user.is_staff else ""

        response_data = {
            "user_id": user.id,
            "authentication": True,
            "authorization": authorization_status,
        }
        return JsonResponse(response_data)
