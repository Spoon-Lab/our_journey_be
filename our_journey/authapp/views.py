import requests
from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import redirect
import jwt
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication

from our_journey.config.settings.base import CLIENT_ID, GOOGLE_SECRET


def get_google_access_token(code):
    token_url = "https://oauth2.googleapis.com/token"
    redirect_uri = "http://127.0.0.1:8000/accounts/google/login/callback/"  # Google OAuth 설정에서 지정한 redirect URI와 동일해야 합니다.
    token_data = {
        "code": code,
        "client_id": CLIENT_ID,
        "client_secret": GOOGLE_SECRET,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }

    token_response = requests.post(token_url, data=token_data)
    token_response_json = token_response.json()

    return token_response_json  # access_token 및 id_token 포함


def decode_google_jwt(id_token):
    try:
        decoded_token = jwt.decode(id_token, options={"verify_signature": False})
        return decoded_token
    except jwt.ExpiredSignatureError:
        return None
    except jwt.DecodeError:
        return None


def google_callback(request):
    code = request.GET.get("code")
    if not code:
        return JsonResponse({"error": "No code provided"}, status=400)

    token_data = get_google_access_token(code)

    id_token = token_data.get("id_token")
    access_token = token_data.get("access_token")

    if not id_token:
        return JsonResponse({"error": "Failed to retrieve ID token"}, status=400)

    decoded_token = decode_google_jwt(id_token)
    if not decoded_token:
        return JsonResponse({"error": "Failed to decode ID token"}, status=400)

    # 여기에서 사용자 정보를 확인하고 세션이나 쿠키를 설정하거나, 사용자 계정을 생성할 수 있습니다.
    # 예: 이메일 정보 추출
    email = decoded_token.get("email")

    # 사용자 인증, 계정 생성 또는 로그인 처리
    # 예를 들어, 기존 사용자를 찾거나 새로 생성
    # user = User.objects.get_or_create(email=email)[0]
    # login(request, user)
    print(access_token)
    # 이후 원하는 곳으로 리디렉션 또는 토큰 반환
    return JsonResponse(
        {
            "id_token": id_token,
            "access_token": access_token,
            "user_info": decoded_token,  # 디코딩된 사용자 정보 반환 (선택 사항)
        }
    )
