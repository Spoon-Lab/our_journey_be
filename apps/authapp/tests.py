from unittest.mock import patch

from django.conf import settings
from django.contrib.auth.tokens import default_token_generator
from django.core import mail
from django.core.mail import send_mail
from django.test import TestCase
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from rest_framework import status
from rest_framework.test import APITestCase, APIClient

from django.contrib.auth import get_user_model


class PasswordResetRequestTest(APITestCase):
    # 재설정 메일 요청 테스트 코드
    def setUp(self):
        self.client = APIClient()

        User = get_user_model()

        self.user = User.objects.create_user(
            email="testuser@naver.com", password="password123"
        )

    # 비밀번호 재설정 메일 request
    def get_jwt_token(self):
        # 로그인 API 호출하여 JWT 토큰을 가져오는 함수
        login_url = reverse("our-login")  # JWT 토큰 발급 엔드포인트
        login_data = {
            "email": "testuser@naver.com",
            "password": "password123",
        }
        response = self.client.post(login_url, login_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        return response.data["access"]  # access 토큰 반환

    def test_password_reset_request(self):
        # JWT 토큰을 Authorization 헤더에 추가
        token = self.get_jwt_token()
        self.client.credentials(HTTP_AUTHORIZATION="Bearer " + token)

        # 비밀번호 재설정 요청 API 호출
        url = reverse("password-reset-request")
        data = {"email": "testuser@naver.com"}
        response = self.client.post(url, data)

        # 응답 코드가 200 OK인지 확인
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(mail.outbox), 1)  # 메일이 한 통 전송되었는지 확인
        self.assertIn("Password reset", mail.outbox[0].subject)  # 메일 제목 확인
        self.assertIn("testuser@example.com", mail.outbox[0].to)

    def test_password_reset_without_login(self):
        url = reverse("password-reset-request")
        response = self.client.post(url)
        # 로그인 하지 않은 상태에서 재설정 요청이면 인증되지 않아서 401
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class PasswordResetConfirmTest(APITestCase):
    # 재설정 POST 테스트 코드
    def setUp(self):
        self.client = APIClient()
        User = get_user_model()

        self.user = User.objects.create_user(
            email="hycha00@naver.com", password="password123"
        )
        self.uid = urlsafe_base64_encode(force_bytes(self.user.pk))
        self.token = default_token_generator.make_token(self.user)

    def get_jwt_token(self):
        # 로그인 API 호출하여 JWT 토큰을 가져오는 함수
        login_url = reverse("our-login")  # JWT 토큰 발급 엔드포인트
        login_data = {
            "email": "testuser@naver.com",
            "password": "tmvnsfoq123!",
        }
        response = self.client.post(login_url, login_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        return response.data["access"]  # access 토큰 반환

    def test_password_token_validation(self):
        token = self.get_jwt_token()
        url = reverse(
            "password-reset-confirm",
            kwargs={"uidb64": self.uid, "token": self.token},
        )
        pw_data = {"new_password1": "newpassword1", "new_password2": "newpassword1"}
        response = self.client.post(url, pw_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(
            self.client.login(email="testuser@naver.com", password="newpassword1")
        )

    def test_password_reset_invalid_token(self):
        # 잘못된 토큰을 사용했을 때 비밀번호 재설정 POST
        invalid_token = "invalid"
        url = reverse(
            "password-reset-confirm",
            kwargs={"uidb64": self.uid, "token": invalid_token},
        )
        pw_data = {"new_password1": "newpassword1", "new_password2": "newpassword1"}
        response = self.client.post(url, pw_data)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("Invalid", response.data["error"])
