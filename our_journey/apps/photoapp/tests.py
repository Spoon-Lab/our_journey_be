import os

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import RefreshToken

# Create your tests here.
User = get_user_model()


class ContentImageUploadTest(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            email="spoonlab@gmail.com", password="tmvnsfoq1"
        )

        # jwt 토큰 생성 (클라이언트)
        refresh = RefreshToken.for_user(self.user)
        self.access_token = str(refresh.access_token)

        self.url = reverse("content_image_upload")

        self.test_image_path = os.path.join(os.path.dirname(__file__), "test_image.png")
        with open(self.test_image_path, "wb") as f:
            f.write(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00")

    def deleteImage(self):
        # 테스트 끝나면 이미지 삭제
        if os.path.exists(self.test_image_path):
            os.remove(self.test_image_path)

    def test_image_upload(self):
        with open(self.test_image_path, "rb") as image_file:
            file_data = {
                "file": SimpleUploadedFile(
                    name="test_image.png",
                    content=image_file.read(),
                    content_type="image/png",
                ),
                "content_id": "11",
            }

            headers = {"HTTP_AUTHORIZATION": f"Bearer {self.access_token}"}

            response = self.client.post(
                self.url, file_data, format="multipart", **headers
            )

            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertIn("image_url", response.data)
