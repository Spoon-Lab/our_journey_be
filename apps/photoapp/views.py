import os

from django.utils.translation import gettext_lazy as _
from drf_spectacular.utils import OpenApiExample, OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from config.utils import unauthorized_response

from .serializers import ImageUrlSerializer
from .utils import *


class ImageUploadAPIView(APIView):
    permission_classes = [IsAuthenticated]

    S3_BUCKET_NAME = settings.S3_BUCKET_NAME

    def get_s3_path(self, photo_type):
        """S3 경로 사진 타입에 따라 설정"""
        type_profile = "profile"
        type_content = "content"
        type_thread = "thread"
        if photo_type == type_profile:
            return f"media/{type_profile}"
        elif photo_type == type_content:
            return f"media/{type_content}"
        elif photo_type == type_thread:
            return f"media/{type_thread}"
        else:
            raise ValidationError({"detail": "Invalid photo type."})

    def delete_existing_images(self, folder_dir):
        """기존 S3 폴더에 있는 이미지를 삭제"""
        session = boto3.Session(
            aws_access_key_id=settings.S3_ACCESS_KEY,
            aws_secret_access_key=settings.S3_SECRET_KEY,
        )
        s3_client = session.client("s3")

        # 폴더 내의 모든 오브젝트 리스트 가져오기
        objects = s3_client.list_objects_v2(
            Bucket=self.S3_BUCKET_NAME, Prefix=folder_dir
        )

        if "Contents" in objects:
            delete_keys = [{"Key": obj["Key"]} for obj in objects["Contents"]]
            s3_client.delete_objects(
                Bucket=self.S3_BUCKET_NAME, Delete={"Objects": delete_keys}
            )

    async def upload_images(self, bucket_name, folder_dir, images):
        VALID_EXTENSIONS = [
            ".jpg",
            ".jpeg",
            ".png",
            ".webp",
            ".gif",
        ]  # 유효한 파일 확장자 리스트
        upload_tasks = []
        image_urls = []
        for x in images:
            file_extension = os.path.splitext(x.name)[1]

            # 파일 확장자 유효성 검사
            if file_extension not in VALID_EXTENSIONS:
                raise ValidationError({"error": _("허용되지 않는 파일 확장자입니다.")})

            # 파일을 다시 처음부터 읽을 수 있도록 설정
            x.file.seek(0)

            # S3에 파일 업로드 비동기 태스크 생성
            task = asyncio.create_task(
                s3_upload_image(
                    f"{folder_dir}/{x.name}", x.file, file_extension
                )  # x.file로 파일 객체 전달
            )
            upload_tasks.append(task)

            # S3 퍼블릭 URL 생성
            public_url = f"https://{bucket_name}.s3.ap-northeast-2.amazonaws.com/{folder_dir}/{x.name}"
            image_urls.append(public_url)

        # 모든 업로드 작업을 비동기로 실행
        await asyncio.gather(*upload_tasks)

        return image_urls

    @extend_schema(
        tags=["Image Upload"],
        request={
            "multipart/form-data": {
                "type": "object",
                "properties": {
                    "photo_type": {
                        "type": "string",
                        "enum": ["profile", "content", "thread"],
                        "description": "Type of the photo to be uploaded. Example values: 'profile', 'content', 'thread'.",
                    },
                    "images": {
                        "type": "array",
                        "items": {"type": "string", "format": "binary"},
                    },
                },
                "required": ["photo_type", "images"],
            }
        },
        responses={
            201: OpenApiResponse(
                response=ImageUrlSerializer, description="Images successfully uploaded."
            ),
            400: OpenApiResponse(
                response={
                    "type": "object",
                    "properties": {
                        "detail": {"type": "string"},
                        "code": {"type": "string"},
                    },
                },
                examples=[
                    OpenApiExample(
                        name="Missing photo_type",
                        summary="photo_type 값이 전달되지 않음",
                        value={"detail": "이미지 타입을 알려주세요."},
                    ),
                    OpenApiExample(
                        name="Missing image file",
                        summary="이미지 파일이 전달되지 않음",
                        value={"detail": "이미지 파일을 전달해주세요."},
                    ),
                ],
                description="Bad request due to missing or incorrect parameters.",
            ),
            401: unauthorized_response(),
        },
        description="Upload or reupload images to S3",
    )
    def post(self, request):
        photo_type = request.data.get("photo_type")
        if not photo_type:
            raise ValidationError({"detail": _("이미지 타입을 알려주세요.")})

        images = request.FILES.getlist("images")
        if not images:
            raise ValidationError({"detail": _("이미지 파일을 전달해주세요.")})

        folder_dir = self.get_s3_path(photo_type)

        image_urls = asyncio.run(
            self.upload_images(self.S3_BUCKET_NAME, folder_dir, images)
        )

        return Response(
            {"image_url": image_urls},
            status=status.HTTP_201_CREATED,
        )
