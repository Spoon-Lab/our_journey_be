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
        """S3 경로를 사용자 ID와 사진 타입에 따라 설정"""
        if photo_type == "profile":
            return f"media/profile"
        elif photo_type == "content":
            return f"media/content"
        elif photo_type == "thread":
            return f"media/thread"
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
        upload_tasks = []
        image_urls = []
        for x in images:
            task = asyncio.create_task(s3_upload_image(f"{folder_dir}/{x}", x))
            x.file.seek(0)  # 파일 포인터를 처음으로 되돌림
            upload_tasks.append(task)

            # Presigned URL 생성
            presigned_url = generate_presigned_url(
                bucket_name, folder_dir, x, 60 * 60, "get"
            )
            image_urls.append(presigned_url)

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
                        "description": "The type of the photo (e.g., profile, content, thread)",
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
                        value={"detail": "photo_type is required."},
                    ),
                    OpenApiExample(
                        name="Missing image file",
                        summary="이미지 파일이 전달되지 않음",
                        value={"detail": "Image file must be provided."},
                    ),
                ],
                description="Bad request due to missing or incorrect parameters.",
            ),
            401: unauthorized_response(),
        },
        description="Upload images to S3 for user profile or thread image",
    )
    def post(self, request):
        photo_type = request.data.get("photo_type")
        if not photo_type:
            raise ValidationError({"detail": _("Photo type is required.")})

        images = request.FILES.getlist("images")
        if not images:
            raise ValidationError({"detail": _("Image file must be provided.")})

        folder_dir = self.get_s3_path(photo_type)

        image_urls = asyncio.run(
            self.upload_images(self.S3_BUCKET_NAME, folder_dir, images)
        )

        return Response(
            {"image_url": image_urls},
            status=status.HTTP_201_CREATED,
        )
