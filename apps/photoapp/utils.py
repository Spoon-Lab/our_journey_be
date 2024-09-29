import asyncio
import mimetypes

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from django.conf import settings


async def s3_upload_image(destination_blob_name, source_file_name, file_extension):
    try:
        session = boto3.Session(
            aws_access_key_id=settings.S3_ACCESS_KEY,
            aws_secret_access_key=settings.S3_SECRET_KEY,
        )

        s3 = session.resource("s3")

        # 확장자에 따른 Content-Type 자동 설정
        content_type, _ = mimetypes.guess_type(destination_blob_name)
        if content_type is None:
            content_type = "application/octet-stream"  # 기본값 설정

        await asyncio.to_thread(
            s3.Bucket(settings.S3_BUCKET_NAME).put_object,
            Key=destination_blob_name,
            Body=source_file_name,
            ContentType=content_type,  # Content-Type 설정 추가
            ContentDisposition="inline",
        )
        return True

    except Exception as e:
        print(e, "오류")
        return False


def generate_presigned_url(bucket, folder, key, file_extension, expired_in, _method):
    try:
        s3 = boto3.client(
            "s3",
            aws_access_key_id=settings.S3_ACCESS_KEY,
            aws_secret_access_key=settings.S3_SECRET_KEY,
            config=Config(
                signature_version="s3v4", s3={"use_accelerate_endpoint": True}
            ),
            region_name="ap-northeast-2",
        )
        # 확장자에 따른 기본적인 Content-Type 매핑
        mime_types = {
            ".jpeg": "image/jpeg",
            ".jpg": "image/jpeg",
            ".png": "image/png",
            ".gif": "image/gif",
            ".bmp": "image/bmp",
        }

        # 확장자에 맞는 MIME 타입을 가져옴, 없을 경우 기본값
        mime_type = mime_types.get(file_extension, "application/octet-stream")

        param = {
            "Bucket": bucket,
            "Key": f"{folder}/{key}",
            "ResponseContentType": mime_type,  # 확장자에 따른 동적 MIME 타입 설정
            "ResponseContentDisposition": "inline",  # 브라우저에서 바로 열리도록 설정
        }
        if _method == "put":
            param["ContentType"] = "image/*"

        url = s3.generate_presigned_url(
            ClientMethod=f"{_method}_object", Params=param, ExpiresIn=expired_in
        )

    except ClientError:
        raise
    return url
