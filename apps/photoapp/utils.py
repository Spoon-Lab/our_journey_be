import asyncio

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from django.conf import settings


async def s3_upload_image(destination_blob_name, source_file_name):
    try:
        session = boto3.Session(
            aws_access_key_id=settings.S3_ACCESS_KEY,
            aws_secret_access_key=settings.S3_SECRET_KEY,
        )

        s3 = session.resource("s3")
        await asyncio.to_thread(
            s3.Bucket(settings.S3_BUCKET_NAME).put_object,
            Key=destination_blob_name,
            Body=source_file_name,
        )
        return True

    except Exception as e:
        print(e, "오류")
        return False


def generate_presigned_url(bucket, folder, key, expired_in, _method):
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
        param = {
            "Bucket": bucket,
            "Key": f"{folder}/{key}",
        }
        if _method == "put":
            param["ContentType"] = "image/*"

        url = s3.generate_presigned_url(
            ClientMethod=f"{_method}_object", Params=param, ExpiresIn=expired_in
        )

    except ClientError:
        raise
    return url
