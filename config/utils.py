from drf_spectacular.utils import OpenApiExample, OpenApiResponse


def unauthorized_response():
    return OpenApiResponse(
        response={
            "type": "object",
            "properties": {
                "detail": {"type": "string"},
                "code": {
                    "type": "string",
                    "nullable": True,  # 'code'는 선택적 항목
                },
                "messages": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "token_class": {"type": "string"},
                            "token_type": {"type": "string"},
                            "message": {"type": "string"},
                        },
                    },
                    "nullable": True,  # 'messages'는 선택적 항목
                },
            },
        },
        examples=[
            OpenApiExample(
                name="Invalid token with messages",
                summary="유효하지 않거나 만료된 토큰에 대한 응답",
                value={
                    "detail": "이 토큰은 모든 타입의 토큰에 대해 유효하지 않습니다",
                    "code": "token_not_valid",
                    "messages": [
                        {
                            "token_class": "AccessToken",
                            "token_type": "access",
                            "message": "유효하지 않거나 만료된 토큰입니다",
                        }
                    ],
                },
            ),
            OpenApiExample(
                name="Missing authentication credentials",
                summary="인증 자격 증명(access token)이 제공되지 않음",
                value={
                    "detail": "자격 인증데이터(authentication credentials)가 제공되지 않았습니다."
                },
            ),
        ],
        description="Unauthorized request due to missing or invalid token.",
    )
