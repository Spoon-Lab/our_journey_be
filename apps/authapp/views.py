import requests
from allauth.account.models import EmailAddress, EmailConfirmationHMAC
from dj_rest_auth.registration.views import RegisterView
from dj_rest_auth.views import LoginView, LogoutView, PasswordChangeView
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.http import HttpResponseRedirect, JsonResponse
from django.shortcuts import render
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.translation import gettext_lazy as _
from drf_spectacular.utils import (
    OpenApiExample,
    OpenApiParameter,
    OpenApiResponse,
    extend_schema,
    extend_schema_serializer,
)
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView

from config.utils import unauthorized_response

from .models import User
from .serializers import (
    CustomLoginSerializer,
    CustomRegisterSerializer,
    JWTResponseSerializer,
    UserCertificateSerializer,
    UserSerializer,
)


class CustomRegisterView(RegisterView):
    serializer_class = CustomRegisterSerializer

    @extend_schema(
        tags=["User Registration"],
        responses={
            201: OpenApiResponse(
                response={
                    "type": "object",
                    "properties": {
                        "detail": {
                            "type": "string",
                            "example": "확인 이메일을 발송했습니다.",
                        }
                    },
                }
            ),
            400: OpenApiResponse(
                response={
                    "type": "object",
                    "properties": {
                        "error": {
                            "type": "string",
                        }
                    },
                },
                examples=[
                    OpenApiExample(
                        name="This email is already registered",
                        summary="이미 해당 이메일이 사용 중일 때",
                        value={"error": "email is already registered"},
                    ),
                    OpenApiExample(
                        name="The two password fields do not match.",
                        summary="password1과 password2 필드 값이 맞지 않을 때",
                        value={"error": "password do not match"},
                    ),
                    OpenApiExample(
                        name="password validation error",
                        summary="비밀번호 유효성 검사 오류",
                        value={"error": "use safe password"},
                    ),
                ],
                description="email is already registered or password error",
            ),
        },
    )
    @extend_schema_serializer(exclude_fields=["username"])
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)

        if not serializer.is_valid():
            errors = serializer.errors
            # 이메일 중복 에러 처리
            if "email" in errors:
                raise ValidationError({"error": "email is already registered"})
            if "password1" in errors:
                raise ValidationError({"error": "use safe password"})
            else:
                raise ValidationError({"error": "password do not match"})
        return super().post(request, *args, **kwargs)


@extend_schema(tags=["User Login"])
@extend_schema_serializer(exclude_fields=["username"])
class OurLoginView(LoginView):
    permission_classes = (AllowAny,)
    serializer_class = CustomLoginSerializer

    def get_response(self):
        user_id = self.user.pk
        data = {
            "access": str(self.access_token),
            "refresh": str(self.refresh_token),
            "user": {
                "pk": user_id,
                "email": self.user.email,
            },
        }
        return Response(data, status=status.HTTP_200_OK)

    @extend_schema(
        responses={
            200: OpenApiResponse(
                response=JWTResponseSerializer, description="JWT login response"
            ),
            400: OpenApiResponse(
                response={
                    "type": "object",
                    "properties": {
                        "detail": {
                            "type": "string",
                            "nullable": True,  # 선택적일 수 있음
                            "example": "Email verification is required to log in.",
                        },
                        "email": {
                            "type": "array",
                            "items": {
                                "type": "string",
                                "example": "No account found with this email address.",
                            },
                            "nullable": True,  # 선택적일 수 있음
                        },
                    },
                },
                examples=[
                    OpenApiExample(
                        name="No account found",
                        summary="계정이 존재하지 않을 때",
                        value={"error": ["No account found with this email address."]},
                    ),
                    OpenApiExample(
                        name="Incorrect password",
                        summary="비밀번호가 틀렸을 때",
                        value={"error": ["Incorrect password. Please try again."]},
                    ),
                ],
                description="No account or incorrect password",
            ),
            403: OpenApiResponse(
                response={
                    "type": "object",
                    "properties": {
                        "error": {
                            "type": "string",
                            "example": ["Email verification is required to log in."],
                        }
                    },
                },
                description="Email verification is required to log in.",
            ),
        },
    )
    def post(self, request, *args, **kwargs):
        self.request = request

        # admin 계정이 아니고, 인증 메일 확인하기 전이면 403
        if (
            not self.request.user.is_superuser
            and EmailAddress.objects.filter(
                email=request.data["email"], verified=False
            ).exists()
        ):
            return Response(
                {"error": [_("Email verification is required to log in.")]},
                status=status.HTTP_403_FORBIDDEN,  # Forbidden 응답
            )
        else:
            self.serializer = self.get_serializer(data=self.request.data)

            self.serializer.is_valid(raise_exception=True)

            self.login()

            return self.get_response()


class OurLogoutView(LogoutView):
    @extend_schema(
        tags=["User Logout"],
        parameters=[
            OpenApiParameter(
                name="refresh_token",
                description="The refresh token stored in the cookie for authentication.",
                required=True,
                type=str,
                location=OpenApiParameter.COOKIE,  # 쿠키 파라미터임을 명시
            )
        ],
        responses={
            200: OpenApiResponse(
                response={
                    "type": "object",
                    "properties": {
                        "detail": {
                            "type": "string",
                            "example": "로그아웃되었습니다.",
                        }
                    },
                },
                description="Logout Success",
            ),
            401: OpenApiResponse(
                response={
                    "type": "object",
                    "properties": {
                        "detail": {
                            "type": "string",
                            "example": "Refresh token was not included in cookie data.",
                        }
                    },
                },
                description="Refresh token was not included in cookie data.",
            ),
        },
    )
    def post(self, request, *args, **kwargs):
        # 기본 토큰 갱신 동작을 그대로 호출
        return super().post(request, *args, **kwargs)


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

    @extend_schema(
        tags=["User Authenticate"],
        description="Spring server can request and be returned user data.",
        responses={
            200: OpenApiResponse(
                response=UserCertificateSerializer,
                description="""user certificate from main(Spring) server. Authorization is admin or generl.
                            """,
            ),
            401: unauthorized_response(),
        },
    )
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


def email_confirm(request):
    return render(request, "auth/email_confirm.html")


@extend_schema(
    tags=["User Email confirmation after join"],
    description="유저가 회원가입 후 메일함에서 인증 완료하는 api",
)
class ConfirmEmailView(APIView):
    permission_classes = [AllowAny]

    def get(self, *args, **kwargs):
        confirmation = self.get_object()

        # email_confirmation이 None이면 400 응답
        if confirmation is None:
            return Response(
                {"error": "Invalid or expired confirmation link."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        confirmation.confirm(self.request)

        # 이메일 인증이 완료된 후 spring 프로필 생성하는 API 요청
        url = "http://13.125.137.216:8080/profiles"
        data = {
            "id": confirmation.email_address.user.id,
        }
        response = requests.post(url, json=data)

        return HttpResponseRedirect(redirect_to="http://localhost:3000/login")

    def get_object(self, queryset=None):
        key = self.kwargs["key"]

        # 이메일 인증할 객체가 있는지 확인
        email_confirmation = EmailConfirmationHMAC.from_key(key)

        if not email_confirmation:
            return None  # 인증할 객체가 없는 경우 None으로 반환

        return email_confirmation


class CustomTokenRefreshView(TokenRefreshView):
    @extend_schema(
        tags=["refresh Access token"],
        request={
            "application/json": {
                "type": "object",
                "properties": {"refresh": {"type": "string"}},
            }
        },
        responses={
            200: OpenApiResponse(
                response={
                    "type": "object",
                    "properties": {
                        "access": {"type": "string"},
                    },
                },
                examples=[
                    OpenApiExample(
                        name="Success Example",
                        summary="This is an example of a successful token refresh response.",
                        value={"access": "string"},
                    )
                ],
                description="New access token here.",
            ),
            400: OpenApiResponse(
                response={
                    "type": "object",
                    "properties": {
                        "refresh": {
                            "type": "array",
                            "items": {
                                "type": "string",
                                "example": "이 필드는 필수 항목입니다.",
                            },
                        }
                    },
                },
                description="This field is required.",
            ),
            401: OpenApiResponse(
                response={
                    "type": "object",
                    "properties": {
                        "detail": {
                            "type": "string",
                            "example": "유효하지 않거나 만료된 토큰입니다",  # 구체적인 예시 추가
                        },
                        "code": {
                            "type": "string",
                            "example": "token_not_valid",  # 구체적인 예시 추가
                        },
                    },
                },
                description="Invalid token or token is expired.",
            ),
        },
    )
    def post(self, request, *args, **kwargs):
        # 기본 토큰 갱신 동작을 그대로 호출
        return super().post(request, *args, **kwargs)


class GoogleLoginCallback(APIView):
    def verify_google_token(self, id_token):
        # Google의 토큰 검증 엔드포인트
        google_token_info_url = (
            f"https://oauth2.googleapis.com/tokeninfo?id_token={id_token}"
        )

        # Google에 토큰 유효성 확인 요청
        response = requests.get(google_token_info_url)

        if response.status_code == 200:
            token_info = response.json()
            email = token_info.get("email")
            if token_info.get("email_verified"):
                return email, token_info
            else:
                raise ValueError("Email not verified")
        else:
            raise ValueError("Invalid token")

    def create_or_update_user(self, email, token_info):
        try:
            # 이미 등록된 사용자가 있는지 확인
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            # 새로운 사용자 생성
            user = User.objects.create(
                email=email,
                first_name=token_info.get("given_name", ""),
                last_name=token_info.get("family_name", ""),
            )
            user.set_unusable_password()  # 소셜 로그인은 비밀번호가 필요 없음
            user.save()

            # 유저 db에 등록된 이후에 프로필 생성하는 spring api 요청
            url = "http://13.125.137.216:8080/profiles"
            data = {
                "id": user.id,
            }
            response = requests.post(url, json=data)

        return user

    def get_user_info(self, user):
        refresh = RefreshToken.for_user(user)
        return {
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "user": {
                "pk": user.pk,
                "email": user.email,
            },
        }

    @extend_schema(
        tags=["Google Social Login Callback API"],
        request={
            "application/json": {
                "type": "object",
                "properties": {"id_token": {"type": "string"}},
            }
        },
        responses={
            200: OpenApiResponse(
                response=UserSerializer, description="social login success."
            ),
            400: OpenApiResponse(
                response={
                    "type": "string",
                    "properties": {"detail": {"type": "string"}},
                },
                examples=[
                    OpenApiExample(
                        name="ID token value none",
                        summary="ID token 값이 전달되지 않음",
                        value={"error": "ID token is required."},
                    ),
                    OpenApiExample(
                        name="Invalid token",
                        summary="ID token 값이 유효하지 않음",
                        value={"error": "Invalid token"},
                    ),
                ],
                description="ID token error",
            ),
        },
    )
    def post(self, request):
        # 클라이언트에서 id_token을 받음
        id_token = request.data.get("id_token")

        if not id_token:
            return Response(
                {"error": "ID token is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            # Google 토큰 검증
            email, token_info = self.verify_google_token(id_token)

            # 사용자 생성 또는 업데이트
            user = self.create_or_update_user(email, token_info)

            # 구글 로그인도 일반 로그인과 동일하게 응답
            user_info = self.get_user_info(user)

            return Response(
                user_info,
                status=status.HTTP_200_OK,
            )
        except ValueError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetRequestView(APIView):
    @extend_schema(
        tags=["Password Reset Email Request"],
        description="User can require password reset email without login.",
        request={
            "application/json": {
                "type": "object",
                "properties": {"email": {"type": "string"}},
            }
        },
        responses={
            200: OpenApiResponse(
                description="비밀번호 재설정 메일이 전송됨",
            ),
            400: OpenApiResponse(
                response={
                    "type": "object",
                    "properties": {
                        "error": {
                            "type": "string",
                        }
                    },
                },
                examples=[
                    OpenApiExample(
                        name="User not found",
                        summary="유저가 존재하지 않을 때의 응답",
                        value={"error": "User does not exist."},
                    ),
                    OpenApiExample(
                        name="Email required",
                        summary="이메일이 제공되지 않았을 때의 응답",
                        value={"error": "Email is required."},  # 다른 예시 데이터
                    ),
                ],
                description="Email is required or User does not exist.",
            ),
        },
    )
    def post(self, request, *args, **kwargs):

        email = request.data.get("email")
        if not email:
            return Response(
                {"error": "Email is required."}, status=status.HTTP_400_BAD_REQUEST
            )

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {"error": "User does not exist."}, status=status.HTTP_400_BAD_REQUEST
            )

        # 비밀번호 재설정 링크 토큰 설정
        uid = urlsafe_base64_encode(force_bytes(user.id))
        token = default_token_generator.make_token(user)

        # 재설정 url (frontend url)
        # reset_url = f"{request.build_absolute_uri(reverse('password-reset-confirm', args=[uid, token]))}"
        reset_url = f"http://localhost:3000/reset-password/{uid}/{token}"
        # 이메일 내용
        subject = "Our Journey에서 비밀번호 재설정"
        message = f"안녕하세요,\n\n다음 링크를 통해 비밀번호를 재설정할 수 있습니다:\n{reset_url}\n새 비밀번호를 요청하지 않으셨나요? 이 이메일을 무시해주세요."

        # 이메일 발송
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email])

        return Response(status=status.HTTP_200_OK)


class PasswordResetConfirmView(PasswordChangeView):
    permission_classes = [AllowAny]

    @extend_schema(
        tags=["Password Reset Confirm"],
        description="User can change password with uid and token data.",
        responses={
            200: OpenApiResponse(description="New password has been saved."),
            400: OpenApiResponse(
                response={
                    "type": "object",
                    "properties": {
                        "error": {
                            "type": "string",
                        }
                    },
                },
                examples=[
                    OpenApiExample(
                        name="Invalid token or token is expired",
                        summary="비밀번호 재설정 링크가 유효하지 않거나 만료 혹은 이미 사용되었을 경우",
                        value={"error": ["Invalid token or token is expired."]},
                    ),
                    OpenApiExample(
                        name="password value is required",
                        summary="바꿀 비밀번호 값(new_password1) 혹은 비밀번호 확인값(new_password2)이 없을 때",
                        value={
                            "error": [
                                "new_password1 is required",
                                "new_password2 is required",
                            ]
                        },
                    ),
                ],
                description="This field is required.",
            ),
        },
    )
    def post(self, request, uidb64, token, *args, **kwargs):
        try:
            # uidb64 디코딩으로 user id값 확인
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)

        # User 데이터베이스에 id 값이 없을 때
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response(
                {"error": ["Invalid uid"]}, status=status.HTTP_400_BAD_REQUEST
            )

        # 재설정을 요청하는 유저와 토큰값이 일치한지 확인
        if not default_token_generator.check_token(user, token):
            return Response(
                {"error": ["Invalid token or token is expired."]},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 기존 비밀번호 재설정 로직 이용
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            # 비밀번호 변경
            user.set_password(serializer.validated_data["new_password1"])
            user.save()
            return Response(status=status.HTTP_200_OK)
        # 필수 항목이 누락된 경우 에러 메시지 커스터마이즈
        error_list = []
        for field, errors in serializer.errors.items():
            for error in errors:
                if "필수 항목" in error:
                    error_list.append(f"{field} is required")

        return Response({"error": error_list}, status=status.HTTP_400_BAD_REQUEST)
