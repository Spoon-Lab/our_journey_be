from dj_rest_auth.registration.views import VerifyEmailView
from django.urls import include, path, re_path

from .views import (
    ConfirmEmailView,
    CustomRegisterView,
    CustomTokenRefreshView,
    GoogleLoginCallback,
    OurLoginView,
    OurLogoutView,
    PasswordResetConfirmView,
    PasswordResetRequestView,
    UserAuthenticationView,
    auth_redirect_view,
)

urlpatterns = [
    # path("", include("dj_rest_auth.urls")),
    # path("signup/", include("dj_rest_auth.registration.urls")),
    path("signup", CustomRegisterView.as_view(), name="signup"),
    path("social", include("allauth.urls")),
    path("login", OurLoginView.as_view(), name="login"),
    path("logout", OurLogoutView.as_view(), name="logout"),
    # spring과의 인증 api
    path("certificate", UserAuthenticationView.as_view(), name="auth"),
    # 유효한 이메일이 유저에게 전달
    re_path(
        r"^account-confirm-email/$",
        VerifyEmailView.as_view(),
        name="account_email_verification_sent",
    ),
    # 유저가 클릭한 이메일(=링크) 확인
    re_path(
        r"^account-confirm-email/(?P<key>[-:\w]+)/$",
        ConfirmEmailView.as_view(),
        name="account_confirm_email",
    ),
    path("token/refresh", CustomTokenRefreshView.as_view(), name="token_refresh"),
    path(
        "google/callback", GoogleLoginCallback.as_view(), name="google-login-callback"
    ),
    # 구글 소셜 로그인 후 jwt토큰 리턴
    path("redirect", auth_redirect_view, name="auth_redirect"),
    # path("admin-category/", AdminCategoryAPIView.as_view(), name="admin-category"),
    path(
        "password-reset-request",
        PasswordResetRequestView.as_view(),
        name="password-reset-request",
    ),
    path(
        "password-reset-confirm/<str:uidb64>/<str:token>",
        PasswordResetConfirmView.as_view(),
        name="password-reset-confirm",
    ),
]
