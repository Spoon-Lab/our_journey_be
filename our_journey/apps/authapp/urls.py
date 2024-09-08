from dj_rest_auth.registration.views import VerifyEmailView
from django.urls import path, include, re_path

from .views import (
    UserAuthenticationView,
    auth_redirect_view,
    ConfirmEmailView,
    CustomLoginView,
    AdminCategoryAPIView,
)

urlpatterns = [
    path("login/", CustomLoginView.as_view(), name="login"),
    path("", include("dj_rest_auth.urls")),
    path("signup/", include("dj_rest_auth.registration.urls")),
    # 구글 소셜 로그인 후 jwt토큰 리턴
    path("redirect/", auth_redirect_view, name="auth_redirect"),
    # spring과의 인증 api
    path("certificate/", UserAuthenticationView.as_view(), name="auth"),
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
    path("admin-category/", AdminCategoryAPIView.as_view(), name="admin-category"),
]
