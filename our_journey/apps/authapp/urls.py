from django.urls import path, include, re_path

from .views import UserAuthenticationView, auth_redirect_view, ConfirmEmailView

urlpatterns = [
    path("", include("dj_rest_auth.urls")),
    path("signup/", include("dj_rest_auth.registration.urls")),
    # 구글 소셜 로그인 후 jwt토큰 리턴
    path("redirect/", auth_redirect_view, name="auth_redirect"),
    # spring과의 인증 api
    path("certificate/", UserAuthenticationView.as_view(), name="auth"),
    re_path(
        r"^account-confirm-email/(?P<key>[-:\w]+)/$",
        ConfirmEmailView.as_view(),
        name="account_confirm_email",
    ),
]
