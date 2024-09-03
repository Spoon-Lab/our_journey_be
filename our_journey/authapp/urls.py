from django.urls import path

from .views import UserAuthenticationView, auth_redirect_view

urlpatterns = [
    # 구글 소셜 로그인 후 jwt토큰 리턴
    path("redirect/", auth_redirect_view, name="auth_redirect"),
    # spring과의 인증 api
    path("certificate/", UserAuthenticationView.as_view(), name="auth"),
]
