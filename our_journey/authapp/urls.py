from django.urls import path

from our_journey.authapp.views import google_callback

urlpatterns = [
    # 구글 소셜 로그인
    # path("google/login/", google_login, name="google_login"),
    path("/google/callback/", google_callback, name="google_callback"),
]
