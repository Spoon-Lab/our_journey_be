from django.urls import path

from our_journey.apps.photoapp.views import ContentImageUploadAPIView

urlpatterns = [
    path(
        "content_image_upload/",
        ContentImageUploadAPIView.as_view(),
        name="content_image_upload",
    ),
]
