from django.conf import settings
from django.http import JsonResponse
from rest_framework.response import Response
from rest_framework.views import APIView


class ContentImageUploadAPIView(APIView):
    def post(self, request, *args, **kwargs):
        return Response({"image_url": ""})
