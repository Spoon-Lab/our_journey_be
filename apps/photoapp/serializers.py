from rest_framework import serializers


class ImageUrlSerializer(serializers.Serializer):
    image_url = serializers.ListField(child=serializers.CharField())
