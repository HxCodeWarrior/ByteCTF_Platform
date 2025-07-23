from rest_framework import generics
from rest_framework.permissions import IsAuthenticated
from apps.accounts.serializers import UserUpdateSerializer, UserSerializer

class UserProfileView(generics.RetrieveUpdateAPIView):
    serializer_class = UserUpdateSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user