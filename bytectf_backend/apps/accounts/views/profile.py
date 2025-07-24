from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.contrib.auth import logout
from apps.accounts.models import UserSession
from apps.accounts.serializers import (
    UserUpdateSerializer, 
    UserSerializer,
    UserSessionSerializer
)

class UserProfileView(generics.RetrieveUpdateAPIView):
    serializer_class = UserUpdateSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user
    
    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = UserSerializer(instance)
        return Response(serializer.data)


class UserSessionsView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserSessionSerializer
    
    def get_queryset(self):
        return UserSession.objects.filter(
            user=self.request.user
        ).order_by('-last_activity')
    
    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        sessions = [
            {
                'id': session.id,
                'ip_address': session.ip_address,
                'user_agent': session.user_agent,
                'last_activity': session.last_activity,
                'current': (
                    session.session_key == request.session.session_key
                )
            }
            for session in queryset
        ]
        return Response(sessions)


class RevokeSessionView(generics.DestroyAPIView):
    permission_classes = [IsAuthenticated]
    
    def get_object(self):
        session_id = self.kwargs.get('session_id')
        return UserSession.objects.get(
            id=session_id,
            user=self.request.user
        )
    
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        
        # 如果是当前会话，执行登出
        if instance.session_key == request.session.session_key:
            logout(request)
        
        instance.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)