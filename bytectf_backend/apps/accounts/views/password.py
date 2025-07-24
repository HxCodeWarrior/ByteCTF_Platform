from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import status
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.core.cache import cache
from apps.accounts.services.verification import send_password_reset_email
from apps.accounts.models import CustomUser, AuditLog
from apps.accounts.serializers import (
    PasswordChangeSerializer, 
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer
)

class PasswordChangeView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_scope = 'password_change'

    def post(self, request):
        serializer = PasswordChangeSerializer(
            data=request.data, 
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {"message": "密码修改成功"}, 
            status=status.HTTP_200_OK
        )


class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]
    throttle_scope = 'password_reset'

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        email = serializer.validated_data['email']
        user = CustomUser.objects.get(email=email)
        
        # 生成重置令牌
        token_generator = PasswordResetTokenGenerator()
        token = token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        
        # 存储令牌（5分钟有效）
        cache_key = f"password_reset:{uid}"
        cache.set(cache_key, token, timeout=300)
        
        # 发送重置邮件
        send_password_reset_email(user, uid, token, request)
        
        return Response(
            {"message": "密码重置邮件已发送，请查收"}, 
            status=status.HTTP_200_OK
        )


class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        uid = request.data.get('uid')
        token = request.data.get('token')
        
        # 验证令牌
        try:
            uid = force_str(urlsafe_base64_decode(uid))
            user = CustomUser.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
            user = None
        
        cache_key = f"password_reset:{uid}"
        valid_token = cache.get(cache_key)
        
        token_generator = PasswordResetTokenGenerator()
        if user and valid_token == token and token_generator.check_token(user, token):
            # 更新密码
            user.set_password(serializer.validated_data['new_password'])
            user.save()
            
            # 清除令牌
            cache.delete(cache_key)
            
            # 记录审计日志
            AuditLog.objects.create(
                user=user,
                action='PASSWORD_RESET',
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                details={'method': 'email'}
            )
            
            return Response(
                {"message": "密码重置成功"}, 
                status=status.HTTP_200_OK
            )
        
        return Response(
            {"error": "无效或过期的重置令牌"}, 
            status=status.HTTP_400_BAD_REQUEST
        )