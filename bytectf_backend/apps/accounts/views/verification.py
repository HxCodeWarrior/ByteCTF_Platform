# 文件: apps/accounts/verification.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import status
from django.core.cache import cache
from apps.accounts.models import CustomUser, AuditLog
from apps.accounts.serializers import EmailVerificationSerializer, PhoneVerificationSerializer
from apps.accounts.services.verification import send_verification_email, send_sms_verification

class EmailVerificationView(APIView):
    permission_classes = [AllowAny]
    throttle_scope = 'email_verify'

    def post(self, request):
        serializer = EmailVerificationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        token = serializer.validated_data['token']
        cache_key = f"email_verify:{token}"
        user_id = cache.get(cache_key)
        
        if not user_id:
            return Response(
                {"error": "验证链接无效或已过期"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            user = CustomUser.objects.get(pk=user_id)
            user.email_verified = True
            user.save()
            
            # 清除缓存
            cache.delete(cache_key)
            
            # 记录审计日志
            AuditLog.objects.create(
                user=user,
                action='EMAIL_VERIFIED',
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                details={}
            )
            
            return Response(
                {"message": "邮箱验证成功"}, 
                status=status.HTTP_200_OK
            )
        except CustomUser.DoesNotExist:
            return Response(
                {"error": "用户不存在"}, 
                status=status.HTTP_400_BAD_REQUEST
            )


class ResendEmailVerificationView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        if user.email_verified:
            return Response(
                {"message": "邮箱已通过验证"}, 
                status=status.HTTP_200_OK
            )
        
        # 发送验证邮件
        send_verification_email(user, request)
        
        return Response(
            {"message": "验证邮件已重新发送"}, 
            status=status.HTTP_200_OK
        )


class PhoneVerificationRequestView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        if user.phone_verified:
            return Response(
                {"message": "手机号已通过验证"}, 
                status=status.HTTP_200_OK
            )
        
        # 生成并发送验证码
        send_sms_verification(user, request)
        
        return Response(
            {"message": "验证码已发送"}, 
            status=status.HTTP_200_OK
        )


class PhoneVerificationConfirmView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = PhoneVerificationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = request.user
        code = serializer.validated_data['code']
        cache_key = f"phone_verify:{user.id}"
        stored_code = cache.get(cache_key)
        
        if stored_code and stored_code == code:
            user.phone_verified = True
            user.save()
            
            # 清除缓存
            cache.delete(cache_key)
            
            # 记录审计日志
            AuditLog.objects.create(
                user=user,
                action='PHONE_VERIFIED',
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                details={}
            )
            
            return Response(
                {"message": "手机号验证成功"}, 
                status=status.HTTP_200_OK
            )
        
        return Response(
            {"error": "验证码无效或已过期"}, 
            status=status.HTTP_400_BAD_REQUEST
        )