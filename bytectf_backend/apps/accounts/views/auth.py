from datetime import timedelta
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.utils import timezone
from django.views.decorators.csrf import csrf_protect
from django.utils.decorators import method_decorator
from django.core.cache import cache
from django.contrib.auth import login, logout, authenticate
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.contrib.auth.password_validation import validate_password
from django_otp.plugins.otp_totp.models import TOTPDevice
from apps.accounts.models import (
    CustomUser,
    AuditLog,
    UserSession
)
from apps.accounts.services.verification import send_verification_email
from apps.accounts.serializers import (
    RegisterSerializer, 
    LoginSerializer, 
    UserSerializer,
    TwoFactorSetupSerializer,
    TwoFactorVerifySerializer
)

@method_decorator(csrf_protect, name='dispatch')
class RegisterView(APIView):
    permission_classes = [AllowAny]
    throttle_scope = 'register'

    def post(self, request):
        serializer = RegisterSerializer(
            data=request.data, 
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)

        # 检查邮箱是否已注册
        email = serializer.validated_data.get('email')
        if CustomUser.objects.filter(email=email).exists():
            return Response({"error": "该邮箱已被注册"}, status=status.HTTP_400_BAD_REQUEST)

        # 检查密码强度
        password = serializer.validated_data.get('password')
        try:
            validate_password(password)
        except ValidationError as e:
            return Response({"error": e.messages}, status=status.HTTP_400_BAD_REQUEST)

        # 保存用户
        user = serializer.save()

        # 发送验证邮件
        send_verification_email(user, request)

        # 生成 token
        refresh = RefreshToken.for_user(user)
        access_token = refresh.access_token

        return Response({
            "message": "注册成功，请查收邮箱验证邮件",
            "user": UserSerializer(user).data,
            "refresh": str(refresh),
            "access": str(access_token)
        }, status=status.HTTP_201_CREATED)



@method_decorator(csrf_protect, name='dispatch')
class LoginView(APIView):
    permission_classes = [AllowAny]
    throttle_scope = 'login'

    def post(self, request):
        serializer = LoginSerializer(
            data=request.data, 
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data.get('email')
        password = serializer.validated_data.get('password')

        # 检查登录失败次数
        cache_key = f"login_failures:{email}"
        failures = cache.get(cache_key, 0)
        if failures >= 5:
            return Response({"error": "登录失败次数过多，请稍后再试"}, status=status.HTTP_429_TOO_MANY_REQUESTS)

        user = authenticate(request, email=email, password=password)
        if user is None:
            # 记录登录失败
            cache.set(cache_key, failures + 1, timeout=300)  # 5 分钟内限制
            return Response({"error": "邮箱或密码错误"}, status=status.HTTP_401_UNAUTHORIZED)

        # 登录成功，清除失败记录
        cache.delete(cache_key)

        # 记录登录行为
        user.last_login = timezone.now()
        user.save()

        # 记录用户会话
        UserSession.objects.update_or_create(
            user=user,
            session_key=request.session.session_key,
            defaults={
                'ip_address': request.META.get('REMOTE_ADDR'),
                'user_agent': request.META.get('HTTP_USER_AGENT', '')[:255]
            }
        )

        # 生成 token 并设置过期时间
        refresh = RefreshToken.for_user(user)
        refresh.set_exp(lifetime=timedelta(days=7))  # 刷新 token 7 天后过期
        access_token = refresh.access_token
        access_token.set_exp(lifetime=timedelta(hours=1))  # 访问 token 1 小时后过期

        login(request, user)
        return Response({
            "message": "登录成功",
            "refresh": str(refresh),
            "access": str(access_token),
            "user": UserSerializer(user).data,
            "requires_2fa": user.two_factor_enabled
        })

@method_decorator(csrf_protect, name='dispatch')
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            # 使 refresh token 失效
            refresh_token = request.data.get('refresh')
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()

            # 清理会话记录
            if request.session.session_key:
                UserSession.objects.filter(
                    user=request.user,
                    session_key=request.session.session_key
                ).delete()

            # 清理会话
            logout(request)

            # 记录审计日志
            AuditLog.objects.create(
                user=request.user,
                action='LOGOUT',
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                details={'method': 'api'}
            )

            return Response(
                {"message": "退出成功"}, 
                status=status.HTTP_200_OK
            )
        except Exception as e:
            return Response(
                {"error": str(e)}, 
                status=status.HTTP_400_BAD_REQUEST
            )



class TwoFactorSetupView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """获取双因素认证状态"""
        return Response({
            "enabled": request.user.two_factor_enabled,
            "backup_codes": []  # 实际应生成备份代码
        })

    def post(self, request):
        """启用双因素认证"""
        serializer = TwoFactorSetupSerializer(
            data=request.data, 
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        
        # 创建TOTP设备
        device = TOTPDevice.objects.create(
            user=request.user, 
            name='default'
        )
        
        # 生成配置信息
        request.user.two_factor_enabled = True
        request.user.save()
        
        # 记录审计日志
        AuditLog.objects.create(
            user=request.user,
            action='2FA_ENABLED',
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            details={'method': 'TOTP'}
        )
        
        return Response({
            "message": "双因素认证已启用",
            "qr_code_url": device.config_url,
            "backup_codes": ["code1", "code2"]  # 实际应生成真实备份代码
        })


class TwoFactorVerifyView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """验证双因素认证代码"""
        serializer = TwoFactorVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        device = TOTPDevice.objects.filter(user=request.user).first()
        if not device:
            return Response(
                {"error": "未配置双因素认证设备"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if device.verify_token(serializer.validated_data['totp_code']):
            # 标记为已验证（在实际登录流程中处理）
            return Response({"message": "验证成功"})
        
        return Response(
            {"error": "验证码无效"}, 
            status=status.HTTP_400_BAD_REQUEST
        )


class TwoFactorDisableView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """禁用双因素认证"""
        serializer = TwoFactorSetupSerializer(
            data=request.data, 
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        
        # 删除TOTP设备
        TOTPDevice.objects.filter(user=request.user).delete()
        request.user.two_factor_enabled = False
        request.user.save()
        
        # 记录审计日志
        AuditLog.objects.create(
            user=request.user,
            action='2FA_DISABLED',
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            details={'method': 'TOTP'}
        )
        
        return Response({"message": "双因素认证已禁用"})
