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
from apps.accounts.models import CustomUser
from apps.accounts.serializers import RegisterSerializer, LoginSerializer, UserSerializer

@method_decorator(csrf_protect, name='dispatch')
class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
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

        # 生成 token
        refresh = RefreshToken.for_user(user)
        access_token = refresh.access_token

        return Response({
            "message": "注册成功",
            "user": UserSerializer(user).data,
            "refresh": str(refresh),
            "access": str(access_token)
        }, status=status.HTTP_201_CREATED)



@method_decorator(csrf_protect, name='dispatch')
class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
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
        })

@method_decorator(csrf_protect, name='dispatch')
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            # 使 refresh token 失效
            refresh_token = request.data.get('refresh')
            token = RefreshToken(refresh_token)
            token.blacklist()

            # 清理会话
            logout(request)

            return Response({"message": "退出成功"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
