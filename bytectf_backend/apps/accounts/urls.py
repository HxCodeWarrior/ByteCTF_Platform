# 文件: apps/accounts/urls.py
from django.urls import path
from apps.accounts.views.auth import (
    RegisterView, 
    LoginView, 
    LogoutView,
    TwoFactorSetupView,
    TwoFactorVerifyView,
    TwoFactorDisableView
)
from apps.accounts.views.profile import (
    UserProfileView,
    UserSessionsView,
    RevokeSessionView
)
from .views.password import (
    PasswordChangeView,
    PasswordResetRequestView,
    PasswordResetConfirmView
)
from apps.accounts.views.verification import (
    EmailVerificationView,
    ResendEmailVerificationView,
    PhoneVerificationRequestView,
    PhoneVerificationConfirmView
)

app_name = 'accounts'

urlpatterns = [
    # 认证相关
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    
    # 双因素认证
    path('2fa/setup/', TwoFactorSetupView.as_view(), name='2fa-setup'),
    path('2fa/verify/', TwoFactorVerifyView.as_view(), name='2fa-verify'),
    path('2fa/disable/', TwoFactorDisableView.as_view(), name='2fa-disable'),
    
    # 个人资料
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('sessions/', UserSessionsView.as_view(), name='user-sessions'),
    path('sessions/<int:session_id>/revoke/', RevokeSessionView.as_view(), name='revoke-session'),
    
    # 密码管理
    path('password/change/', PasswordChangeView.as_view(), name='password-change'),
    path('password/reset/request/', PasswordResetRequestView.as_view(), name='password-reset-request'),
    path('password/reset/confirm/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    
    # 验证相关
    path('verify/email/', EmailVerificationView.as_view(), name='email-verify'),
    path('verify/email/resend/', ResendEmailVerificationView.as_view(), name='resend-email-verify'),
    path('verify/phone/request/', PhoneVerificationRequestView.as_view(), name='phone-verify-request'),
    path('verify/phone/confirm/', PhoneVerificationConfirmView.as_view(), name='phone-verify-confirm'),
]