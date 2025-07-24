import random
from django.core.cache import cache
from django.template.loader import render_to_string
from django.core.mail import send_mail
from django.conf import settings
from twilio.rest import Client

def send_verification_email(user, request):
    """发送邮箱验证邮件"""
    # 生成验证令牌
    token = f"email-verify-{random.randint(100000, 999999)}"
    cache_key = f"email_verify:{token}"
    cache.set(cache_key, user.id, timeout=3600)  # 1小时有效
    
    # 构建验证链接
    verify_url = f"{settings.FRONTEND_URL}/verify-email?token={token}"
    
    # 渲染邮件内容
    subject = "请验证您的邮箱"
    message = render_to_string('email/verification_email.html', {
        'user': user,
        'verify_url': verify_url,
        'app_name': settings.APP_NAME
    })
    
    # 发送邮件
    send_mail(
        subject,
        message,
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
        html_message=message
    )


def send_password_reset_email(user, uid, token, request):
    """发送密码重置邮件"""
    # 构建重置链接
    reset_url = f"{settings.FRONTEND_URL}/reset-password?uid={uid}&token={token}"
    
    # 渲染邮件内容
    subject = "重置您的密码"
    message = render_to_string('email/password_reset_email.html', {
        'user': user,
        'reset_url': reset_url,
        'app_name': settings.APP_NAME
    })
    
    # 发送邮件
    send_mail(
        subject,
        message,
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
        html_message=message
    )


def send_sms_verification(user, request):
    """发送手机验证码"""
    # 生成6位验证码
    code = ''.join(random.choices('0123456789', k=6))
    cache_key = f"phone_verify:{user.id}"
    cache.set(cache_key, code, timeout=300)  # 5分钟有效
    
    # 使用Twilio发送短信
    if settings.TWILIO_ENABLED:
        client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
        client.messages.create(
            body=f"您的验证码是: {code}",
            from_=settings.TWILIO_PHONE_NUMBER,
            to=user.phone
        )