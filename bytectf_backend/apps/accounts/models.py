from django.db import models
from django.contrib.auth.models import AbstractUser, PermissionsMixin, BaseUserManager
from imagekit.models import ProcessedImageField
from imagekit.processors import ResizeToFill

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError("用户必须设置邮箱")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        
        if extra_fields.get('is_staff') is not True:
            raise ValueError("超级用户必须设置 is_staff=True")
        if extra_fields.get('is_superuser') is not True:
            raise ValueError("超级用户必须设置 is_superuser=True.")
        return self.create_user(email, password, **extra_fields)
    


class CustomUser(AbstractUser, PermissionsMixin):
    # 核心字段
    email          = models.EmailField("邮箱/Email" ,unique=True)
    phone          = models.CharField("手机号/PhoneNumber" ,max_length=11, unique=True)
    username       = models.CharField("用户名/UserName" ,max_length=15, unique=True)

    # 安全验证字段
    email_verified = models.BooleanField("邮箱验证状态", default=False)
    phone_verified = models.BooleanField("手机验证状态", default=False)
    two_factor_enabled = models.BooleanField("双因素认证", default=False)
    totp_secret = models.CharField("TOTP密钥", max_length=32, blank=True, null=True)

    # 个人信息字段
    avatar = ProcessedImageField(
        verbose_name="头像",
        upload_to='avatars/',
        processors=[ResizeToFill(300, 300)],
        format='JPEG',
        options={'quality': 90},
        null=True,
        blank=True
    )
    introduction   = models.TextField(blank=True, verbose_name="简介")

    # 时间戳
    create_time    = models.DateTimeField("注册时间/Registration time", auto_now_add=True)
    update_time    = models.DateTimeField("更新时间/Update time", auto_now=True)
    last_login     = models.DateTimeField("最后登录时间", blank=True, null=True)

    # 权限标志
    is_staff       = models.BooleanField(default=True)
    is_active      = models.BooleanField(default=True)
    is_superuser   = models.BooleanField(default=False)

    USERNAME_FIELD  = 'email'                 # 使用邮箱作为登录字段
    REQUIRED_FIELDS = ['username', 'phone']  # 创建超级用户时不需要额外字段

    objects = CustomUserManager()

    def __str__(self):
        return self.email
    
    class Meta:
        verbose_name = "Custom User"
        verbose_name_plural = "Custom Users"
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['phone']),
            models.Index(fields=['create_time']),
        ]



class UserSession(models.Model):
    """用户会话管理模型"""
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='sessions')
    session_key = models.CharField("会话Key", max_length=40)
    ip_address = models.GenericIPAddressField("IP地址")
    user_agent = models.CharField("用户代理", max_length=255)
    created_at = models.DateTimeField("创建时间", auto_now_add=True)
    last_activity = models.DateTimeField("最后活动", auto_now=True)

    class Meta:
        verbose_name = "用户会话"
        verbose_name_plural = "用户会话管理"
        unique_together = ('user', 'session_key')
        
    def __str__(self):
        return f"{self.user.email} - {self.ip_address}"



class AuditLog(models.Model):
    """安全审计日志"""
    ACTION_CHOICES = [
        ('REGISTER', '注册'),
        ('LOGIN', '登录'),
        ('LOGOUT', '登出'),
        ('PASSWORD_CHANGE', '密码修改'),
        ('2FA_ENABLED', '启用双因素认证'),
        ('PROFILE_UPDATE', '资料更新'),
    ]
    
    user       = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True)
    action     = models.CharField("操作类型", max_length=20, choices=ACTION_CHOICES)
    ip_address = models.GenericIPAddressField("IP地址")
    user_agent = models.CharField("用户代理", max_length=255, blank=True)
    timestamp  = models.DateTimeField("操作时间", auto_now_add=True)
    details    = models.JSONField("操作详情", default=dict, blank=True)

    class Meta:
        verbose_name = "审计日志"
        verbose_name_plural = "审计日志管理"
        ordering = ['-timestamp']
        
    def __str__(self):
        return f"{self.get_action_display()} - {self.timestamp}"
