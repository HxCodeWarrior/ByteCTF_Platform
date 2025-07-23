from django.db import models
from django.contrib.auth.models import AbstractUser, PermissionsMixin, BaseUserManager

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
    email          = models.EmailField("邮箱/Email" ,unique=True)
    phone          = models.CharField("手机号/PhoneNumber" ,max_length=11, unique=True)
    username       = models.CharField("用户名/UserName" ,max_length=15, unique=True)
    avatar         = models.ImageField(upload_to='avatars/', null=True, blank=True, verbose_name="头像")
    introduction   = models.TextField(blank=True, verbose_name="简介")
    create_time    = models.DateTimeField("注册时间/Registration time", auto_now_add=True)
    update_time    = models.DateTimeField("更新时间/Update time", auto_now=True)
    is_staff = models.BooleanField(default=True)
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
