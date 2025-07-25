"""
Django settings for bytectf_backend project.

Generated by 'django-admin startproject' using Django 5.1.3.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/5.1/ref/settings/
"""
import os
from pathlib import Path
from datetime import timedelta

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = "django-insecure-7o5d(pv^g$-zk=1ohbw211w0^5lh9asmll8@&u_f_+&ixg0x&x"

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.getenv('DJANGO_DEBUG', default=False)

ALLOWED_HOSTS = []


# Application definition

INSTALLED_APPS = [
    # Django 默认内置应用
    "django.contrib.admin",          # Django 管理后台
    "django.contrib.auth",           # 认证系统（用户、权限）
    "django.contrib.contenttypes",   # 内容类型框架（用于通用关系）
    "django.contrib.sessions",      # 会话管理
    "django.contrib.messages",       # 消息框架（用于一次性提示）
    "django.contrib.staticfiles",    # 静态文件管理（CSS/JS/图片等）

    # 第三方库应用
    'rest_framework',               # Django REST framework（构建API）
    'rest_framework.authtoken',     # 用于 Token 认证
    'rest_framework_simplejwt.token_blacklist', # 用于黑名单令牌
    'corsheaders',                  # 跨域资源共享（CORS）支持
    'drf_yasg',                     # API文档生成工具（基于Swagger/OpenAPI）
    'django_otp',                   # One-Time Password（OTP）支持
    'django_otp.plugins.otp_totp',  # TOTP 支持

    # 自定义应用（项目特定功能模块）
    'apps.accounts',                # 用户账户管理（注册/登录/权限等）
    'apps.challenges',              # CTF 题目管理
    'apps.competitions',            # 比赛管理
    'apps.submissions',             # 用户提交记录管理
    'apps.scoreboard',              # 积分榜功能
]

AUTH_USER_MODEL = "accounts.CustomUser"

# API 限流配置
REST_FRAMEWORK = {
    'DEFAULT_THROTTLE_RATES': {
        'user': '1000/day',
        'anon': '100/day',
        'login': '5/minute',
        'register': '10/hour',
        'password_reset': '3/hour',
    },
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.UserRateThrottle',
        'rest_framework.throttling.AnonRateThrottle',
    ],
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',   # JWT 支持
        'rest_framework.authentication.SessionAuthentication',         # Session 支持
        'rest_framework.throttling.UserRateThrottle',                  # 用户限流
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    )
}

# JWT配置
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=30),     # 访问令牌有效期
    'REFRESH_TOKEN_LIFETIME': timedelta(days=3),        # 刷新令牌有效期
    'ROTATE_REFRESH_TOKENS': True,                      # 使用刷新令牌后是否轮换新令牌
    'BLACKLIST_AFTER_ROTATION': True,                   # 轮换后是否将旧令牌加入黑名单
    'UPDATE_LAST_LOGIN': True,                          # 每次登录是否更新用户最后登录时间
    'ALGORITHM': 'HS256',                               # 加密算法
    'SIGNING_KEY': SECRET_KEY,                          # 加密密钥
    'AUTH_HEADER_TYPES': ('Bearer',),                   # 认证头类型
}

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    'django_otp.middleware.OTPMiddleware',
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    'django.middleware.csrf.CsrfViewMiddleware',
    'apps.accounts.middleware.audit.AuditMiddleware',
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"


# Database
# https://docs.djangoproject.com/en/5.1/ref/settings/#databases

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.getenv("POSTGRES_DB", default='bytectf_db'),
        'USER': os.getenv('POSTGRES_USER', default='byteRootctf'),
        'PASSWORD': os.getenv('POSTGRES_PASSWORD', default='<bytectf><root>'),
        'HOST': os.getenv('POSTGRES_HOST', default='127.0.0.1'),
        'PORT': os.getenv('POSTGRES_PORT', default='5432'),
    }
}


# Password validation
# https://docs.djangoproject.com/en/5.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        'OPTIONS': {
            'min_length': 10,
        }
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.1/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.1/howto/static-files/

STATIC_URL = "static/"

# Default primary key field type
# https://docs.djangoproject.com/en/5.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# 邮件配置
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.your-email-provider.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'noreply@yourctf.com'
EMAIL_HOST_PASSWORD = 'your-email-password'
DEFAULT_FROM_EMAIL = 'CTF Platform <noreply@yourctf.com>'

# Twilio配置（短信服务）
TWILIO_ENABLED = True
TWILIO_ACCOUNT_SID = 'your_account_sid'
TWILIO_AUTH_TOKEN = 'your_auth_token'
TWILIO_PHONE_NUMBER = '+1234567890'

# 缓存配置（使用Redis）
CACHES = {
    # 测试
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    }
    # 生产开发
    # 'default': {
    #     'BACKEND': 'django_redis.cache.RedisCache',
    #     'LOCATION': 'redis://127.0.0.1:6379/1',
    #     'OPTIONS': {
    #         'CLIENT_CLASS': 'django_redis.client.DefaultClient',
    #     }
    # }
}

# 会话配置
SESSION_ENGINE = "django.contrib.sessions.backends.cached_db"
SESSION_COOKIE_AGE = 1209600  # 2周
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True

# OPT加密配置，自定义字符串
OTP_TOTP_ISSUER = "ByTeCTF<oPt>/*-"