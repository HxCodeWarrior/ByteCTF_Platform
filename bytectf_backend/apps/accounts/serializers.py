from rest_framework import serializers
from django.contrib.auth import authenticate
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from django_otp.plugins.otp_totp.models import TOTPDevice
from apps.accounts.models import (
    CustomUser, 
    AuditLog,
    UserSession
)

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = (
            'id', 'email', 'phone', 'username', 'avatar', 'introduction', 
            'create_time', 'update_time', 'last_login',
            'email_verified', 'phone_verified', 'two_factor_enabled',
            'create_time', 'update_time', 'last_login')
        read_only_fields = (
            'id', 'is_staff', 'is_active', 'is_superuser',
            'email_verified', 'phone_verified', 'two_factor_enabled',
            'create_time', 'update_time', 'last_login'
        )

class UserSessionSerializer(serializers.ModelSerializer):
    current = serializers.SerializerMethodField()

    class Meta:
        model = UserSession
        fields = ['id', 'ip_address', 'user_agent', 'last_activity', 'current']

    def get_current(self, obj):
        request = self.context.get('request')
        return obj.session_key == getattr(request.session, 'session_key', None)

class RegisterSerializer(serializers.ModelSerializer):
    """注册序列化器"""
    password = serializers.CharField(
        write_only=True, 
        style={'input_type': 'password'},
        min_length=10,
        help_text="密码需至少10位，包含大小写字母、数字和特殊字符"
    )
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
       model = CustomUser
       fields = ('email', 'phone', 'username', 'password', 'confirm_password')
       extra_kwargs = {
           'email': {'required': True},
           'phone': {'required': True},
           'username': {'required': True},
       }

    def validate(self, data):
        # 密码复杂度验证
        try:
            validate_password(data['password'])
        except ValidationError as e:
            raise serializers.ValidationError({'password': e.messages})
        
        # 密码一致性验证
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError({'confirm_password': '两次输入的密码不一致'})
        
        # 邮箱格式验证
        try:
            validate_email(data['email'])
        except ValidationError:
            raise serializers.ValidationError({'email': '邮箱格式无效'})
            
        return data

    def create(self, validated_data):
        user = CustomUser(
            email=validated_data['email'],
            phone=validated_data['phone'],
            username=validated_data['username']
        )
        user.set_password(validated_data['password'])
        user.save()
        
        # 创建审计日志
        AuditLog.objects.create(
            user=user,
            action='REGISTER',
            ip_address=self.context.get('request').META.get('REMOTE_ADDR'),
            user_agent=self.context.get('request').META.get('HTTP_USER_AGENT', ''),
            details={'method': 'email'}
        )
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    totp_code = serializers.CharField(
        required=False, 
        allow_blank=True,
        help_text="启用双因素认证时需要提供"
    )

    def validate(self, data):
        request = self.context.get('request')
        user = authenticate(email=data['email'], password=data['password'])
        
        if not user:
            raise serializers.ValidationError('邮箱或密码错误')
        if not user.is_active:
            raise serializers.ValidationError('用户未激活')
        
        # 双因素认证检查
        if user.two_factor_enabled:
            if 'totp_code' not in data or not data['totp_code']:
                raise serializers.ValidationError(
                    {'totp_code': '该账户启用了双因素认证，请输入验证码'}
                )
                
            # 验证TOTP
            device = TOTPDevice.objects.filter(user=user).first()
            if not device or not device.verify_token(data['totp_code']):
                raise serializers.ValidationError(
                    {'totp_code': '验证码无效或已过期'}
                )
                
        # 更新审计日志
        AuditLog.objects.create(
            user=user,
            action='LOGIN',
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            details={'method': 'email', 'two_factor': user.two_factor_enabled}
        )
        
        return user

class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ('phone', 'username', 'avatar', 'introduction')
        extra_kwargs = {
            'phone':        {'required': False},
            'username':     {'required': False},
            'avatar':       {'required': False},
            'introduction': {'required': False},
        }
    
    def update(self, instance, validated_data):
        # 创建审计日志
        changes = {}
        for field, value in validated_data.items():
            if getattr(instance, field) != value:
                changes[field] = {
                    'old': getattr(instance, field),
                    'new': value
                }
        
        # 保存更新
        updated_user = super().update(instance, validated_data)
        
        if changes:
            AuditLog.objects.create(
                user=instance,
                action='PROFILE_UPDATE',
                ip_address=self.context.get('request').META.get('REMOTE_ADDR'),
                user_agent=self.context.get('request').META.get('HTTP_USER_AGENT', ''),
                details={'changes': changes}
            )
            
        return updated_user

class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(
        write_only=True, 
        min_length=10,
        help_text="密码需至少10位，包含大小写字母、数字和特殊字符"
    )
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, data):
        user = self.context['request'].user
        
        # 旧密码验证
        if not user.check_password(data['old_password']):
            raise serializers.ValidationError({"old_password": "旧密码错误"})
        
        # 密码复杂度验证
        try:
            validate_password(data['new_password'], user=user)
        except ValidationError as e:
            raise serializers.ValidationError({"new_password": e.messages})
        
        # 密码一致性验证
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError({"confirm_password": "两次输入的密码不一致"})
            
        # 新旧密码对比
        if data['old_password'] == data['new_password']:
            raise serializers.ValidationError(
                {"new_password": "新密码不能与旧密码相同"}
            )
            
        return data

    def save(self):
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save()
        
        # 创建审计日志
        AuditLog.objects.create(
            user=user,
            action='PASSWORD_CHANGE',
            ip_address=self.context.get('request').META.get('REMOTE_ADDR'),
            user_agent=self.context.get('request').META.get('HTTP_USER_AGENT', ''),
            details={'method': 'self-service'}
        )


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()
    
    def validate_email(self, value):
        # 验证邮箱是否存在
        if not CustomUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("该邮箱未注册")
        return value


class PasswordResetConfirmSerializer(serializers.Serializer):
    token = serializers.CharField()
    new_password = serializers.CharField(min_length=12)
    confirm_password = serializers.CharField()

    def validate(self, data):
        # 密码一致性验证
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError({"confirm_password": "两次输入的密码不一致"})
            
        # 密码复杂度验证
        try:
            validate_password(data['new_password'])
        except ValidationError as e:
            raise serializers.ValidationError({"new_password": e.messages})
            
        return data


class TwoFactorSetupSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        user = self.context['request'].user
        if not user.check_password(data['password']):
            raise serializers.ValidationError({"password": "密码错误"})
        return data


class TwoFactorVerifySerializer(serializers.Serializer):
    totp_code = serializers.CharField()


class EmailVerificationSerializer(serializers.Serializer):
    token = serializers.CharField()


class PhoneVerificationSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=6)
