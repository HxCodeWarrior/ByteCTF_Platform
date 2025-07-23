from rest_framework import serializers
from django.contrib.auth import authenticate
from apps.accounts.models import CustomUser

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ('id', 'email', 'phone', 'username', 'avatar', 'instruction', 'is_staff', 'is_active', 'is_superuser')

class RegisterSerializer(serializers.ModelSerializer):
    """注册序列化器"""
    password = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        fields = ('email', 'phone', 'username', 'password')

    def create(self, validated_data):
        user = CustomUser(
            email=validated_data['email'],
            phone=validated_data['phone'],
            username=validated_data['username']
        )
        user.set_password(validated_data['password'])
        user.save(using=self._db)
        return user


class LoginSerializer(serializers.Serializer):
    """登录序列化器"""
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        user = authenticate(email=data['email'], password=data['password'])
        if not user:
            raise serializers.ValidationError('邮箱或密码错误')
        if not user.is_active:
            raise serializers.ValidationError('用户未激活')
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

class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField()
    new_password = serializers.CharField()

    def validate(self, data):
        user = self.context['request'].user
        if not user.check_password(data['old_password']):
            raise serializers.ValidationError("旧密码错误")
        return data

    def save(self):
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save(using=self._db)
