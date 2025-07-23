from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from apps.accounts.models import CustomUser

class CustomUserAdmin(UserAdmin):
    """
    自定义 CustomUser 模型在 Django 管理后台的显示和行为
    列表显示配置 list_display: 定义在管理后台列表页面中显示的字段
        - email: 用户的邮箱
        - phone: 用户的手机号
        - username: 用户名
        - is_active: 用户是否激活
        - is_staff: 是否为自定义用户
        - is_superuser: 用户是否为超级用户
    列表过滤配置 list_filter: 定义在管理后台列表页面中可用的过滤器
        - is_active: 用户是否激活
        - is_staff: 是否为自定义用户
        - is_superuser: 用户是否为超级用户
    字段分组配置 fieldsets: 定义在管理后台列表页面中可用的字段分组
        - 默认分组 (None): 默认分组，显示字段为 email, username, is_active, is_staff, is_superuser
        - 个人信息分组 (Personal info): 显示字段为 username, phone
        - 权限分组 (Permissions): 显示字段为 is_active, is_staff, is_superuser
    用户表单配置 add_fieldsets: 定义在管理后台添加用户页面中显示的字段
        - classes: ('wide',)：设置表单的 CSS 类，用于调整表单宽度
        - fields: 显示 email、username、password1 和 password2 字段, 其中 password1 和 password2 用于密码输入和确认
    用户搜索配置 search_fields: 定义在管理后台列表页面中可用的搜索字段
    用户排序配置 ordering: 定义在管理后台列表页面中可用的排序字段
    """
    list_display = ('email', 'phone', 'username', 'is_active', 'is_staff', 'is_superuser')
    list_filter = ('is_active', 'is_staff', 'is_superuser')
    search_fields = ('email', 'phone', 'username')
    ordering = ('email', 'phone', 'username')
    readonly_fields = ('create_time', 'update_time')
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('username','phone', 'avatar', 'introduction')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser')}),

    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'phone' ,'username', 'password1', 'password2')}
        ),

    )

# 将 CustomUser 模型注册到 Django 管理后台，并使用自定义的 CustomUserAdmin 类管理
admin.site.register(CustomUser, CustomUserAdmin)
