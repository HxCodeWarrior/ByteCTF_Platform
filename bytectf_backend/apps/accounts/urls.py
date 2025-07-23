from django.urls import path
from apps.accounts.views.auth import RegisterView, LoginView, LogoutView
from apps.accounts.views.profile import UserProfileView
from apps.accounts.views.password import PasswordChangeView

app_name = 'accounts'

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('password/change/', PasswordChangeView.as_view(), name='password-change'),
]