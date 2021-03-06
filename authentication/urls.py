import django
from django.urls import path
from .views import LogoutAPIView, RegisterView, VerifyEmail, LoginAPIView, PasswordTokenCheckAPIView, RequestPasswordResetEmail, SetNewPasswordAPIView, LoginSerializer
from rest_framework_simplejwt.views import (TokenRefreshView)



urlpatterns = [
   path('register', RegisterView.as_view(), name='register'),
   path('email-verify', VerifyEmail.as_view(), name='email-verify'),
   path('login', LoginAPIView.as_view(), name='login'),
   path('logout', LogoutAPIView.as_view(), name='logout'),
   path('request-reset-email', RequestPasswordResetEmail.as_view(), name='request-reset-email'),
   path('password-reset/<uidb64>/<token>/', PasswordTokenCheckAPIView.as_view(), name='password-reset-confirm'),
   path('password-reset-complete', SetNewPasswordAPIView.as_view(), name='password-reset-complete'),
   path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]