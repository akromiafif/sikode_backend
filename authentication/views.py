from os import stat
from rest_framework import generics, serializers, status, views, permissions
from .serializers import RegisterSerialzer, EmailVerificationSerializer, LoginSerializer, ResetCredentialsSerializer, SetNewPasswordSerializer, LogoutSerializer
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from .utils import Util
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
import jwt
from django.conf import settings
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .renderers import UserRenderer
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .utils import Util
from rest_framework import permissions




class RegisterView(generics.GenericAPIView):
  serializer_class = RegisterSerialzer
  renderer_classes = (UserRenderer,)

  def post(self, request):
    user = request.data
    serializers = self.serializer_class(data=user)
    serializers.is_valid(raise_exception=True)
    serializers.save()

    user_data = serializers.data
    user = User.objects.get(email=user_data['email'])
    token = RefreshToken.for_user(user).access_token

    current_site = get_current_site(request).domain
    relative_link = reverse('email-verify')
    abs_url = 'http://' + current_site + relative_link + "?token=" + str(token)
    email_body = 'Hi ' + user.username + ' Use link below to verify your email \n' + abs_url

    data = {
      'email_body': email_body,
      'email_subject': 'Verify your email',
      'to_email': user.email
    }
    Util.send_email(data)

    return Response(user_data, status=status.HTTP_201_CREATED)


class VerifyEmail(views.APIView):
  serializer_class = EmailVerificationSerializer
  token_param_config = openapi.Parameter('token', in_=openapi.IN_QUERY, description='Description', type=openapi.TYPE_STRING)

  @swagger_auto_schema(manual_parameters=[token_param_config])
  def get(self, request):
    token = request.GET.get('token')

    try:
      payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
      user = User.objects.get(id=payload['user_id'])
      
      if not user.is_verified:          
        user.is_verified = True
        user.save()

      return Response({'email': 'successfully activated'}, status=status.HTTP_200_OK)
    except jwt.ExpiredSignatureError as identifier:
      return Response({'error': 'avtivation link expired'}, status=status.HTTP_400_BAD_REQUEST)
    except jwt.exceptions.DecodeError as identifier:
      return Response({'error': "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)



class LoginAPIView(generics.GenericAPIView):
  serializer_class = LoginSerializer

  def post(self, request):
    serializer = self.serializer_class(data=request.data)
    serializer.is_valid(raise_exception=True)

    return Response(serializer.data, status=status.HTTP_200_OK)



class RequestPasswordResetEmail(generics.GenericAPIView):
  serializer_class = ResetCredentialsSerializer

  def post(self, request):
    serializer = self.serializer_class(data=request.data)
    email = request.data['email']
    
    if User.objects.filter(email=email).exists():
      user = User.objects.get(email=email)
      uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
      token = PasswordResetTokenGenerator().make_token(user)

      current_site = get_current_site(request=request).domain
      relative_link = reverse('password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})
      abs_url = 'http://' + current_site + relative_link
      email_body = 'Hello, \n use link bellow to reset your password ' + abs_url

      data = {
        'email_body': email_body,
        'email_subject': 'Reset your password',
        'to_email': user.email
      }

      Util.send_email(data)

    return Response({'success': 'Password link sent successfully'}, status=status.HTTP_200_OK)



class PasswordTokenCheckAPIView(generics.GenericAPIView):
  serializer_class = ResetCredentialsSerializer
  
  def get(self, request, uidb64, token):
    try:
      id = smart_str(urlsafe_base64_decode(uidb64))
      user = User.objects.get(id=id)

      if not PasswordResetTokenGenerator().check_token(user, token):
        return Response({'error': 'Token us not valid, please request again'}, status=status.HTTP_401_UNAUTHORIZED)

      return Response({'success': True, 'message': 'Credentials is valid', 'uidb64': uidb64, 'token': token}, status=status.HTTP_200_OK)
    except DjangoUnicodeDecodeError as identifier:
      return Response({'error': 'Token us not valid, please request again'}, status=status.HTTP_401_UNAUTHORIZED)



class SetNewPasswordAPIView(generics.GenericAPIView):
  serializer_class = SetNewPasswordSerializer

  def patch(self, request):
    serializer = self.serializer_class(data=request.data)
    serializer.is_valid(raise_exception=True)

    return Response({'success': True, 'message': 'Password reset success'}, status=status.HTTP_200_OK)



class LogoutAPIView(generics.GenericAPIView):
  serializer_class = LogoutSerializer
  permission_classes = (permissions.IsAuthenticated,)

  def post(self, request):
    serializer = self.serializer_class(data=request.data)
    serializer.is_valid(raise_exception=True)
    serializer.save()

    return Response(status=status.HTTP_204_NO_CONTENT)