from django.shortcuts import render
from rest_framework import generics, status, views
from .serializers import RegisterSerialzer, EmailVerificationSerializer
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



class RegisterView(generics.GenericAPIView):
  serializer_class = RegisterSerialzer

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