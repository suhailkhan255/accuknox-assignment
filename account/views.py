from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from rest_framework.permissions import AllowAny
from account.serializers import (SendPasswordResetEmailSerializer,UserChangePasswordSerializer,
                                  UserLoginSerializer, UserPasswordResetSerializer, UserProfileSerializer, 
                                  UserRegistrationSerializer, FriendRequestSerializer)

from django.contrib.auth import authenticate
from account.rendrers import UserRenderer

from rest_framework import generics
from .models import User, FriendRequest
from django.db.models import Q
from rest_framework.pagination import PageNumberPagination


# Generate Token Manually
def get_tokens_for_user(user):
  refresh = RefreshToken.for_user(user)
  return {
      'refresh': str(refresh),
      'access': str(refresh.access_token),
  }

class UserRegistrationView(APIView):
  renderer_classes = [UserRenderer]
  def post(self, request, format=None):
    serializer = UserRegistrationSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    user = serializer.save()
    token = get_tokens_for_user(user)
    return Response({'token':token, 'msg':'Registration Successful'}, status=status.HTTP_201_CREATED)

class UserLoginView(APIView):
  renderer_classes = [UserRenderer]
  def post(self, request, format=None):
    serializer = UserLoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    email = serializer.data.get('email')
    password = serializer.data.get('password')
    user = authenticate(email=email, password=password)
    if user is not None:
      token = get_tokens_for_user(user)
      return Response({'token':token, 'msg':'Login Success'}, status=status.HTTP_200_OK)
    else:
      return Response({'errors':{'non_field_errors':['Email or Password is not Valid']}}, status=status.HTTP_404_NOT_FOUND)

class UserProfileView(APIView):
  renderer_classes = [UserRenderer]
  permission_classes = [IsAuthenticated]
  def get(self, request, format=None):
    serializer = UserProfileSerializer(request.user)
    return Response(serializer.data, status=status.HTTP_200_OK)

class UserChangePasswordView(APIView):
  renderer_classes = [UserRenderer]
  permission_classes = [IsAuthenticated]
  def post(self, request, format=None):
    serializer = UserChangePasswordSerializer(data=request.data, context={'user':request.user})
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Changed Successfully'}, status=status.HTTP_200_OK)

class SendPasswordResetEmailView(APIView):
  permission_classes = [AllowAny]
  renderer_classes = [UserRenderer]
  def post(self, request, format=None):
    serializer = SendPasswordResetEmailSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Reset link send. Please check your Email'}, status=status.HTTP_200_OK)

class UserPasswordResetView(APIView):
  renderer_classes = [UserRenderer]
  def post(self, request, uid, token, format=None):
    serializer = UserPasswordResetSerializer(data=request.data, context={'uid':uid, 'token':token})
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Reset Successfully'}, status=status.HTTP_200_OK)




class UserSearchPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page_size'
    max_page_size = 100

class UserSearchView(generics.ListAPIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    serializer_class = UserProfileSerializer
    pagination_class = UserSearchPagination
    

    def get_queryset(self):
        search_keyword = self.request.query_params.get('q', '')

        return User.objects.filter(
            Q(email=search_keyword) | Q(name__icontains=search_keyword)
        )



class FriendRequestCreateView(generics.CreateAPIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    queryset = FriendRequest.objects.all()
    serializer_class = FriendRequestSerializer

    def perform_create(self, serializer):
        from_user = self.request.user
        to_user_id = self.request.data.get('to_user')
        to_user = User.objects.get(id=to_user_id)
        
        # Check if a friend request already exists
        if FriendRequest.objects.filter(from_user=from_user, to_user=to_user, is_accepted=False, is_rejected=False).exists():
            return Response({'detail': 'Friend request already sent.'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the inverse friend request exists (to_user sending to_user request)
        if FriendRequest.objects.filter(from_user=to_user, to_user=from_user, is_accepted=False, is_rejected=False).exists():
            return Response({'detail': 'Friend request already exists. You can accept it instead.'}, status=status.HTTP_400_BAD_REQUEST)

        serializer.save(from_user=from_user, to_user=to_user)

class FriendRequestActionView(generics.UpdateAPIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    queryset = FriendRequest.objects.all()
    serializer_class = FriendRequestSerializer

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        action = request.data.get('action')

        if action == 'accept':
            instance.is_accepted = True
            instance.save()

        elif action == 'reject':
            instance.is_rejected = True
            instance.save()

        return Response({'detail': 'Friend request updated successfully.'})


class FriendListView(generics.ListAPIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    serializer_class = UserProfileSerializer

    def get_queryset(self):
        user = self.request.user
        friends = FriendRequest.objects.filter(
            (Q(from_user=user) | Q(to_user=user)) &
            Q(is_accepted=True) &
            Q(is_rejected=False)
        )
        
        friend_ids = []
        for friend in friends:
            friend_ids.append(friend.from_user.id if friend.to_user.id == user.id else friend.to_user.id)

        return User.objects.filter(id__in=friend_ids)

