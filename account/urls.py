from django.contrib import admin
from django.urls import path, include
from . import views



urlpatterns = [
    path('register/', views.UserRegistrationView.as_view(), name= 'register'),
    path('login/', views.UserLoginView.as_view()),
    path('profile/', views.UserProfileView.as_view(), name='profile'),
    path('changepassword/', views.UserChangePasswordView.as_view(), name='changepassword'),
    path('send-reset-password-email/', views.SendPasswordResetEmailView.as_view(), name='send-reset-password-email'),
    path('reset-password/<uid>/<token>/', views.UserPasswordResetView.as_view(), name='reset-password'),
    path('search/', views.UserSearchView.as_view(), name='user-search'),
    path('friend-request/', views.FriendRequestCreateView.as_view(), name='friend-request'),
    path('friend-request/action/<int:pk>/', views.FriendRequestActionView.as_view(), name='friend-request-action'),
    path('friends/', views.FriendListView.as_view(), name='friend-list'),
   

]