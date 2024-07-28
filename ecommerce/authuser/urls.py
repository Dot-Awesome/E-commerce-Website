from django.urls import path
from authuser import views

urlpatterns = [
    path('signup/', views.signup, name='signup'),
    path('login/', views.handleLogin, name='handleLogin'),
    path('logout/', views.handleLogout, name='handleLogout'),
    # path('activate/<uidb64>/<token>', views.activateAccountView.as_view(), name='activate'),
]
