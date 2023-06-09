from authentication import views
from django.urls import path, include

urlpatterns = [
    path('',views.home,name='home'),
    path('signup',views.signup,name='signup'),
    path('signin',views.signin,name='signin'),
    path('signout',views.signout,name='signout'),
     path('activate/<uid64>/<token>',views.activate,name='activate'),
    
]
