from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
   
    path('login/', views.login_view, name='login_view'),
    path('register/', views.register_view, name='register_view'),
    path('logout/', views.logout_view, name='logout_view'),
   
    path('analyze/', views.analyze_certificate, name='analyze_certificate'),  # Analysis page
    
    path('grading-system/', views.grading_system, name='grading_system'),  # Grading system page
    path('security-recommendations/', views.security_recommendations, name='security_recommendations'),
 
]