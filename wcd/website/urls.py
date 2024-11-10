from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('login/', views.login_view, name='login_view'),
    path('register/', views.register_view, name='register_view'),
    path('logout/', views.logout_view, name='logout_view'),
    path('analyze/', views.analyze_certificate, name='analyze_certificate'),  
    path('grading-system/', views.grading_system, name='grading_system'),  
    path('security-recommendations/', views.security_recommendations, name='security_recommendations'),
    path('analyzed-urls/', views.analyzed_urls, name='analyzed_urls'),
    path('send_email_view/', views.send_email_view, name='send_email_view'),
    #path('contact/', views.contact_view, name='contact'),
    path('notification_alert/', views.notification_alert, name='notification_alert'),
    path('disclaimer/', views.disclaimer_view, name='disclaimer'),
    path('copyright/', views.copyright_view, name='copyright'),
    path('about/', views.about_view, name='about'),
]

