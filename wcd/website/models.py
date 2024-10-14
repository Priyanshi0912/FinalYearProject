
from django.db import models
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.utils import timezone




class AnalyzedURL(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    url = models.URLField()
    date_analyzed = models.DateTimeField(auto_now_add=True)
    grade = models.CharField(max_length=2, null=True, blank=True)  # Add grade field

    def __str__(self):
        return self.url

from django.db import models

class SSLAnalysis(models.Model):
    url = models.URLField(unique=True)
    expiry_date = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.url
    


class NotificationSettings(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    alerts_on = models.BooleanField(default=False)

    def __str__(self):
        return f'{self.user.username} - Alerts On: {self.alerts_on}'



