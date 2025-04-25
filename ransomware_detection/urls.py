from django.contrib import admin
from django.urls import path
from ransomware_detection.views import detect_ransomware, home

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', home, name='home'),
    path('detect/', detect_ransomware, name='detect_ransomware'),
]