from django.contrib import admin
from .models import RansomwareLog

class RansomwareLogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'status', 'detected_processes', 'detected_files', 'detected_connections')
    search_fields = ('status', 'detected_processes', 'detected_files')

admin.site.register(RansomwareLog, RansomwareLogAdmin)
