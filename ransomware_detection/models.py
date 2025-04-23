from django.db import models

class RansomwareLog(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    detected_processes = models.TextField(blank=True, null=True)
    detected_files = models.TextField(blank=True, null=True)
    detected_connections = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=20)  # "Benign" or "Ransomware Detected"

    def __str__(self):
        return f"{self.timestamp} - {self.status}"
