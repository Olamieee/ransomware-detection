from django_q.tasks import schedule
from .views import detect_ransomware

def schedule_detection():
    """Schedule ransomware detection to run every 5 minutes."""
    schedule('ransomware_detection.views.detect_ransomware', schedule_type='I', minutes=5)