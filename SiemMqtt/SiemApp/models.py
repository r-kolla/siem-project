from django.db import models

class Log(models.Model):
    timestamp = models.DateTimeField()
    topic = models.CharField(max_length=255)
    message = models.TextField()
    qos = models.IntegerField()
    retain = models.BooleanField()
    publisher_id = models.CharField(max_length=255, default="unknown")
    ip = models.GenericIPAddressField(default="unknown", null=True, blank=True)  # Add this field

    def __str__(self):
        return f"[{self.timestamp}] {self.topic}: {self.message}"