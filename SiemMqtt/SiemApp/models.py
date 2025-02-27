from django.db import models

class Log(models.Model):
    timestamp = models.DateTimeField()
    topic = models.CharField(max_length=255, default="unknown")  # Default topic if missing
    publisher_id = models.CharField(max_length=255, default="unknown")  # New Field
    message = models.TextField()
    qos = models.IntegerField(default=0)  # QoS defaults to 0
    retain = models.BooleanField(default=False)  # Retain defaults to False

    def __str__(self):
        return f"[{self.timestamp}] {self.topic}: {self.message}"
