from django.db import models

class Device(models.Model):
    ip_address = models.GenericIPAddressField(unique=True, db_index=True)
    mac_address = models.CharField(max_length=17, unique=True, db_index=True)  
    hostname = models.CharField(max_length=255, blank=True, null=True)
    is_authorized = models.BooleanField(default=True)  
    last_seen = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.hostname or 'Unknown'} ({self.ip_address})"

class Rule(models.Model):
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField()
    pattern = models.CharField(max_length=500)
    severity = models.IntegerField(
        choices=[(1, "Low"), (2, "Medium"), (3, "High"), (4, "Critical")],
        db_index=True
    )

    def __str__(self):
        return f"{self.name} - {self.get_severity_display()}"

class Log(models.Model):
    timestamp = models.DateTimeField(db_index=True)
    topic = models.CharField(max_length=255)
    message = models.TextField()
    qos = models.IntegerField()
    retain = models.BooleanField()
    publisher_id = models.CharField(max_length=255, default="unknown")
    ip = models.GenericIPAddressField(null=True, blank=True, default=None)
    device = models.ForeignKey(Device, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return f"[{self.timestamp}] {self.topic}: {self.message[:50]}..."

class Threat(models.Model):
    log = models.ForeignKey(Log, on_delete=models.CASCADE)
    rule = models.ForeignKey(Rule, on_delete=models.CASCADE)
    detected_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Threat: {self.rule.name} detected in Log {self.log.id}"

class Alert(models.Model):
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("sent", "Sent"),
        ("acknowledged", "Acknowledged"),
    ]
    threat = models.ForeignKey(Threat, on_delete=models.CASCADE)
    message = models.TextField()
    sent_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")

    def __str__(self):
        return f"Alert for {self.threat.rule.name} - {self.status}"

class DetectionRule(models.Model):
    rule = models.ForeignKey(Rule, on_delete=models.CASCADE)
    pattern = models.CharField(max_length=500)  

    def __str__(self):
        return f"{self.rule.name} - Pattern: {self.pattern}"
