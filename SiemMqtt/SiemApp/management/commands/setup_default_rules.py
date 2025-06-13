from django.core.management.base import BaseCommand
from SiemApp.models import Rule

class Command(BaseCommand):
    help = 'Sets up default security rules for MQTT SIEM'

    def handle(self, *args, **options):
        default_rules = [
            {
                'name': 'Password in Plain Text',
                'description': 'Detects passwords being sent in plain text in MQTT messages',
                'pattern': r'/password[=:]\s*["\']?[\w\d@#$%^&*]+["\']?/i',  # Note the 'r' prefix
                'severity': 3,  # High
            },
            {
                'name': 'High Temperature Alert',
                'description': 'Detects unusually high temperature readings from IoT sensors',
                'pattern': '> 85',  # Assuming temperature is in Fahrenheit
                'severity': 2,  # Medium
            },
            {
                'name': 'System Restart',
                'description': 'Detects system restart messages',
                'pattern': 'restart',
                'severity': 1,  # Low
            },
            {
                'name': 'Failed Authentication',
                'description': 'Detects authentication failures',
                'pattern': r'/auth.*fail|fail.*auth|login.*fail|fail.*login/i',  # Note the 'r' prefix
                'severity': 3,  # High
            },
            {
                'name': 'Suspicious Command',
                'description': 'Detects potentially dangerous commands',
                'pattern': r'/exec|eval|system|cmd|command/i',  # Note the 'r' prefix
                'severity': 4,  # Critical
            },
        ]

        for rule_data in default_rules:
            Rule.objects.get_or_create(
                name=rule_data['name'],
                defaults={
                    'description': rule_data['description'],
                    'pattern': rule_data['pattern'],
                    'severity': rule_data['severity'],
                }
            )
        
        self.stdout.write(self.style.SUCCESS('Successfully created default rules'))