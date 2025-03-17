# views.py
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from .models import Device, Threat
from django.views.decorators.csrf import csrf_exempt

def threats_page(request):
    return render(request, "threats.html")

def threats_list(request):
    threats = Threat.objects.select_related("log", "rule").order_by("-detected_at")
    data = [
        {
            "id": threat.id,
            "rule": threat.rule.name,
            "severity": threat.rule.get_severity_display(),
            "log_message": threat.log.message[:100],  # Trimmed for preview
            "detected_at": threat.detected_at.strftime("%Y-%m-%d %H:%M:%S"),
        }
        for threat in threats
    ]
    return JsonResponse(data, safe=False)


def device_list(request):
    devices = Device.objects.all()
    return render(request, 'device_list.html', {'devices': devices})

def toggle_device_auth(request, device_id):
    device = get_object_or_404(Device, id=device_id)
    device.is_authorized = not device.is_authorized
    device.save()
    return JsonResponse({"status": "success", "is_authorized": device.is_authorized})

# templates/device_list.html
"""
<!DOCTYPE html>
<html>
<head>
    <title>Device Management</title>
    <script>
        function toggleAuth(deviceId) {
            fetch(`/toggle_device_auth/${deviceId}/`, {method: 'POST'})
            .then(response => response.json())
            .then(data => {
                let btn = document.getElementById(`auth-btn-${deviceId}`);
                btn.innerText = data.is_authorized ? 'Block' : 'Authorize';
                btn.style.backgroundColor = data.is_authorized ? 'red' : 'green';
            });
        }
    </script>
</head>
<body>
    <h2>Device Management</h2>
    <table border="1">
        <tr>
            <th>Hostname</th>
            <th>IP Address</th>
            <th>MAC Address</th>
            <th>Status</th>
            <th>Action</th>
        </tr>
        {% for device in devices %}
        <tr>
            <td>{{ device.hostname }}</td>
            <td>{{ device.ip_address }}</td>
            <td>{{ device.mac_address }}</td>
            <td>{{ "Authorized" if device.is_authorized else "Blocked" }}</td>
            <td>
                <button id="auth-btn-{{ device.id }}" style="background-color: {{ 'red' if device.is_authorized else 'green' }}; color: white;" onclick="toggleAuth({{ device.id }})">
                    {{ "Block" if device.is_authorized else "Authorize" }}
                </button>
            </td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
"""
def logs_view(request):
    return render(request, 'logs.html')



@csrf_exempt  # Temporary: Use CSRF token properly instead
def update_device_status(request, action, device_id):
    if request.method != "POST":
        return JsonResponse({"message": "Invalid request"}, status=400)

    device = get_object_or_404(Device, id=device_id)

    if action == "authorize":
        device.is_authorized = True
    elif action == "block":
        device.is_authorized = False
    else:
        return JsonResponse({"message": "Invalid action"}, status=400)

    device.save()
    return JsonResponse({"message": f"Device {device.hostname} is now {'Authorized' if device.is_authorized else 'Blocked'}"})

def device_list(request):
    devices = Device.objects.all()
    return render(request, "devices.html", {"devices": devices})

def rules_page(request):
    return render(request, "rules.html")
