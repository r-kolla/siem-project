# views.py
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from .models import Device, Threat, Log, Rule, Alert
from django.views.decorators.csrf import csrf_exempt
import json
from django.utils import timezone
from datetime import datetime, timedelta
from django.core.paginator import Paginator
from django.db.models import Count
from django.http import HttpResponse
import csv


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


def logs_view(request):
    # Get filter parameters
    topic_filter = request.GET.get('topic', '')
    publisher_filter = request.GET.get('publisher', '')
    ip_filter = request.GET.get('ip', '')
    message_filter = request.GET.get('message', '')
    qos_filter = request.GET.get('qos', '')
    time_range = request.GET.get('time_range', '24h')
    
    # Build queryset with filters
    logs_queryset = Log.objects.all().order_by('-timestamp')
    
    if topic_filter:
        logs_queryset = logs_queryset.filter(topic__icontains=topic_filter)
    if publisher_filter:
        logs_queryset = logs_queryset.filter(publisher_id__icontains=publisher_filter)
    if ip_filter:
        logs_queryset = logs_queryset.filter(ip__icontains=ip_filter)
    if message_filter:
        logs_queryset = logs_queryset.filter(message__icontains=message_filter)
    if qos_filter:
        logs_queryset = logs_queryset.filter(qos=qos_filter)
    
    # Apply time filters
    now = timezone.now()
    if time_range == '1h':
        logs_queryset = logs_queryset.filter(timestamp__gte=now - timedelta(hours=1))
    elif time_range == '6h':
        logs_queryset = logs_queryset.filter(timestamp__gte=now - timedelta(hours=6))
    elif time_range == '24h':
        logs_queryset = logs_queryset.filter(timestamp__gte=now - timedelta(days=1))
    elif time_range == '7d':
        logs_queryset = logs_queryset.filter(timestamp__gte=now - timedelta(days=7))
    elif time_range == '30d':
        logs_queryset = logs_queryset.filter(timestamp__gte=now - timedelta(days=30))
    elif time_range == 'custom':
        start_date = request.GET.get('start_date')
        end_date = request.GET.get('end_date')
        if start_date:
            try:
                from django.utils.dateparse import parse_datetime
                logs_queryset = logs_queryset.filter(timestamp__gte=parse_datetime(start_date))
            except:
                pass
        if end_date:
            try:
                from django.utils.dateparse import parse_datetime
                logs_queryset = logs_queryset.filter(timestamp__lte=parse_datetime(end_date))
            except:
                pass
    
    # Pagination
    paginator = Paginator(logs_queryset, 25)  # 25 logs per page
    page_number = request.GET.get('page', 1)
    logs = paginator.get_page(page_number)
    
    # Generate chart data
    log_activity_data = []
    log_activity_labels = []
    
    # For last 24 hours by hour
    for hour in range(24, -1, -1):
        start_time = now - timedelta(hours=hour)
        end_time = now - timedelta(hours=hour-1) if hour > 0 else now
        count = Log.objects.filter(timestamp__gte=start_time, timestamp__lt=end_time).count()
        log_activity_data.append(count)
        label = start_time.strftime('%H:%M')
        log_activity_labels.append(label)
    
    # Top publishers (top 5)
    top_publishers = Log.objects.values('publisher_id') \
        .annotate(count=Count('publisher_id')) \
        .order_by('-count')[:5]
    top_publishers_labels = [p['publisher_id'] for p in top_publishers]
    top_publishers_data = [p['count'] for p in top_publishers]
    
    # Top topics (top 5)
    top_topics = Log.objects.values('topic') \
        .annotate(count=Count('topic')) \
        .order_by('-count')[:5]
    top_topics_labels = [t['topic'] for t in top_topics]
    top_topics_data = [t['count'] for t in top_topics]
    
    # QoS distribution
    qos_0_count = Log.objects.filter(qos=0).count()
    qos_1_count = Log.objects.filter(qos=1).count()
    qos_2_count = Log.objects.filter(qos=2).count()
    qos_distribution_data = [qos_0_count, qos_1_count, qos_2_count]
    
    # Statistics
    total_logs = Log.objects.count()
    logs_today = Log.objects.filter(timestamp__gte=now.replace(hour=0, minute=0, second=0)).count()
    unique_publishers = Log.objects.values('publisher_id').distinct().count()
    unique_topics = Log.objects.values('topic').distinct().count()
    
    # Build query string for pagination links
    query_params = request.GET.copy()
    if 'page' in query_params:
        del query_params['page']
    query_string = query_params.urlencode()
    
    context = {
        'logs': logs,
        'total_logs': total_logs,
        'logs_today': logs_today,
        'unique_publishers': unique_publishers,
        'unique_topics': unique_topics,
        'log_activity_labels': json.dumps(log_activity_labels),
        'log_activity_data': json.dumps(log_activity_data),
        'top_publishers_labels': json.dumps(top_publishers_labels),
        'top_publishers_data': json.dumps(top_publishers_data),
        'top_topics_labels': json.dumps(top_topics_labels),
        'top_topics_data': json.dumps(top_topics_data),
        'qos_distribution_data': json.dumps(qos_distribution_data),
        'topic_filter': topic_filter,
        'publisher_filter': publisher_filter,
        'ip_filter': ip_filter,
        'message_filter': message_filter,
        'qos_filter': qos_filter,
        'time_range': time_range,
        'query_params': query_string,
    }
    
    return render(request, 'logs.html', context)
def log_detail(request, log_id):
    """API endpoint to get log details"""
    try:
        log = Log.objects.get(id=log_id)
        return JsonResponse({
            'id': log.id,
            'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'topic': log.topic,
            'message': log.message,
            'publisher_id': log.publisher_id,
            'ip': log.ip,
            'qos': log.qos,
            'retain': log.retain,
            'device': log.device.hostname if log.device else 'Unknown'
        })
    except Log.DoesNotExist:
        return JsonResponse({'error': 'Log not found'}, status=404)
    


def export_logs(request):
    """Export logs in the selected format"""
    format_type = request.GET.get('format', 'csv')
    
    # Get logs with any applied filters
    logs = Log.objects.all().order_by('-timestamp')
    
    # Apply the same filters as in logs_view
    topic = request.GET.get('topic', '')
    if topic:
        logs = logs.filter(topic__icontains=topic)
    # Add other filters as needed
    
    if format_type == 'csv':
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="mqtt_logs.csv"'
        
        writer = csv.writer(response)
        writer.writerow(['ID', 'Timestamp', 'Topic', 'Message', 'Publisher ID', 'IP', 'QoS', 'Retain'])
        
        for log in logs:
            writer.writerow([
                log.id,
                log.timestamp,
                log.topic,
                log.message,
                log.publisher_id,
                log.ip or 'Unknown',
                log.qos,
                'Yes' if log.retain else 'No'
            ])
        
        return response
    
    elif format_type == 'json':
        logs_data = [{
            'id': log.id,
            'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'topic': log.topic,
            'message': log.message,
            'publisher_id': log.publisher_id,
            'ip': log.ip or 'Unknown',
            'qos': log.qos,
            'retain': log.retain
        } for log in logs]
        
        response = HttpResponse(json.dumps(logs_data, indent=2), content_type='application/json')
        response['Content-Disposition'] = 'attachment; filename="mqtt_logs.json"'
        return response
    
    # Default to CSV if format is not recognized
    return HttpResponse("Unsupported format")


def rules(request):
    """View for managing security rules"""
    
    # Get all rules
    rules = Rule.objects.all()
    
    # Get rule effectiveness data (last 30 days)
    thirty_days_ago = timezone.now() - timedelta(days=30)
    rule_effectiveness = (
        Threat.objects.filter(detected_at__gte=thirty_days_ago)
        .values('rule__name')
        .annotate(count=Count('id'))
        .order_by('-count')
    )
    
    # Format data for the chart
    chart_labels = []
    chart_data = []
    
    for item in rule_effectiveness:
        chart_labels.append(item['rule__name'])
        chart_data.append(item['count'])
    
    # Ensure we have at least 5 items for the chart (pad with empty values if needed)
    while len(chart_labels) < 5:
        chart_labels.append("")
        chart_data.append(0)
    
    context = {
        'rules': rules,
        'chart_labels': chart_labels,
        'chart_data': chart_data,
    }
    
    return render(request, 'rules.html', context)
def add_rule(request):
    """Add a new rule"""
    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description')
        pattern = request.POST.get('pattern')
        severity = request.POST.get('severity')
        
        if not all([name, description, pattern, severity]):
            return JsonResponse({
                'status': 'error',
                'message': 'All fields are required'
            })
        
        try:
            rule = Rule.objects.create(
                name=name,
                description=description,
                pattern=pattern,
                severity=int(severity)
            )
            
            return JsonResponse({
                'status': 'success',
                'message': 'Rule added successfully',
                'rule': {
                    'id': rule.id,
                    'name': rule.name,
                    'description': rule.description,
                    'pattern': rule.pattern,
                    'severity': rule.severity,
                    'severity_display': rule.get_severity_display()
                }
            })
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': f'Error adding rule: {str(e)}'
            })
    
    return JsonResponse({
        'status': 'error',
        'message': 'Invalid request method'
    })
def edit_rule(request, rule_id):
    """Edit an existing rule"""
    rule = get_object_or_404(Rule, id=rule_id)
    
    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description')
        pattern = request.POST.get('pattern')
        severity = request.POST.get('severity')
        
        if not all([name, description, pattern, severity]):
            return JsonResponse({
                'status': 'error',
                'message': 'All fields are required'
            })
        
        try:
            rule.name = name
            rule.description = description
            rule.pattern = pattern
            rule.severity = int(severity)
            rule.save()
            
            return JsonResponse({
                'status': 'success',
                'message': 'Rule updated successfully',
                'rule': {
                    'id': rule.id,
                    'name': rule.name,
                    'description': rule.description,
                    'pattern': rule.pattern,
                    'severity': rule.severity,
                    'severity_display': rule.get_severity_display()
                }
            })
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': f'Error updating rule: {str(e)}'
            })
    
    return JsonResponse({
        'status': 'error',
        'message': 'Invalid request method'
    })
def delete_rule(request, rule_id):
    """Delete a rule"""
    rule = get_object_or_404(Rule, id=rule_id)
    
    if request.method == 'POST':
        try:
            rule.delete()
            return JsonResponse({
                'status': 'success',
                'message': 'Rule deleted successfully'
            })
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': f'Error deleting rule: {str(e)}'
            })
    
    return JsonResponse({
        'status': 'error',
        'message': 'Invalid request method'
    })


def threats(request):
    """View for displaying and managing threats"""
    
    # Get filter parameters
    severity = request.GET.get('severity', '')
    rule_id = request.GET.get('rule', '')
    start_date = request.GET.get('start_date', '')
    end_date = request.GET.get('end_date', '')
    status = request.GET.get('status', '')
    
    # Base queryset
    threats_query = Threat.objects.all().select_related('rule', 'log', 'log__device').order_by('-detected_at')
    
    # Apply filters
    if severity:
        threats_query = threats_query.filter(rule__severity=severity)
    
    if rule_id:
        threats_query = threats_query.filter(rule_id=rule_id)
    
    if start_date:
        try:
            start = datetime.strptime(start_date, '%Y-%m-%d')
            threats_query = threats_query.filter(detected_at__gte=start)
        except ValueError:
            pass
    
    if end_date:
        try:
            end = datetime.strptime(end_date, '%Y-%m-%d')
            end = end.replace(hour=23, minute=59, second=59)
            threats_query = threats_query.filter(detected_at__lte=end)
        except ValueError:
            pass
    
    if status:
        alerts_with_status = Alert.objects.filter(status=status).values_list('threat_id', flat=True)
        threats_query = threats_query.filter(id__in=alerts_with_status)
    
    # Pagination
    paginator = Paginator(threats_query, 20)  # 20 threats per page
    page_number = request.GET.get('page')
    threats = paginator.get_page(page_number)
    
    # Get all rules for filter dropdown
    rules = Rule.objects.all().order_by('name')
    
    # Get count by severity for the sidebar
    severity_counts = {
        'critical': Threat.objects.filter(rule__severity=4).count(),
        'high': Threat.objects.filter(rule__severity=3).count(),
        'medium': Threat.objects.filter(rule__severity=2).count(),
        'low': Threat.objects.filter(rule__severity=1).count(),
    }
    
    # Get recent threats for timeline
    recent_threats = Threat.objects.all().select_related('rule').order_by('-detected_at')[:10]
    
    context = {
        'threats': threats,
        'rules': rules,
        'severity_counts': severity_counts,
        'recent_threats': recent_threats,
        'filters': {
            'severity': severity,
            'rule': rule_id,
            'start_date': start_date,
            'end_date': end_date,
            'status': status,
        }
    }
    
    return render(request, 'threats.html', context) 

def threat_detail_api(request, threat_id):
    """API endpoint for getting threat details"""
    try:
        threat = Threat.objects.select_related(
            'rule', 'log', 'log__device'
        ).get(id=threat_id)
        
        # Get alerts for this threat
        alerts = threat.alerts.all().order_by('-created_at')
        
        # Format the response data
        data = {
            'id': threat.id,
            'detected_at': threat.detected_at.isoformat(),
            'rule': {
                'id': threat.rule.id,
                'name': threat.rule.name,
                'description': threat.rule.description,
                'pattern': threat.rule.pattern,
                'severity': threat.rule.severity,
                'severity_display': threat.rule.get_severity_display(),
            },
            'log': {
                'id': threat.log.id,
                'timestamp': threat.log.timestamp.isoformat(),
                'topic': threat.log.topic,
                'message': threat.log.message,
                'qos': threat.log.qos,
                'retain': threat.log.retain,
                'publisher_id': threat.log.publisher_id,
                'ip': str(threat.log.ip) if threat.log.ip else None,
            },
            'device': None,
            'alerts': [
                {
                    'id': alert.id,
                    'message': alert.message,
                    'status': alert.status,
                    'status_display': alert.get_status_display(),
                    'created_at': alert.created_at.isoformat(),
                }
                for alert in alerts
            ]
        }
        
        # Add device information if available
        if threat.log.device:
            data['device'] = {
                'id': threat.log.device.id,
                'name': threat.log.device.name,
                'mac_address': threat.log.device.mac_address,
                'ip_address': str(threat.log.device.ip_address),
                'is_authorized': threat.log.device.is_authorized,
            }
        
        return JsonResponse(data)
    
    except Threat.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Threat not found'}, status=404)
    
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
def update_threat_status(request, threat_id):
    """API endpoint for updating threat status"""
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=405)
    
    try:
        # Parse request body
        import json
        data = json.loads(request.body)
        status = data.get('status')
        
        if not status:
            return JsonResponse({'status': 'error', 'message': 'Status is required'}, status=400)
            
        if status not in ['pending', 'in_progress', 'resolved', 'false_positive']:
            return JsonResponse({'status': 'error', 'message': 'Invalid status'}, status=400)
        
        # Get the threat
        threat = Threat.objects.get(id=threat_id)
        
        # Update or create an alert
        alert, created = Alert.objects.update_or_create(
            threat=threat,
            defaults={
                'message': f"Status updated to {status}",
                'status': status
            }
        )
        
        return JsonResponse({'status': 'success', 'message': 'Threat status updated'})
        
    except Threat.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Threat not found'}, status=404)
        
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)