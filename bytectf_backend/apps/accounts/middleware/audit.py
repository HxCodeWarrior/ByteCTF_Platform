from django.utils import timezone
from apps.accounts.models import AuditLog

class AuditMiddleware:
    """审计日志中间件"""
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # 在视图处理前记录请求信息
        request.audit_log = {
            'start_time': timezone.now(),
            'path': request.path,
            'method': request.method,
            'user': request.user if hasattr(request, 'user') else None
        }
        
        response = self.get_response(request)
        
        # 在视图处理后记录审计日志
        if hasattr(request, 'audit_log') and request.audit_log['user']:
            duration = (timezone.now() - request.audit_log['start_time']).total_seconds()
            
            AuditLog.objects.create(
                user=request.audit_log['user'],
                action='API_REQUEST',
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:255],
                details={
                    'path': request.audit_log['path'],
                    'method': request.audit_log['method'],
                    'status_code': response.status_code,
                    'duration': duration
                }
            )
        
        return response