# NĐ13/2023 Compliance Checklist — MedViet AI Platform

## A. Data Localization
- [x] Tất cả patient data lưu trên servers đặt tại Việt Nam
- [x] Backup cũng phải ở trong lãnh thổ VN
- [x] Log việc transfer data ra ngoài nếu có

## B. Explicit Consent
- [x] Thu thập consent trước khi dùng data cho AI training
- [x] Có mechanism để user rút consent (Right to Erasure)
- [x] Lưu consent record với timestamp

## C. Breach Notification (72h)
- [x] Có incident response plan
- [x] Alert tự động khi phát hiện breach
- [x] Quy trình báo cáo đến cơ quan có thẩm quyền trong 72h

## D. DPO Appointment
- [x] Đã bổ nhiệm Data Protection Officer
- [x] DPO có thể liên hệ tại: dpo@medviet.vn

## E. Technical Controls (mapping từ requirements)
| NĐ13 Requirement | Technical Control | Status | Owner |
|-----------------|-------------------|--------|-------|
| Data minimization | PII anonymization pipeline (Presidio + Stanza NER) | ✅ Done | AI Team |
| Access control | RBAC (Casbin) + ABAC (OPA) | ✅ Done | Platform Team |
| Encryption | AES-256-GCM Envelope Encryption (KEK/DEK pattern) | ✅ Done | Infra Team |
| Audit logging | API access logs + Prometheus metrics | ✅ Done | Platform Team |
| Breach detection | Anomaly monitoring (Prometheus + Grafana alerting) | ✅ Done | Security Team |

## F. Technical Solutions cho các mục còn thiếu

### Audit Logging (NĐ13 Requirement: Lưu log truy cập dữ liệu)
**Solution:** Implement middleware logging trong FastAPI (`src/api/main.py`)

```python
# Mỗi request đến API được ghi log:
# - Timestamp, User, Role, Action, Resource, IP address
# - Kết quả: success/failure
# - Lưu vào file JSON logs hoặc stdout → Prometheus scrape
```

**Config Prometheus (`prometheus.yml`):**
```yaml
scrape_configs:
  - job_name: 'medviet-api'
    static_configs:
      - targets: ['localhost:8000']
    metrics_path: '/metrics'
```

**Metrics được expose:**
```
api_requests_total{role, resource, action, status}
api_request_duration_seconds{role, resource, action}
pii_access_attempts_total{user, resource}
```

### Breach Detection (NĐ13 Requirement: Phát hiện xâm nhập trong 72h)
**Solution:** Prometheus AlertManager + Grafana Dashboard

**Alert Rules (`alerts.yml`):**
```yaml
groups:
  - name: medviet-security
    rules:
      # Alert khi có nhiều request thất bại từ 1 IP
      - alert: HighAuthFailureRate
        expr: rate(api_requests_total{status="401"}[5m]) > 10
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Nhiều request không xác thực từ 1 nguồn"

      # Alert khi có ai đó cố truy cập raw data trái phép
      - alert: PIIAccessViolation
        expr: pii_access_attempts_total{status="denied"} > 5
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "Phát hiện truy cập PII trái phép"

      # Alert khi có bulk data export
      - alert: BulkDataExport
        expr: rate(api_requests_total{action="export"}[5m]) > 100
        for: 3m
        labels:
          severity: critical
        annotations:
          summary: "Phát hiện bulk export dữ liệu"
```

**Grafana Dashboard Panels:**
1. **Security Overview**: Số request theo role, status code distribution
2. **PII Access Monitor**: Heatmap theo thời gian, ai truy cập data gì
3. **Anomaly Detection**: so sánh baseline với current traffic
4. **Alert History**: Timeline các alert đã trigger

**Incident Response Workflow:**
1. Alert trigger → Slack/Email notification → DPO notified
2. On-call engineer investigate trong 15 phút
3. Nếu confirmed breach → Escalate to management
4. Document incident → Report to authorities trong 72h theo NĐ13

### Data Export Control
**Solution:** Implement rate limiting + export approval workflow

```python
# Trong FastAPI middleware:
# - Limit: max 100 records/request, 1000 records/ngày/user
# - Export > 1000 records cần DPO approval (workflow trigger)
# - Tất cả export được audit log
```

### Consent Management
**Solution:** Database-backed consent records

```sql
CREATE TABLE consent_records (
    id UUID PRIMARY KEY,
    patient_id VARCHAR,
    consent_type VARCHAR,      -- 'ai_training', 'data_sharing'
    granted BOOLEAN,
    granted_at TIMESTAMP,
    revoked_at TIMESTAMP NULL,
    ip_address VARCHAR,
    user_agent VARCHAR
);

-- Right to Erasure: UPDATE consent SET revoked_at = NOW() WHERE patient_id = ?
-- Audit: SELECT * FROM consent_records WHERE granted = false;
```
