# Source : Anthropic-Cybersecurity-Skills
# AWS IAM Least Privilege & Privilege Escalation Analyzer (`scan.py`)

Công cụ phân tích bảo mật chuyên sâu cho AWS IAM, kết hợp giữa **Phân tích tĩnh cấu hình quyền (Static Policy Analysis)** và **Phân tích động lịch sử truy cập (Dynamic Access Advisor Analysis)** nhằm phát hiện các đường dẫn leo thang đặc quyền (Privilege Escalation) và các vi phạm nguyên tắc đặc quyền tối thiểu (Least Privilege).

---

## 📌 Tính năng nổi bật

### Giai đoạn 1: Phân tích tĩnh chuyên sâu (Static Analysis)
* **Kế thừa quyền từ IAM Group (Group Inheritance):** Tự động liên kết User với các IAM Group mà họ tham gia để gộp đầy đủ cả Inline Policy và Managed Policy của Group (tránh bỏ sót quyền như các công cụ thông thường).
* **Xử lý luật phủ quyết (Explicit Deny Evaluation):** Tuân thủ tuyệt đối logic đánh giá quyền của AWS: tính toán quyền hiệu lực bằng phép trừ tập hợp $\text{Effective} = \text{Allow} - \text{Deny}$ (hỗ trợ cả Deny chính xác, Deny `service:*` và Deny `*`).
* **Phát hiện 14 kịch bản leo thang đặc quyền (Privilege Escalation):** Quét các tổ hợp quyền nguy hiểm dẫn đến chiếm quyền Administrator (như `PassRole+Lambda`, `PassRole+EC2`, `CreatePolicyVersion`, `UpdateAssumeRolePolicy`,...).
* **Kiểm tra quyền Wildcard nguy hiểm:** Cảnh báo các quyền cấp dạng `*` hoặc `service:*` trên các dịch vụ nhạy cảm (`iam:*`, `sts:*`, `ec2:*`, `s3:*`,...).
* **Bắt lỗi thao tác nhạy cảm dùng `Resource: "*"`:** Cảnh báo các API can thiệp dữ liệu trọng yếu (`s3:DeleteBucket`, `dynamodb:PutItem`, `secretsmanager:GetSecretValue`,...) khi không được giới hạn trong ARN tài nguyên cụ thể.
* **Truy vết nguồn gốc quyền (Permission Sources Tracing):** Báo cáo chi tiết từng quyền đến từ đâu (Inline Policy, Managed Policy hay kế thừa từ Group nào).

### Giai đoạn 2: Phân tích động thực tế (Dynamic Analysis via Access Advisor)
* **Tích hợp AWS IAM Access Advisor:** Truy vấn trực tiếp từ AWS để đối chiếu giữa **quyền được cấp** và **quyền thực tế sử dụng**.
* **Phát hiện dịch vụ chưa từng dùng (`never_used`):** Liệt kê các dịch vụ được mở quyền trong Policy nhưng đối tượng chưa bao giờ gọi API một lần nào trong lịch sử.
* **Phát hiện dịch vụ bị bỏ hoang (`inactive`):** Cảnh báo các dịch vụ không phát sinh bất kỳ lệnh gọi nào trong hơn $N$ ngày (mặc định 90 ngày).

---

## ⚙️ Yêu cầu môi trường & Cài đặt

### Yêu cầu
* Hệ điều hành: Windows 10/11, Linux hoặc macOS.
* Python: Phiên bản **3.10 trở lên** (khuyến nghị Python 3.12).
* Thông tin xác thực AWS đã được cấu hình trong `~/.aws/credentials` hoặc qua biến môi trường.

---

## 🚀 Hướng dẫn sử dụng

Chương trình hỗ trợ cả chế độ quét trực tiếp tài khoản AWS và chế độ kiểm thử ngoại tuyến (Offline).

### 1. Quét trực tiếp tài khoản AWS (Toàn diện Stage 1 + Stage 2)
Chế độ đầy đủ nhất: chạy cả kiểm tra tĩnh và phân tích Access Advisor để tìm dịch vụ không dùng trong 90 ngày:

```powershell
python scan.py --check-unused --output live_report.json
```

### 2. Quét trực tiếp nhanh (Chỉ Stage 1)
Nếu chỉ cần kiểm tra cấu hình leo thang quyền và quyền wildcard mà không cần đợi phân tích lịch sử Access Advisor:

```powershell
python scan.py --output live_stage1_report.json
```

### 3. Tùy chỉnh số ngày không hoạt động
Thay đổi ngưỡng thời gian không sử dụng dịch vụ (ví dụ: cắm cờ các dịch vụ không dùng trong **60 ngày**):

```powershell
python scan.py --check-unused --max-unused-days 60 --output report_60days.json
```

### 4. Sử dụng AWS CLI Profile khác
Nếu máy cấu hình nhiều tài khoản AWS:

```powershell
python scan.py --profile my-work-profile --check-unused --output company_report.json
```

### 5. Quét ngoại tuyến từ file JSON (Offline Scan)
Hữu ích khi bạn nhận file kết xuất JSON của tài khoản và muốn phân tích mà không cần kết nối mạng hay cài đặt AWS credentials:

```powershell
python scan.py --input-file test_least_privilege.json --output offline_report.json
```

---

## 📋 Danh sách tham số dòng lệnh (CLI Options)

* `👉 --check-unused`
  * **Chức năng:** Kích hoạt **Stage 2** (gọi IAM Access Advisor phân tích dịch vụ không dùng).
  * **Mặc định:** `Tắt (False)` | *Khuyến nghị: Luôn bật khi quét trực tiếp tài khoản AWS.*

* `👉 --max-unused-days <Số ngày>`
  * **Chức năng:** Thiết lập ngưỡng số ngày không phát sinh lệnh gọi để phân loại dịch vụ vào diện "bỏ hoang" (`inactive`).
  * **Mặc định:** `90` ngày | *Tùy chọn thường dùng: 30, 60, 90, 180.*

* `👉 --output <Tên file>`
  * **Chức năng:** Đường dẫn và tên file JSON kết quả đầu ra.
  * **Mặc định:** `least_privilege_report.json`.

* `👉 --input-file <Đường dẫn file>`
  * **Chức năng:** Chỉ định file JSON cấu hình IAM có sẵn để phân tích ngoại tuyến (Offline scan, không cần kết nối AWS).
  * **Mặc định:** `None` (mặc định sẽ kết nối trực tiếp tài khoản AWS).

* `👉 --profile <Tên profile>`
  * **Chức năng:** Chỉ định AWS CLI profile cụ thể cấu hình trong file `~/.aws/credentials`.
  * **Mặc định:** `None` (sử dụng profile default).

---

## 📑 Cấu trúc file báo cáo JSON đầu ra

Kết quả quét được xuất dưới dạng JSON với cấu trúc phân cấp chuẩn:

```json
{
  "report_time": "2026-09-20T10:28:25.940174+00:00",
  "source": "live-account (profile=default)",
  "stages_run": ["stage1_static_analysis", "stage2_access_advisor"],
  "total_principals_with_findings": 16,
  "severity_summary": {
    "critical": 30,
    "high": 27,
    "medium": 1066,
    "low": 58
  },
  "findings": [
    {
      "principal_type": "User",
      "principal_name": "kudoisseiUser1",
      "arn": "arn:aws:iam::854813112425:user/kudoisseiUser1",
      "permission_sources": [
        {
          "source_type": "group_managed",
          "group_name": "AdminGroup1",
          "policy_name": "AdministratorAccess",
          "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
          "allowed_count": 1,
          "denied_count": 0
        }
      ],
      "denied_actions": [],
      "effective_action_count": 1,
      "escalation_paths": [
        {
          "escalation_path": "PassRole+Lambda",
          "severity": "critical",
          "description": "Pass privileged role to Lambda and invoke it"
        }
      ],
      "wildcard_findings": [
        {
          "action": "*",
          "severity": "critical",
          "finding": "Wildcard action '*' grants broad access"
        }
      ],
      "resource_wildcard_findings": [],
      "unused_services": [
        {
          "service_name": "AWS App2Container",
          "service_namespace": "a2c",
          "status": "never_used",
          "severity": "medium",
          "finding": "Service 'AWS App2Container' (a2c) is granted but has NEVER been used"
        },
        {
          "service_name": "Manage - Amazon API Gateway",
          "service_namespace": "apigateway",
          "status": "inactive",
          "severity": "low",
          "finding": "Service 'Manage - Amazon API Gateway' (apigateway) not used for 144 days (last: 2026-04-28)"
        }
      ]
    }
  ]
}
```

---

## 📊 Công cụ tóm tắt báo cáo trực quan (`summarize.py`)

Do báo cáo quét tài khoản thực tế (`live_least_privilege_report.json`) có thể lên đến **gần 10.000 dòng JSON** (chứa lịch sử Access Advisor của hàng trăm dịch vụ), việc đọc thủ công là bất khả thi.

File **`summarize.py`** được xây dựng để đọc file JSON kết quả và tự động trích xuất bảng điều khiển tóm tắt, chỉ lọc ra:
1. 🚨 **Nguy cơ leo thang đặc quyền Admin** (kèm mô tả kịch bản).
2. ⚠️ **Quyền cấp toàn phần (`*`)** cần thu hồi.
3. 🎯 **Quyền can thiệp dữ liệu có `Resource: "*"`** cần thu hẹp về ARN cụ thể.
4. ❌ **Danh sách dịch vụ dư thừa (chưa từng dùng một lần nào)**.
5. ⏳ **Danh sách dịch vụ bỏ hoang (> 90 ngày)**.
6. 📌 **Nguồn cấp quyền** (chỉ rõ User bị thừa quyền từ Group hay Managed Policy nào để quản trị viên sửa đúng chỗ).

### Cách sử dụng `summarize.py`:

```powershell
# 1. Tóm tắt mặc định ra màn hình console
python summarize.py -i live_least_privilege_report.json

# 2. Xuất báo cáo tóm tắt định dạng Markdown (.md)
python summarize.py -i live_least_privilege_report.json --md summary_report.md

# 3. Xuất báo cáo Dashboard giao diện Web trực quan (.html) - Mở trực tiếp bằng trình duyệt
python summarize.py -i live_least_privilege_report.json --html dashboard.html

# 4. Xuất cả 2 định dạng cùng lúc (vừa .md vừa .html):
python summarize.py -i live_least_privilege_report.json --md summary_report.md --html dashboard.html

# 5. Chỉ xem các IAM Users (bỏ qua các Role nội bộ của AWS để báo cáo gọn gàng):
python summarize.py -i live_least_privilege_report.json --only-users --html user_dashboard.html

# 6. Chỉ lọc ra các lỗi mức độ nguy hiểm (Critical & High):
python summarize.py -i live_least_privilege_report.json --critical-only --html critical_report.html
```

---

## 🔒 Quyền IAM tối thiểu để chạy script (Scanner Least Privilege)

Để bản thân công cụ `scan.py` hoạt động được trên tài khoản AWS theo đúng chuẩn an toàn (chỉ đọc, không có quyền ghi hay sửa đổi hạ tầng), tài khoản chạy script chỉ cần được cấp các quyền sau:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowIAMReadAndAudit",
      "Effect": "Allow",
      "Action": [
        "iam:GetAccountAuthorizationDetails",
        "iam:GenerateServiceLastAccessedDetails",
        "iam:GetServiceLastAccessedDetails"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## 🗑️ Cách gỡ cài đặt (Clean up)

Nếu bạn muốn gỡ bỏ hoàn toàn Python và các thư viện liên quan khỏi máy tính sau khi hoàn thành công việc:

```powershell
# Gỡ bỏ Python và toàn bộ thư viện pip kèm theo
winget uninstall Python.Python.3.12
```
