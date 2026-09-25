# 📋 Báo Cáo Tóm Tắt Least Privilege & Khuyến Nghị Khắc Phục

- **Thời gian quét:** `2026-09-21T04:34:20.792646+00:00`
- **Nguồn dữ liệu:** `live-account (profile=default)`
- **Giai đoạn phân tích:** `stage1_static_analysis, stage2_access_advisor`
- **Tổng số đối tượng cần xem xét:** `16`

## 1. Thống kê mức độ rủi ro

| Mức độ | Số lượng phát hiện | Ý nghĩa |
|:---|:---:|:---|
| 🔴 **Critical** | 30 | Nguy cơ chiếm toàn quyền quản trị (Admin) ngay lập tức |
| 🟠 **High** | 27 | Cấp quyền wildcard hoặc thao tác xóa nhạy cảm trên toàn bộ tài nguyên |
| 🟡 **Medium** | 1066 | Dịch vụ được mở quyền nhưng chưa từng được sử dụng |
| 🔵 **Low** | 59 | Dịch vụ không phát sinh lệnh gọi trong hơn 90 ngày |

## 2. Chi tiết các đối tượng vi phạm & Hướng khắc phục

### 👤 [User] `admin-user-01`
- **ARN:** `arn:aws:iam::123456789012:user/admin-user-01`
- **Nguồn cấp quyền:**
  - Kế thừa từ Group **`AdminGroup-Demo`** ➔ Policy `AdministratorAccess`

> 🚨 **CẢNH BÁO LEO THANG QUYỀN (14 kịch bản):**
> - **`CreatePolicyVersion`** (critical): Create new policy version with elevated privileges
> - **`SetDefaultPolicyVersion`** (critical): Set a previously created permissive policy version as default
> - **`PassRole+Lambda`** (critical): Pass privileged role to Lambda and invoke it
> - **`PassRole+EC2`** (critical): Launch EC2 with privileged instance profile
> - **`PassRole+CloudFormation`** (high): Deploy CloudFormation stack with privileged role
> - **`AttachUserPolicy`** (critical): Attach AdministratorAccess to own user
> - **`AttachGroupPolicy`** (critical): Attach AdministratorAccess to own group
> - **`AttachRolePolicy`** (high): Attach elevated policy to assumable role
> - **`PutUserPolicy`** (critical): Add inline policy to own user
> - **`PutGroupPolicy`** (high): Add inline policy to own group
> - **`AssumeRole`** (medium): Assume role with higher privileges
> - **`PassRole+SageMaker`** (high): Create SageMaker notebook with privileged role
> - **`UpdateAssumeRolePolicy`** (critical): Modify trust policy to assume privileged role
> - **`PassRole+SSM`** (critical): Execute commands on EC2 via SSM with privileged role

> ⚠️ **CẤP QUYỀN TOÀN PHẦN (WILDCARD):**
> - Action `*`: Wildcard action '*' grants broad access

- ❌ **Quyền dư thừa (Chưa từng dùng):** `150` dịch vụ
  - *Ví dụ:* `AWS App2Container`, `Alexa for Business`, `Account access manager`, `AWS Certificate Manager`, `AWS Private Certificate Authority`, `AWS Compute Optimizer Automation`, `AWS Activate`, `AWS Agent Registry`
  - *(Gợi ý: Cần gỡ bỏ toàn bộ 150 dịch vụ này khỏi policy)*
- ⏳ **Dịch vụ bỏ hoang (>90 ngày):** `21` dịch vụ (`AWS Action Recommendations` (117 ngày), `Manage - Amazon API Gateway` (146 ngày), `Amazon CloudWatch Application Insights` (116 ngày), `Amazon Application Recovery Controller - Zonal Shift` (110 ngày), `AWS Billing Console` (116 ngày))

---

### 👤 [User] `test-user-02`
- **ARN:** `arn:aws:iam::123456789012:user/test-user-02`
- **Nguồn cấp quyền:**
  - Gắn trực tiếp ➔ Policy `AdministratorAccess`
  - Gắn trực tiếp ➔ Policy `IAMUserChangePassword`
  - Gắn trực tiếp ➔ Policy `AdministratorAccess-AWSElasticBeanstalk`
  - Gắn trực tiếp ➔ Policy `AdministratorAccess-Amplify`

> 🚨 **CẢNH BÁO LEO THANG QUYỀN (14 kịch bản):**
> - **`CreatePolicyVersion`** (critical): Create new policy version with elevated privileges
> - **`SetDefaultPolicyVersion`** (critical): Set a previously created permissive policy version as default
> - **`PassRole+Lambda`** (critical): Pass privileged role to Lambda and invoke it
> - **`PassRole+EC2`** (critical): Launch EC2 with privileged instance profile
> - **`PassRole+CloudFormation`** (high): Deploy CloudFormation stack with privileged role
> - **`AttachUserPolicy`** (critical): Attach AdministratorAccess to own user
> - **`AttachGroupPolicy`** (critical): Attach AdministratorAccess to own group
> - **`AttachRolePolicy`** (high): Attach elevated policy to assumable role
> - **`PutUserPolicy`** (critical): Add inline policy to own user
> - **`PutGroupPolicy`** (high): Add inline policy to own group
> - **`AssumeRole`** (medium): Assume role with higher privileges
> - **`PassRole+SageMaker`** (high): Create SageMaker notebook with privileged role
> - **`UpdateAssumeRolePolicy`** (critical): Modify trust policy to assume privileged role
> - **`PassRole+SSM`** (critical): Execute commands on EC2 via SSM with privileged role

> ⚠️ **CẤP QUYỀN TOÀN PHẦN (WILDCARD):**
> - Action `*`: Wildcard action '*' grants broad access

- **Phạm vi tài nguyên quá rộng (10 quyền):**
  - `dynamodb:deleteitem`: Cần giới hạn từ `Resource: *` về ARN cụ thể.
  - `s3:putobject`: Cần giới hạn từ `Resource: *` về ARN cụ thể.
  - `lambda:updatefunctioncode`: Cần giới hạn từ `Resource: *` về ARN cụ thể.
  - `dynamodb:deletetable`: Cần giới hạn từ `Resource: *` về ARN cụ thể.
  - `lambda:deletefunction`: Cần giới hạn từ `Resource: *` về ARN cụ thể.
  - `s3:deletebucket`: Cần giới hạn từ `Resource: *` về ARN cụ thể.
  - `sqs:deletequeue`: Cần giới hạn từ `Resource: *` về ARN cụ thể.
  - `s3:deleteobject`: Cần giới hạn từ `Resource: *` về ARN cụ thể.
  - *... và 2 quyền khác.*

- ❌ **Quyền dư thừa (Chưa từng dùng):** `200` dịch vụ
  - *Ví dụ:* `AWS App2Container`, `Alexa for Business`, `AWS IAM Access Analyzer`, `AWS Account Management`, `Account access manager`, `AWS Certificate Manager`, `AWS Private Certificate Authority`, `AWS Compute Optimizer Automation`
  - *(Gợi ý: Cần gỡ bỏ toàn bộ 200 dịch vụ này khỏi policy)*

---

### 🛡️ [Role] `AgentCore-AgentCoreProjec-ApplicationAgentCustomerA-XXXXXXXXXXXX`
- **ARN:** `arn:aws:iam::123456789012:role/AgentCore-AgentCoreProjec-ApplicationAgentCustomerA-XXXXXXXXXXXX`
- **Nguồn cấp quyền:**
  - Gắn trực tiếp ➔ Policy `ApplicationAgentCustomerAssistantAgentRuntimeExecutionRoleDefaultPolicyXXXXXXXX`

- ❌ **Quyền dư thừa (Chưa từng dùng):** `1` dịch vụ
  - *Ví dụ:* `Amazon Bedrock Agentcore`

---

### 🛡️ [Role] `AWSServiceRoleForAccessAnalyzer`
- **ARN:** `arn:aws:iam::123456789012:role/aws-service-role/access-analyzer.amazonaws.com/AWSServiceRoleForAccessAnalyzer`
- **Nguồn cấp quyền:**
  - Gắn trực tiếp ➔ Policy `AccessAnalyzerServiceRolePolicy`

- ❌ **Quyền dư thừa (Chưa từng dùng):** `1` dịch vụ
  - *Ví dụ:* `AWS Organizations`

---

### 🛡️ [Role] `AWSServiceRoleForCloudWatchApplicationSignals`
- **ARN:** `arn:aws:iam::123456789012:role/aws-service-role/application-signals.cloudwatch.amazonaws.com/AWSServiceRoleForCloudWatchApplicationSignals`
- **Nguồn cấp quyền:**
  - Gắn trực tiếp ➔ Policy `CloudWatchApplicationSignalsServiceRolePolicy`

- ❌ **Quyền dư thừa (Chưa từng dùng):** `6` dịch vụ
  - *Ví dụ:* `Amazon CloudWatch Application Signals`, `Amazon EC2 Auto Scaling`, `AWS CloudTrail`, `Amazon CloudWatch`, `Amazon CloudWatch Logs`, `Amazon Resource Group Tagging API`

---

### 🛡️ [Role] `AWSServiceRoleForECS`
- **ARN:** `arn:aws:iam::123456789012:role/aws-service-role/ecs.amazonaws.com/AWSServiceRoleForECS`
- **Nguồn cấp quyền:**
  - Gắn trực tiếp ➔ Policy `AmazonECSServiceRolePolicy`

- ❌ **Quyền dư thừa (Chưa từng dùng):** `6` dịch vụ
  - *Ví dụ:* `Amazon EC2 Auto Scaling`, `AWS Auto Scaling`, `Amazon CloudWatch`, `Amazon EventBridge`, `Amazon CloudWatch Logs`, `AWS Systems Manager`
- ⏳ **Dịch vụ bỏ hoang (>90 ngày):** `2` dịch vụ (`Amazon Route 53` (110 ngày), `AWS Cloud Map` (110 ngày))

---

### 🛡️ [Role] `AWSServiceRoleForElasticLoadBalancing`
- **ARN:** `arn:aws:iam::123456789012:role/aws-service-role/elasticloadbalancing.amazonaws.com/AWSServiceRoleForElasticLoadBalancing`
- **Nguồn cấp quyền:**
  - Gắn trực tiếp ➔ Policy `AWSElasticLoadBalancingServiceRolePolicy`

- ❌ **Quyền dư thừa (Chưa từng dùng):** `2` dịch vụ
  - *Ví dụ:* `Amazon CloudWatch Logs`, `AWS Outposts`

---

### 🛡️ [Role] `AWSServiceRoleForRDS`
- **ARN:** `arn:aws:iam::123456789012:role/aws-service-role/rds.amazonaws.com/AWSServiceRoleForRDS`
- **Nguồn cấp quyền:**
  - Gắn trực tiếp ➔ Policy `AmazonRDSServiceRolePolicy`

- ❌ **Quyền dư thừa (Chưa từng dùng):** `4` dịch vụ
  - *Ví dụ:* `Amazon Kinesis Data Streams`, `Amazon CloudWatch Logs`, `Amazon RDS`, `AWS Secrets Manager`

---

### 🛡️ [Role] `AWSServiceRoleForResourceExplorer`
- **ARN:** `arn:aws:iam::123456789012:role/aws-service-role/resource-explorer-2.amazonaws.com/AWSServiceRoleForResourceExplorer`
- **Nguồn cấp quyền:**
  - Gắn trực tiếp ➔ Policy `AWSResourceExplorerServiceRolePolicy`

- ❌ **Quyền dư thừa (Chưa từng dùng):** `62` dịch vụ
  - *Ví dụ:* `AWS Amplify UI Builder`, `AWS Application Auto Scaling`, `Amazon CloudWatch Application Signals`, `Amazon CloudWatch Application Insights`, `AWS Mainframe Modernization Application Testing`, `Amazon ARC Region switch`, `Amazon Application Recovery Controller - Zonal Shift`, `AWS B2B Data Interchange`
  - *(Gợi ý: Cần gỡ bỏ toàn bộ 62 dịch vụ này khỏi policy)*
- ⏳ **Dịch vụ bỏ hoang (>90 ngày):** `36` dịch vụ (`AWS Certificate Manager` (127 ngày), `Amazon Managed Workflows for Apache Airflow` (102 ngày), `Amazon AppFlow` (134 ngày), `AWS AppSync` (132 ngày), `Amazon Managed Service for Prometheus` (123 ngày))

---

### 🛡️ [Role] `AWSServiceRoleForSupport`
- **ARN:** `arn:aws:iam::123456789012:role/aws-service-role/support.amazonaws.com/AWSServiceRoleForSupport`
- **Nguồn cấp quyền:**
  - Gắn trực tiếp ➔ Policy `AWSSupportServiceRolePolicy`

- ❌ **Quyền dư thừa (Chưa từng dùng):** `200` dịch vụ
  - *Ví dụ:* `AWS IAM Access Analyzer`, `AWS Account Management`, `AWS Certificate Manager`, `AWS Private Certificate Authority`, `AWS DevOps Agent Service`, `Amazon AI Operations`, `Amazon Managed Workflows for Apache Airflow`, `AWS MWAA Serverless`
  - *(Gợi ý: Cần gỡ bỏ toàn bộ 200 dịch vụ này khỏi policy)*

---

### 🛡️ [Role] `AWSServiceRoleForTrustedAdvisor`
- **ARN:** `arn:aws:iam::123456789012:role/aws-service-role/trustedadvisor.amazonaws.com/AWSServiceRoleForTrustedAdvisor`
- **Nguồn cấp quyền:**
  - Gắn trực tiếp ➔ Policy `AWSTrustedAdvisorServiceRolePolicy`

- ❌ **Quyền dư thừa (Chưa từng dùng):** `24` dịch vụ
  - *Ví dụ:* `AWS IAM Access Analyzer`, `Amazon EC2 Auto Scaling`, `AWS Cost Explorer Service`, `AWS CloudFormation`, `Amazon CloudFront`, `AWS CloudTrail`, `Amazon CloudWatch`, `Amazon DynamoDB Accelerator (DAX)`
  - *(Gợi ý: Cần gỡ bỏ toàn bộ 24 dịch vụ này khỏi policy)*

---

### 🛡️ [Role] `cdk-demo12345-cfn-exec-role-123456789012-ap-southeast-1`
- **ARN:** `arn:aws:iam::123456789012:role/cdk-demo12345-cfn-exec-role-123456789012-ap-southeast-1`
- **Nguồn cấp quyền:**
  - Gắn trực tiếp ➔ Policy `AdministratorAccess`

> 🚨 **CẢNH BÁO LEO THANG QUYỀN (14 kịch bản):**
> - **`CreatePolicyVersion`** (critical): Create new policy version with elevated privileges
> - **`SetDefaultPolicyVersion`** (critical): Set a previously created permissive policy version as default
> - **`PassRole+Lambda`** (critical): Pass privileged role to Lambda and invoke it
> - **`PassRole+EC2`** (critical): Launch EC2 with privileged instance profile
> - **`PassRole+CloudFormation`** (high): Deploy CloudFormation stack with privileged role
> - **`AttachUserPolicy`** (critical): Attach AdministratorAccess to own user
> - **`AttachGroupPolicy`** (critical): Attach AdministratorAccess to own group
> - **`AttachRolePolicy`** (high): Attach elevated policy to assumable role
> - **`PutUserPolicy`** (critical): Add inline policy to own user
> - **`PutGroupPolicy`** (high): Add inline policy to own group
> - **`AssumeRole`** (medium): Assume role with higher privileges
> - **`PassRole+SageMaker`** (high): Create SageMaker notebook with privileged role
> - **`UpdateAssumeRolePolicy`** (critical): Modify trust policy to assume privileged role
> - **`PassRole+SSM`** (critical): Execute commands on EC2 via SSM with privileged role

> ⚠️ **CẤP QUYỀN TOÀN PHẦN (WILDCARD):**
> - Action `*`: Wildcard action '*' grants broad access

- ❌ **Quyền dư thừa (Chưa từng dùng):** `198` dịch vụ
  - *Ví dụ:* `AWS App2Container`, `Alexa for Business`, `AWS IAM Access Analyzer`, `AWS Account Management`, `Account access manager`, `AWS Certificate Manager`, `AWS Private Certificate Authority`, `AWS Compute Optimizer Automation`
  - *(Gợi ý: Cần gỡ bỏ toàn bộ 198 dịch vụ này khỏi policy)*

---

### 🛡️ [Role] `cdk-demo12345-deploy-role-123456789012-ap-southeast-1`
- **ARN:** `arn:aws:iam::123456789012:role/cdk-demo12345-deploy-role-123456789012-ap-southeast-1`
- **Nguồn cấp quyền:**
  - Gắn trực tiếp ➔ Policy `default`
  - Gắn trực tiếp ➔ Policy `AWSCloudFormationReadOnlyAccess`

> 🚨 **CẢNH BÁO LEO THANG QUYỀN (1 kịch bản):**
> - **`PassRole+CloudFormation`** (high): Deploy CloudFormation stack with privileged role

- **Phạm vi tài nguyên quá rộng (2 quyền):**
  - `kms:encrypt`: Cần giới hạn từ `Resource: *` về ARN cụ thể.
  - `kms:decrypt`: Cần giới hạn từ `Resource: *` về ARN cụ thể.

- ❌ **Quyền dư thừa (Chưa từng dùng):** `2` dịch vụ
  - *Ví dụ:* `AWS Identity and Access Management`, `AWS Security Token Service`

---

### 🛡️ [Role] `cdk-demo12345-image-publishing-role-123456789012-ap-southeast-1`
- **ARN:** `arn:aws:iam::123456789012:role/cdk-demo12345-image-publishing-role-123456789012-ap-southeast-1`
- **Nguồn cấp quyền:**
  - Gắn trực tiếp ➔ Policy `cdk-demo12345-image-publishing-role-default-policy-123456789012-ap-southeast-1`

- ❌ **Quyền dư thừa (Chưa từng dùng):** `1` dịch vụ
  - *Ví dụ:* `Amazon Elastic Container Registry`

---

### 🛡️ [Role] `cdk-demo12345-lookup-role-123456789012-ap-southeast-1`
- **ARN:** `arn:aws:iam::123456789012:role/cdk-demo12345-lookup-role-123456789012-ap-southeast-1`
- **Nguồn cấp quyền:**
  - Gắn trực tiếp ➔ Policy `LookupRolePolicy`
  - Gắn trực tiếp ➔ Policy `ReadOnlyAccess`

- ❌ **Quyền dư thừa (Chưa từng dùng):** `199` dịch vụ
  - *Ví dụ:* `Alexa for Business`, `AWS IAM Access Analyzer`, `AWS Account Management`, `AWS Certificate Manager`, `AWS Private Certificate Authority`, `AWS Action Recommendations`, `AWS DevOps Agent Service`, `Amazon AI Operations`
  - *(Gợi ý: Cần gỡ bỏ toàn bộ 199 dịch vụ này khỏi policy)*

---

### 🛡️ [Role] `CodeDeployServiceRole`
- **ARN:** `arn:aws:iam::123456789012:role/CodeDeployServiceRole`
- **Nguồn cấp quyền:**
  - Gắn trực tiếp ➔ Policy `AWSCodeDeployRoleForECS`

- **Phạm vi tài nguyên quá rộng (2 quyền):**
  - `s3:getobject`: Cần giới hạn từ `Resource: *` về ARN cụ thể.
  - `sns:publish`: Cần giới hạn từ `Resource: *` về ARN cụ thể.

- ❌ **Quyền dư thừa (Chưa từng dùng):** `7` dịch vụ
  - *Ví dụ:* `Amazon CloudWatch`, `Amazon Elastic Container Service`, `Elastic Load Balancing`, `AWS Identity and Access Management`, `AWS Lambda`, `Amazon S3`, `Amazon SNS`

---
