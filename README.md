# 클라우드 보안 감시자(Cloud Security Sentinel)

AWS Terraform 인프라 코드의 보안 취약점을 감지하고 NIST 800-53 기준으로 등급화하는 GitHub Actions 기반 자동화 보안 시스템입니다.

## 주요 기능

- Terraform IaC 코드의 보안 취약점 자동 스캔
- NIST 800-53 표준에 따른 취약점 등급화
- CRITICAL 취약점 발견 시 자동 워크플로우 차단
- 개발자 태깅 및 알림 제공
- 관리자 사원번호 인증을 통한 워크플로우 차단 해제
- 다양한 알림 채널(Slack, 이메일, GitHub 이슈) 지원

## 시스템 아키텍처

클라우드 보안 감시자는 다음과 같은 구성 요소로 이루어져 있습니다:

1. **보안 스캐너**: Terraform 코드를 분석하여 취약점을 감지합니다 (checkov, tfsec 활용)
2. **NIST 등급화 엔진**: 발견된 취약점을 NIST 800-53 컨트롤에 매핑하고 심각도를 판단합니다
3. **워크플로우 컨트롤러**: CRITICAL 취약점 발견 시 배포를 자동 차단합니다
4. **사용자 관리**: 개발자 태깅 및 관리자 인증을 처리합니다
5. **알림 시스템**: 다양한 채널로 취약점 알림을 전송합니다

## 설치 및 설정

### 사전 요구사항

- GitHub 계정 및 저장소
- AWS 인프라 코드 (Terraform)
- Python 3.10 이상

### 설치 방법

1. 이 저장소를 복제합니다:
   ```bash
   git clone https://github.com/your-username/cloud-security-sentinel.git
   cd cloud-security-sentinel
   ```

2. 필요한 패키지를 설치합니다:
   ```bash
   pip install -r requirements.txt
   ```

3. 환경 변수를 설정합니다:
   - `GITHUB_TOKEN`: GitHub API 접근을 위한 토큰
   - `SLACK_WEBHOOK_URL`: Slack 알림을 위한 웹훅 URL (선택사항)
   - `EMAIL_USER` 및 `EMAIL_PASS`: 이메일 알림을 위한 자격 증명 (선택사항)

4. GitHub Actions 환경에 시크릿을 설정합니다:
   - `GITHUB_TOKEN`: GitHub API 접근을 위한 토큰
   - `SECURITY_ADMIN_USERS`: 보안 관리자 사용자 이름 (콤마로 구분)

### 구성 파일 설정

각 구성 파일을 환경에 맞게 수정합니다:

- `config/severity_thresholds.yml`: 심각도 기준 설정
- `config/notification_channels.yml`: 알림 채널 설정
- `config/auth_config.yml`: 인증 관련 설정

## 사용 방법

### 자동 스캔

Terraform 파일(.tf)을 포함한 커밋을 푸시하면 자동으로 스캔이 시작됩니다.

```bash
git add .
git commit -m "Update infrastructure code"
git push
```

GitHub Actions에서 워크플로우가 실행되어 보안 취약점을 검사합니다.

### 수동 스캔

로컬에서 수동으로 스캔을 실행할 수 있습니다:

```bash
python src/run_security_scan.py
```

### 워크플로우 차단 해제

관리자가 차단된 워크플로우를 해제할 수 있습니다:

```bash
python -m src.workflow_control.release_controller --repo owner/repo --commit [commit-sha]
```

## 예제

- `examples/safe/main.tf`: 보안 모범 사례를 따르는 안전한 Terraform 코드 예제
- `examples/vulnerable/main.tf`: 다양한 보안 취약점을 포함한 Terraform 코드 예제

## 심각도 등급

| 심각도 | 설명 | 대응 조치 |
|--------|------|-----------|
| **CRITICAL** | 즉시 해결이 필요한 심각한 취약점 | 워크플로우 자동 차단, 개발자 태깅, 관리자 알림 |
| **HIGH** | 가능한 빨리 해결해야 하는 중요 취약점 | 개발자 알림, 이슈 생성 |
| **MEDIUM** | 계획된 일정 내에 해결해야 하는 취약점 | 개발자 알림 |
| **LOW** | 낮은 위험도의 취약점 | 보고서에 기록 |

## 지원되는 보안 컨트롤

클라우드 보안 감시자는 다음과 같은 NIST 800-53 보안 컨트롤 패밀리를 지원합니다:

- **AC**: 접근 제어 (AC-3, AC-6, AC-17)
- **AU**: 감사 및 책임 (AU-2, AU-6)
- **CM**: 구성 관리 (CM-2, CM-6)
- **IA**: 식별 및 인증 (IA-2, IA-5)
- **RA**: 리스크 평가 (RA-5)
- **SC**: 시스템 및 통신 보호 (SC-7, SC-8, SC-12, SC-13)
- **SI**: 시스템 및 정보 무결성 (SI-4, SI-7)

## 기여하기

프로젝트에 기여하고 싶으시다면:

1. 이 저장소를 포크합니다
2. 새로운 브랜치를 생성합니다 (`git checkout -b feature/amazing-feature`)
3. 변경사항을 커밋합니다 (`git commit -m 'Add amazing feature'`)
4. 브랜치를 푸시합니다 (`git push origin feature/amazing-feature`)
5. Pull Request를 생성합니다

## 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다. 자세한 내용은 [LICENSE](LICENSE) 파일을 참조하세요.

## 문의

문의사항이나 피드백이 있으시면 issues를 통해 알려주세요.