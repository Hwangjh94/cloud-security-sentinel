#!/usr/bin/env python3
"""
알림 관리 모듈 - 취약점 발견 시 설정된 채널로 알림을 발송합니다.
"""
import os
import yaml
import json
import smtplib
import logging
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from github import Github

# 로깅 설정
logger = logging.getLogger(__name__)

def load_notification_config():
    """알림 설정을 로드합니다."""
    config_path = Path(__file__).parent.parent.parent / "config" / "notification_channels.yml"
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.warning(f"알림 설정을 로드하는 중 오류 발생: {e}. 기본 설정을 사용합니다.")
        return {
            "notification": {
                "slack": {"enabled": False},
                "email": {"enabled": False},
                "github_issue": {"enabled": True, "severity_levels": ["CRITICAL", "HIGH"]}
            },
            "templates": {
                "critical_subject": "[심각] 보안 취약점 발견",
                "critical_body": "심각한 보안 취약점이 발견되었습니다."
            }
        }

def format_notification_message(vulnerability, config):
    """취약점 정보를 기반으로 알림 메시지를 포맷팅합니다."""
    severity = vulnerability.get("severity", "LOW")
    templates = config.get("templates", {})
    
    if severity == "CRITICAL":
        subject_template = templates.get("critical_subject", "[심각] 보안 취약점 발견: {check_name}")
        body_template = templates.get("critical_body", "심각한 보안 취약점이 발견되었습니다.")
    elif severity == "HIGH":
        subject_template = templates.get("high_subject", "[경고] 보안 취약점 발견: {check_name}")
        body_template = templates.get("high_subject", "중요한 보안 취약점이 발견되었습니다.")
    else:
        subject_template = "[알림] 보안 취약점 발견: {check_name}"
        body_template = "보안 취약점이 발견되었습니다."
    
    # 템플릿 변수 대체
    subject = subject_template.format(
        check_name=vulnerability.get("check_name", "알 수 없는 취약점")
    )
    
    body = body_template.format(
        check_name=vulnerability.get("check_name", "알 수 없는 취약점"),
        file_path=vulnerability.get("file_path", ""),
        line_start=vulnerability.get("line_start", ""),
        line_end=vulnerability.get("line_end", ""),
        resource=vulnerability.get("resource", ""),
        nist_control=vulnerability.get("nist_control", ""),
        guideline=vulnerability.get("guideline", "")
    )
    
    return subject, body

def send_slack_notification(vulnerabilities, config, critical=False):
    """Slack으로 취약점 알림을 전송합니다."""
    slack_config = config.get("notification", {}).get("slack", {})
    if not slack_config.get("enabled", False):
        logger.info("Slack 알림이 비활성화되어 있습니다.")
        return False
    
    webhook_url_env = slack_config.get("webhook_url_env", "SLACK_WEBHOOK_URL")
    webhook_url = os.environ.get(webhook_url_env)
    
    if not webhook_url:
        logger.error(f"Slack 웹훅 URL이 환경 변수({webhook_url_env})에 설정되지 않았습니다.")
        return False
    
    severity_levels = slack_config.get("severity_levels", ["CRITICAL"])
    
    # 심각도 필터링
    filtered_vulns = [v for v in vulnerabilities if v.get("severity") in severity_levels]
    
    if not filtered_vulns:
        logger.info("알림을 보낼 취약점이 없습니다.")
        return True
    
    try:
        # 메시지 구성
        critical_prefix = ":rotating_light: *중요 알림* :rotating_light:\n" if critical else ""
        message = f"{critical_prefix}*보안 취약점 스캔 결과*\n\n"
        
        for i, vuln in enumerate(filtered_vulns[:5], 1):  # 최대 5개 표시
            severity = vuln.get("severity", "LOW")
            emoji = ":red_circle:" if severity == "CRITICAL" else ":warning:" if severity == "HIGH" else ":information_source:"
            
            message += f"{emoji} *{severity}* - {vuln.get('check_name')}\n"
            message += f"  • 파일: `{vuln.get('file_path')}`\n"
            message += f"  • 리소스: `{vuln.get('resource', '알 수 없음')}`\n"
            message += f"  • NIST: `{vuln.get('nist_control', '미상')}` ({vuln.get('nist_details', {}).get('name', '')})\n\n"
        
        if len(filtered_vulns) > 5:
            message += f"외 {len(filtered_vulns) - 5}개의 추가 취약점이 발견되었습니다.\n"
        
        # 요청 데이터
        slack_data = {
            "text": message,
            "username": slack_config.get("username", "보안 감시자"),
            "icon_emoji": slack_config.get("icon_emoji", ":lock:"),
            "channel": slack_config.get("channel", "#보안-알림")
        }
        
        # 전송
        response = requests.post(
            webhook_url,
            data=json.dumps(slack_data),
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code != 200:
            logger.error(f"Slack 알림 전송 실패: {response.status_code} - {response.text}")
            return False
        
        logger.info("Slack 알림이 성공적으로 전송되었습니다.")
        return True
    
    except Exception as e:
        logger.exception(f"Slack 알림 전송 중 오류 발생: {e}")
        return False

def send_email_notification(vulnerabilities, config, critical=False):
    """이메일로 취약점 알림을 전송합니다."""
    email_config = config.get("notification", {}).get("email", {})
    if not email_config.get("enabled", False):
        logger.info("이메일 알림이 비활성화되어 있습니다.")
        return False
    
    # 환경 변수에서 자격 증명 로드
    smtp_user_env = email_config.get("smtp_user_env", "EMAIL_USER")
    smtp_pass_env = email_config.get("smtp_pass_env", "EMAIL_PASS")
    
    smtp_user = os.environ.get(smtp_user_env)
    smtp_pass = os.environ.get(smtp_pass_env)
    
    if not smtp_user or not smtp_pass:
        logger.error(f"SMTP 자격 증명이 환경 변수에 설정되지 않았습니다.")
        return False
    
    severity_levels = email_config.get("severity_levels", ["CRITICAL"])
    
    # 심각도 필터링
    filtered_vulns = [v for v in vulnerabilities if v.get("severity") in severity_levels]
    
    if not filtered_vulns:
        logger.info("이메일로 알림을 보낼 취약점이 없습니다.")
        return True
    
    try:
        # SMTP 서버 설정
        smtp_server = email_config.get("smtp_server", "smtp.example.com")
        smtp_port = email_config.get("smtp_port", 587)
        
        # 수신자 리스트
        admin_emails = email_config.get("admin_emails", [])
        if not admin_emails:
            logger.error("이메일 수신자가 설정되지 않았습니다.")
            return False
        
        # 이메일 구성
        msg = MIMEMultipart()
        msg["From"] = email_config.get("from_email", "security-sentinel@example.com")
        msg["To"] = ", ".join(admin_emails)
        
        if critical:
            msg["Subject"] = "[심각] AWS 보안 취약점 즉시 검토 필요"
        else:
            msg["Subject"] = "AWS 보안 취약점 스캔 결과"
        
        # HTML 형식 이메일 본문
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .critical {{ color: red; font-weight: bold; }}
                .high {{ color: orange; font-weight: bold; }}
                .medium {{ color: blue; }}
                .low {{ color: green; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                tr:nth-child(even) {{ background-color: #f9f9f9; }}
            </style>
        </head>
        <body>
            <h2>AWS Terraform 보안 취약점 스캔 결과</h2>
            <p>{"<span class='critical'>❗ 중요 알림: 심각한 취약점이 발견되어 배포가 자동으로 차단되었습니다.</span>" if critical else ""}</p>
            <table>
                <tr>
                    <th>심각도</th>
                    <th>취약점</th>
                    <th>파일</th>
                    <th>리소스</th>
                    <th>NIST 컨트롤</th>
                </tr>
        """
        
        for vuln in filtered_vulns:
            severity = vuln.get("severity", "LOW")
            severity_class = severity.lower()
            
            html += f"""
                <tr>
                    <td class="{severity_class}">{severity}</td>
                    <td>{vuln.get('check_name', '알 수 없음')}</td>
                    <td>{vuln.get('file_path', '')} (라인: {vuln.get('line_start', '?')}-{vuln.get('line_end', '?')})</td>
                    <td>{vuln.get('resource', '알 수 없음')}</td>
                    <td>{vuln.get('nist_control', '미상')} - {vuln.get('nist_details', {}).get('name', '')}</td>
                </tr>
            """
        
        html += """
            </table>
            <p>자세한 정보는 첨부된 보안 보고서를 참조하세요.</p>
        </body>
        </html>
        """
        
        msg.attach(MIMEText(html, 'html'))
        
        # 이메일 전송
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        
        logger.info(f"이메일이 {len(admin_emails)}명의 관리자에게 성공적으로 전송되었습니다.")
        return True
    
    except Exception as e:
        logger.exception(f"이메일 알림 전송 중 오류 발생: {e}")
        return False

def create_github_issue(vulnerabilities, config, critical=False):
    """GitHub 이슈를 생성합니다."""
    github_config = config.get("notification", {}).get("github_issue", {})
    if not github_config.get("enabled", False):
        logger.info("GitHub 이슈 생성이 비활성화되어 있습니다.")
        return False
    
    # GitHub 토큰 확인
    github_token = os.environ.get("GITHUB_TOKEN")
    if not github_token:
        logger.error("GitHub 토큰이 환경 변수에 설정되지 않았습니다.")
        return False
    
    # 저장소 정보 확인
    github_repo = os.environ.get("GITHUB_REPOSITORY")
    if not github_repo:
        logger.error("GitHub 저장소 정보가 환경 변수에 설정되지 않았습니다.")
        return False
    
    severity_levels = github_config.get("severity_levels", ["CRITICAL", "HIGH"])
    
    # 심각도 필터링
    filtered_vulns = [v for v in vulnerabilities if v.get("severity") in severity_levels]
    
    if not filtered_vulns:
        logger.info("GitHub 이슈를 생성할 취약점이 없습니다.")
        return True
    
    try:
        # GitHub API 클라이언트 초기화
        g = Github(github_token)
        repo = g.get_repo(github_repo)
        
        # 이슈 제목
        if critical:
            issue_title = "🚨 심각한 보안 취약점 발견 - 즉시 조치 필요"
        else:
            issue_title = "⚠️ 보안 취약점 발견 - 검토 필요"
        
        # 이슈 본문
        issue_body = "## AWS Terraform 보안 취약점 스캔 결과\n\n"
        
        if critical:
            issue_body += "### ❗ 중요 알림\n"
            issue_body += "심각한 취약점이 발견되어 배포가 자동으로 차단되었습니다. 즉시 검토 후 조치해주세요.\n\n"
        
        issue_body += "### 발견된 취약점\n\n"
        
        for vuln in filtered_vulns:
            severity = vuln.get("severity", "LOW")
            severity_icon = "🔴" if severity == "CRITICAL" else "🟠" if severity == "HIGH" else "🔵" if severity == "MEDIUM" else "🟢"
            
            issue_body += f"{severity_icon} **{severity}**: {vuln.get('check_name')}\n"
            issue_body += f"  - **파일**: `{vuln.get('file_path')}` (라인: {vuln.get('line_start')}-{vuln.get('line_end')})\n"
            issue_body += f"  - **리소스**: `{vuln.get('resource', '알 수 없음')}`\n"
            issue_body += f"  - **NIST 컨트롤**: `{vuln.get('nist_control', '미상')}` ({vuln.get('nist_details', {}).get('name', '')})\n"
            issue_body += f"  - **설명**: {vuln.get('description', '설명 없음')}\n"
            
            if vuln.get("guideline"):
                if isinstance(vuln.get("guideline"), list):
                    issue_body += f"  - **가이드라인**: {', '.join(vuln.get('guideline'))}\n"
                else:
                    issue_body += f"  - **가이드라인**: {vuln.get('guideline')}\n"
            
            issue_body += "\n"
        
        # 커밋 정보 추가
        commit_sha = os.environ.get("GITHUB_SHA")
        github_actor = os.environ.get("GITHUB_ACTOR")
        
        if commit_sha and github_actor:
            issue_body += f"### 커밋 정보\n"
            issue_body += f"- **커밋**: [{commit_sha[:7]}](https://github.com/{github_repo}/commit/{commit_sha})\n"
            issue_body += f"- **작성자**: @{github_actor}\n\n"
        
        # 라벨 설정
        labels = github_config.get("labels", ["security", "vulnerability"])
        
        # 심각도별 추가 라벨
        if any(v.get("severity") == "CRITICAL" for v in filtered_vulns):
            labels.append("critical")
        elif any(v.get("severity") == "HIGH" for v in filtered_vulns):
            labels.append("high")
        
        # 이슈 생성
        issue = repo.create_issue(
            title=issue_title,
            body=issue_body,
            labels=labels
        )
        
        logger.info(f"GitHub 이슈가 성공적으로 생성되었습니다: #{issue.number}")
        return True
    
    except Exception as e:
        logger.exception(f"GitHub 이슈 생성 중 오류 발생: {e}")
        return False

def send_notifications(scan_results, critical=False):
    """모든 설정된 채널로 알림을 전송합니다."""
    config = load_notification_config()
    vulnerabilities = scan_results.get("vulnerabilities", [])
    
    if not vulnerabilities:
        logger.info("알림을 보낼 취약점이 없습니다.")
        return
    
    logger.info(f"알림 전송 시작: 총 {len(vulnerabilities)}개의 취약점")
    
    # Slack 알림
    slack_result = send_slack_notification(vulnerabilities, config, critical)
    
    # 이메일 알림
    email_result = send_email_notification(vulnerabilities, config, critical)
    
    # GitHub 이슈 생성
    github_result = create_github_issue(vulnerabilities, config, critical)
    
    logger.info(f"알림 전송 결과: Slack={slack_result}, 이메일={email_result}, GitHub={github_result}")
    
    return {
        "slack": slack_result,
        "email": email_result,
        "github": github_result
    }