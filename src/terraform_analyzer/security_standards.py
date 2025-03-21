#!/usr/bin/env python3
"""
보안 표준 분석 모듈 - 여러 스캐너의 결과를 통합하고 NIST 800-53 기준으로 분석합니다.
"""
import os
import yaml
import logging
from pathlib import Path

# 로깅 설정
logger = logging.getLogger(__name__)

def load_config():
    """심각도 임계값 설정 파일을 로드합니다."""
    config_path = Path(__file__).parent.parent.parent / "config" / "severity_thresholds.yml"
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.warning(f"설정 파일을 로드하는 중 오류 발생: {e}. 기본 설정을 사용합니다.")
        return {
            "severity_mapping": {
                "checkov": {
                    "HIGH": "CRITICAL",
                    "MEDIUM": "HIGH",
                    "LOW": "MEDIUM",
                    "INFO": "LOW"
                },
                "tfsec": {
                    "HIGH": "CRITICAL",
                    "MEDIUM": "HIGH",
                    "LOW": "MEDIUM",
                    "INFO": "LOW"
                }
            }
        }

def normalize_checkov_results(checkov_results):
    """Checkov 결과를 표준 형식으로 정규화합니다."""
    normalized = []
    config = load_config()
    severity_mapping = config.get("severity_mapping", {}).get("checkov", {})
    
    for result in checkov_results.get("results", {}).get("failed_checks", []):
        original_severity = result.get("severity", "MEDIUM").upper()
        normalized_severity = severity_mapping.get(original_severity, original_severity)
        
        normalized.append({
            "scanner": "checkov",
            "check_id": result.get("check_id", ""),
            "check_name": result.get("check_name", ""),
            "file_path": result.get("file_path", ""),
            "line_start": result.get("file_line_range", [0, 0])[0],
            "line_end": result.get("file_line_range", [0, 0])[1],
            "severity": normalized_severity,
            "resource": result.get("resource", ""),
            "description": result.get("check_name", ""),
            "guideline": result.get("guideline", ""),
            "original": result
        })
    
    return normalized

def normalize_tfsec_results(tfsec_results):
    """tfsec 결과를 표준 형식으로 정규화합니다."""
    normalized = []
    config = load_config()
    severity_mapping = config.get("severity_mapping", {}).get("tfsec", {})
    
    for result in tfsec_results:
        original_severity = result.get("severity", "MEDIUM").upper()
        normalized_severity = severity_mapping.get(original_severity, original_severity)
        
        normalized.append({
            "scanner": "tfsec",
            "check_id": result.get("rule_id", ""),
            "check_name": result.get("rule_description", ""),
            "file_path": result.get("location", {}).get("filename", ""),
            "line_start": result.get("location", {}).get("start_line", 0),
            "line_end": result.get("location", {}).get("end_line", 0),
            "severity": normalized_severity,
            "resource": result.get("resource", ""),
            "description": result.get("description", ""),
            "guideline": result.get("links", []),
            "original": result
        })
    
    return normalized

def map_to_nist_controls(vulnerability):
    """취약점을 NIST 800-53 컨트롤에 매핑합니다."""
    # AWS 서비스 및 취약점 유형별 NIST 컨트롤 매핑
    nist_mapping = {
        # 접근 제어 (AC)
        "aws-iam-no-policy-wildcards": "AC-6",          # 최소 권한 원칙
        "aws-iam-no-user-attached-policies": "AC-6",    # 최소 권한 원칙
        "CKV_AWS_40": "AC-3",                          # AWS S3 공개 접근 차단
        "CKV_AWS_55": "AC-17",                         # AWS 보안 그룹 제한
        
        # 감사 및 책임 (AU)
        "aws-cloudtrail-ensure-enabled": "AU-2",        # 감사 이벤트 활성화
        "CKV_AWS_67": "AU-6",                          # CloudTrail 로그 검증 활성화
        
        # 구성 관리 (CM)
        "aws-s3-encryption-enabled": "CM-6",            # 보안 구성 설정
        "CKV_AWS_18": "CM-2",                          # S3 버킷 로깅 활성화
        
        # 식별 및 인증 (IA)
        "aws-iam-password-policy": "IA-5",              # 인증자 관리
        "CKV_AWS_42": "IA-2",                          # AWS IAM 루트 접근 차단
        
        # 리스크 평가 (RA)
        "aws-vpc-flow-logs-enabled": "RA-5",            # 취약점 스캐닝
        
        # 시스템 및 통신 보호 (SC)
        "aws-vpc-no-public-egress-sgr": "SC-7",         # 경계 보호
        "aws-rds-encryption-enabled": "SC-8",           # 전송 중 암호화
        "CKV_AWS_33": "SC-13",                         # S3 버킷 암호화
        "CKV_AWS_19": "SC-12",                         # KMS 암호화 키 관리
        
        # 시스템 및 정보 무결성 (SI)
        "aws-api-gateway-xray-enabled": "SI-4",         # 정보 시스템 모니터링
        "CKV_AWS_116": "SI-7",                         # 소프트웨어 및 정보 무결성
    }
    
    check_id = vulnerability.get("check_id", "")
    
    # 직접 매핑 시도
    if check_id in nist_mapping:
        return nist_mapping[check_id]
    
    # 패턴 매칭 시도
    for pattern, control in nist_mapping.items():
        if pattern in check_id:
            return control
    
    # AWS 서비스별 기본 매핑
    description = vulnerability.get("description", "").lower()
    if "iam" in description or "identity" in description:
        return "AC-6"
    elif "s3" in description or "storage" in description:
        return "SC-13"
    elif "logging" in description or "monitor" in description:
        return "AU-2"
    elif "encrypt" in description:
        return "SC-13"
    elif "network" in description or "security group" in description:
        return "SC-7"
    
    # 기본값
    return "SI-4"

def analyze_security_standards(checkov_results, tfsec_results):
    """
    여러 스캐너의 결과를 통합하고 NIST 800-53 매핑을 적용합니다.
    """
    # 스캐너 결과 정규화
    normalized_checkov = normalize_checkov_results(checkov_results)
    normalized_tfsec = normalize_tfsec_results(tfsec_results)
    
    # 모든 결과 병합
    all_results = normalized_checkov + normalized_tfsec
    
    # AWS 서비스 감지 및 심각도 조정
    config = load_config()
    aws_service_importance = config.get("aws_service_importance", {})
    
    for vuln in all_results:
        # NIST 컨트롤 매핑
        vuln["nist_control"] = map_to_nist_controls(vuln)
        
        # AWS 서비스 식별 및 심각도 상향 조정
        resource = vuln.get("resource", "").lower()
        description = vuln.get("description", "").lower()
        
        # AWS 서비스 감지
        if "iam" in resource or "iam" in description:
            service = "IAM"
        elif "s3" in resource or "s3" in description:
            service = "S3"
        elif "rds" in resource or "database" in description:
            service = "RDS"
        elif "ec2" in resource or "instance" in description:
            service = "EC2"
        elif "lambda" in resource or "function" in description:
            service = "LAMBDA"
        elif "cloudfront" in resource or "cdn" in description:
            service = "CLOUDFRONT"
        else:
            service = "DEFAULT"
        
        vuln["aws_service"] = service
        
        # 서비스 중요도에 따른 심각도 상향 조정
        service_importance = aws_service_importance.get(service, "LOW")
        current_severity = vuln.get("severity", "LOW")
        
        # 현재 심각도보다 서비스 중요도가 높으면 상향 조정
        severity_levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        if severity_levels.index(service_importance) > severity_levels.index(current_severity):
            vuln["severity"] = service_importance
            vuln["severity_adjusted"] = True
        else:
            vuln["severity_adjusted"] = False
    
    # 카테고리별 취약점 수 계산
    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }
    
    for vuln in all_results:
        severity = vuln.get("severity", "LOW")
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    # 결과 집계
    return {
        "scan_summary": {
            "total_issues": len(all_results),
            "severity_counts": severity_counts,
            "scanners_used": ["checkov", "tfsec"]
        },
        "vulnerabilities": all_results
    }