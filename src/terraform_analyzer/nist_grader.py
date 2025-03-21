#!/usr/bin/env python3
"""
NIST 등급화 모듈 - 취약점을 NIST 800-53 기준으로 등급화하고 차단 결정을 내립니다.
"""
import os
import yaml
import logging
from pathlib import Path

# 로깅 설정
logger = logging.getLogger(__name__)

def load_blocking_rules():
    """차단 규칙을 로드합니다."""
    config_path = Path(__file__).parent.parent.parent / "config" / "severity_thresholds.yml"
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
            return config.get("blocking_rules", {
                "CRITICAL": True,
                "HIGH": False,
                "MEDIUM": False,
                "LOW": False
            })
    except Exception as e:
        logger.warning(f"차단 규칙을 로드하는 중 오류 발생: {e}. 기본 규칙을 사용합니다.")
        return {
            "CRITICAL": True,
            "HIGH": False,
            "MEDIUM": False,
            "LOW": False
        }

def get_nist_control_details(control_id):
    """NIST 컨트롤에 대한 상세 정보를 반환합니다."""
    # NIST 800-53 주요 컨트롤 정보
    nist_controls = {
        "AC-3": {
            "name": "접근 시행",
            "family": "접근 제어",
            "description": "승인된 인가에 따라 시스템 자원에 대한 논리적 접근을 시행합니다.",
            "importance": "HIGH"
        },
        "AC-6": {
            "name": "최소 권한",
            "family": "접근 제어",
            "description": "조직은 사용자가 임무와 업무 기능을 수행하는 데 필요한 최소한의 권한만을 부여합니다.",
            "importance": "CRITICAL"
        },
        "AC-17": {
            "name": "원격 접근",
            "family": "접근 제어",
            "description": "조직은 원격 접근을 위한 사용 제한, 구성 요구사항, 연결 요구사항을 설정합니다.",
            "importance": "HIGH"
        },
        "AU-2": {
            "name": "감사 이벤트",
            "family": "감사 및 책임",
            "description": "정보 시스템은 감사 대상 이벤트를 추적할 수 있어야 합니다.",
            "importance": "MEDIUM"
        },
        "AU-6": {
            "name": "감사 검토, 분석 및 보고",
            "family": "감사 및 책임",
            "description": "조직은 불법, 비인가, 비정상적인 활동을 감지하기 위해 감사 기록을 검토 및 분석합니다.",
            "importance": "MEDIUM"
        },
        "CM-2": {
            "name": "기준 구성",
            "family": "구성 관리",
            "description": "조직은 정보 시스템에 대한 최신 기준 구성을 개발, 문서화, 유지합니다.",
            "importance": "MEDIUM"
        },
        "CM-6": {
            "name": "구성 설정",
            "family": "구성 관리",
            "description": "조직은 정보 시스템의 필수 구성 설정을 수립하고 이를 적용합니다.",
            "importance": "HIGH"
        },
        "IA-2": {
            "name": "사용자 식별 및 인증",
            "family": "식별 및 인증",
            "description": "정보 시스템은 조직 사용자를 고유하게 식별하고 인증합니다.",
            "importance": "HIGH"
        },
        "IA-5": {
            "name": "인증자 관리",
            "family": "식별 및 인증",
            "description": "조직은 인증자 내용, 생성, 발급, 등록, 관리를 위한 절차를 수립합니다.",
            "importance": "HIGH"
        },
        "RA-5": {
            "name": "취약점 스캐닝",
            "family": "리스크 평가",
            "description": "조직은 정보 시스템 및 애플리케이션에 대한 취약점 스캐닝을 수행합니다.",
            "importance": "HIGH"
        },
        "SC-7": {
            "name": "경계 보호",
            "family": "시스템 및 통신 보호",
            "description": "정보 시스템은 외부 경계 및 주요 내부 경계를 모니터링하고 제어합니다.",
            "importance": "CRITICAL"
        },
        "SC-8": {
            "name": "전송 기밀성 및 무결성",
            "family": "시스템 및 통신 보호",
            "description": "정보 시스템은 정보 전송 과정에서 기밀성과 무결성을 보호합니다.",
            "importance": "HIGH"
        },
        "SC-12": {
            "name": "암호화 키 설정 및 관리",
            "family": "시스템 및 통신 보호",
            "description": "조직은 암호화 키의 설정, 배포, 저장, 접근, 파기를 위한 정책과 절차를 수립합니다.",
            "importance": "HIGH"
        },
        "SC-13": {
            "name": "암호화 보호",
            "family": "시스템 및 통신 보호",
            "description": "정보 시스템은 적용 가능한 법률, 규정에 따라 승인된 암호화를 구현합니다.",
            "importance": "HIGH"
        },
        "SI-4": {
            "name": "정보 시스템 모니터링",
            "family": "시스템 및 정보 무결성",
            "description": "조직은 공격과 잠재적 공격 지표를 탐지하기 위해 정보 시스템을 모니터링합니다.",
            "importance": "HIGH"
        },
        "SI-7": {
            "name": "소프트웨어, 펌웨어, 정보 무결성",
            "family": "시스템 및 정보 무결성",
            "description": "정보 시스템은 무단 변경으로부터 소프트웨어, 펌웨어, 정보를 보호합니다.",
            "importance": "HIGH"
        }
    }
    
    return nist_controls.get(control_id, {
        "name": "알 수 없음",
        "family": "미분류",
        "description": "NIST 컨트롤 정보가 없습니다.",
        "importance": "MEDIUM"
    })

def should_block_deployment(vulnerability):
    """취약점의 심각도를 기반으로 배포 차단 여부를 결정합니다."""
    blocking_rules = load_blocking_rules()
    severity = vulnerability.get("severity", "LOW")
    
    return blocking_rules.get(severity, False)

def enhance_vulnerability_info(vulnerability):
    """취약점 정보를 NIST 컨트롤 정보로 보강합니다."""
    nist_control = vulnerability.get("nist_control", "")
    control_details = get_nist_control_details(nist_control)
    
    vulnerability["nist_details"] = {
        "name": control_details.get("name", ""),
        "family": control_details.get("family", ""),
        "description": control_details.get("description", ""),
        "importance": control_details.get("importance", "MEDIUM")
    }
    
    # NIST 중요도가 심각도보다 높으면 심각도 상향 조정
    nist_importance = control_details.get("importance", "MEDIUM")
    current_severity = vulnerability.get("severity", "LOW")
    
    severity_levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    if severity_levels.index(nist_importance) > severity_levels.index(current_severity):
        vulnerability["severity"] = nist_importance
        vulnerability["severity_adjusted_by_nist"] = True
    else:
        vulnerability["severity_adjusted_by_nist"] = False
    
    # 차단 여부 결정
    vulnerability["should_block"] = should_block_deployment(vulnerability)
    
    return vulnerability

def grade_vulnerabilities(analysis_results):
    """취약점을 NIST 800-53 기준으로 등급화합니다."""
    vulnerabilities = analysis_results.get("vulnerabilities", [])
    
    # 각 취약점에 NIST 정보 추가
    enhanced_vulnerabilities = [enhance_vulnerability_info(vuln) for vuln in vulnerabilities]
    
    # 차단 대상 취약점 필터링
    blocking_vulnerabilities = [vuln for vuln in enhanced_vulnerabilities if vuln.get("should_block", False)]
    
    # NIST 컨트롤 패밀리별 취약점 집계
    nist_family_counts = {}
    for vuln in enhanced_vulnerabilities:
        family = vuln.get("nist_details", {}).get("family", "미분류")
        if family not in nist_family_counts:
            nist_family_counts[family] = 0
        nist_family_counts[family] += 1
    
    # 결과 집계
    graded_results = {
        "scan_summary": analysis_results.get("scan_summary", {}),
        "nist_summary": {
            "family_counts": nist_family_counts,
            "blocking_vulnerabilities_count": len(blocking_vulnerabilities)
        },
        "vulnerabilities": enhanced_vulnerabilities,
        "should_block_deployment": len(blocking_vulnerabilities) > 0
    }
    
    return graded_results