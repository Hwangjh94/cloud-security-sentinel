#!/usr/bin/env python3
"""
메인 시큐리티 스캔 스크립트 - Terraform 코드를 스캔하고 취약점을 감지합니다.
"""
import os
import sys
import json
import logging
import argparse
import subprocess
from pathlib import Path

# 프로젝트 루트 디렉토리 가져오기
PROJECT_ROOT = Path(__file__).parent.parent.absolute()
sys.path.append(str(PROJECT_ROOT))

# 프로젝트 모듈 임포트
from src.terraform_analyzer.security_standards import analyze_security_standards
from src.terraform_analyzer.nist_grader import grade_vulnerabilities
from src.notification.notification_manager import send_notifications
from src.storage.state_manager import save_scan_state

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(PROJECT_ROOT / "logs" / "security_scan.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def find_terraform_files(scan_path="."):
    """지정된 경로에서 모든 Terraform 파일을 찾습니다."""
    tf_files = []
    logger.info(f"Looking for Terraform files in {scan_path}")
    
    # 경로가 상대 경로인 경우 절대 경로로 변환
    if not os.path.isabs(scan_path):
        scan_path = os.path.join(os.getcwd(), scan_path)
    
    logger.info(f"Using absolute path: {scan_path}")
    
    try:
        for root, _, files in os.walk(scan_path):
            if ".git" in root or "node_modules" in root:
                continue
            for file in files:
                if file.endswith(".tf"):
                    tf_files.append(os.path.join(root, file))
    except Exception as e:
        logger.error(f"Error finding Terraform files: {e}")
    
    logger.info(f"Found {len(tf_files)} Terraform files")
    return tf_files

def run_checkov_scan(tf_files):
    """Checkov를 사용하여 Terraform 파일을 스캔합니다."""
    logger.info("Checkov 스캔이 비활성화되었습니다.")
    return {}  # 빈 결과 반환

def run_tfsec_scan(tf_files):
    """tfsec를 사용하여 Terraform 파일을 스캔합니다."""
    if not tf_files:
        logger.warning("No Terraform files to scan")
        return []
    
    try:
        logger.info("Running tfsec scan...")
        
        # tfsec 명령 준비 - 파일 경로들을 하나의 디렉토리로 처리
        # tfsec는 개별 파일이 아닌 디렉토리를 스캔하므로, 공통 디렉토리를 찾습니다
        unique_dirs = set(os.path.dirname(tf_file) for tf_file in tf_files)
        
        all_results = []
        for scan_dir in unique_dirs:
            logger.info(f"Scanning directory: {scan_dir}")
            cmd = ["tfsec", "--format", "json", scan_dir]
            
            logger.debug(f"Running command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            
            # tfsec는 취약점을 발견하지 못하면 종료 코드 0을 반환합니다
            if result.stdout:
                try:
                    tfsec_output = json.loads(result.stdout)
                    all_results.extend(tfsec_output.get("results", []))
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse tfsec output as JSON: {e}")
                    logger.debug(f"tfsec output: {result.stdout[:500]}...")  # 처음 500자만 기록
            elif result.returncode != 0:
                logger.error(f"tfsec scan failed: {result.stderr}")
        
        logger.info(f"tfsec scan completed with {len(all_results)} findings")
        return all_results
    except Exception as e:
        logger.exception(f"Error running tfsec: {e}")
        return []

def ensure_output_dirs():
    """출력 디렉토리가 존재하는지 확인하고 생성합니다."""
    (PROJECT_ROOT / "logs").mkdir(exist_ok=True)
    (PROJECT_ROOT / "security-reports").mkdir(exist_ok=True)

def main():
    """메인 스캔 함수"""
    # 명령줄 인자 파싱
    parser = argparse.ArgumentParser(description="Terraform 보안 스캔 도구")
    parser.add_argument("--path", default=".", help="스캔할 Terraform 파일 경로 (기본값: 현재 디렉토리)")
    parser.add_argument("--output", default="scan-results.json", help="결과 파일 경로 (기본값: scan-results.json)")
    parser.add_argument("--verbose", "-v", action="store_true", help="상세 로깅 활성화")
    
    args = parser.parse_args()
    
    # 상세 로깅 설정
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # 출력 디렉토리 확인
    ensure_output_dirs()
    
    logger.info("Starting Terraform security scan...")
    logger.info(f"Scan path: {args.path}")
    
    # Terraform 파일 찾기
    tf_files = find_terraform_files(args.path)
    if not tf_files:
        logger.info("No Terraform files found.")
        return 0
    
    # 스캔 실행
    checkov_results = run_checkov_scan(tf_files)
    tfsec_results = run_tfsec_scan(tf_files)
    
    # 취약점 분석
    logger.info("Analyzing vulnerabilities against security standards...")
    vulnerabilities = analyze_security_standards(checkov_results, tfsec_results)
    
    # NIST 800-53 기준으로 등급화
    logger.info("Grading vulnerabilities based on NIST 800-53...")
    graded_results = grade_vulnerabilities(vulnerabilities)
    
    # 결과 저장
    output_file = PROJECT_ROOT / args.output
    with open(output_file, "w") as f:
        json.dump(graded_results, f, indent=2)
    
    logger.info(f"Scan results saved to {output_file}")
    
    # 상태 저장
    save_scan_state(graded_results)
    
    # 알림 전송
    critical_issues = any(vuln["severity"] == "CRITICAL" for vuln in graded_results.get("vulnerabilities", []))
    if critical_issues:
        logger.warning("CRITICAL security issues detected!")
        send_notifications(graded_results, critical=True)
    else:
        logger.info("No critical security issues detected.")
        send_notifications(graded_results, critical=False)
    
    # GitHub Actions 환경에서 실행 중인 경우 출력 설정
    if os.environ.get("GITHUB_ACTIONS") == "true":
        github_output = os.environ.get("GITHUB_OUTPUT")
        if github_output:
            with open(github_output, "a") as f:
                f.write(f"critical_issues={str(critical_issues).lower()}\n")
    
    # 결과 요약 출력
    print("\n===== Scan Summary =====")
    scan_summary = graded_results.get("scan_summary", {})
    print(f"Total issues: {scan_summary.get('total_issues', 0)}")
    severity_counts = scan_summary.get("severity_counts", {})
    for severity, count in severity_counts.items():
        print(f"{severity}: {count}")
    
    # 차단 필요 여부 확인
    if critical_issues:
        print("\n⚠️  CRITICAL issues detected! Workflow should be blocked.")
        return 1  # 비정상 종료 코드
    else:
        print("\n✅ No critical issues detected.")
        return 0  # 정상 종료 코드

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user.")
        sys.exit(130)
    except Exception as e:
        logger.exception(f"Unhandled exception: {e}")
        sys.exit(1)