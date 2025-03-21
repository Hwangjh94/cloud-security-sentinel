#!/usr/bin/env python3
"""
워크플로우 차단 관리 모듈 - CRITICAL 취약점 발견 시 GitHub 워크플로우를 차단합니다.
"""
import os
import sys
import json
import logging
from pathlib import Path
from github import Github

# 프로젝트 모듈 임포트
sys.path.append(str(Path(__file__).parent.parent.parent))
from src.storage.state_manager import get_block_state, set_block_state

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def load_scan_results():
    """스캔 결과를 로드합니다."""
    try:
        with open("scan-results.json", "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"스캔 결과를 로드하는 중 오류 발생: {e}")
        return None

def should_block_workflow(scan_results):
    """워크플로우를 차단해야 하는지 결정합니다."""
    if not scan_results:
        return False
    
    # CRITICAL 취약점 확인
    vulnerabilities = scan_results.get("vulnerabilities", [])
    critical_vulns = [v for v in vulnerabilities if v.get("severity") == "CRITICAL"]
    
    return len(critical_vulns) > 0

def block_workflow():
    """워크플로우를 차단하고 관리자의 확인을 요청합니다."""
    # GitHub 토큰 확인
    github_token = os.environ.get("GITHUB_TOKEN")
    if not github_token:
        logger.error("GitHub 토큰이 환경 변수에 설정되지 않았습니다.")
        return False
    
    logger.debug(f"토큰 확인됨: {github_token[:4]}...")
    
    # 저장소 정보 확인
    github_repo = os.environ.get("GITHUB_REPOSITORY")
    if not github_repo:
        logger.error("GitHub 저장소 정보가 환경 변수에 설정되지 않았습니다.")
        return False
    
    logger.debug(f"저장소 정보: {github_repo}")
    
    # 커밋 정보 확인
    commit_sha = os.environ.get("GITHUB_SHA")
    if not commit_sha:
        logger.error("GitHub 커밋 SHA가 환경 변수에 설정되지 않았습니다.")
        return False
    
    # 개발자 정보 확인
    github_actor = os.environ.get("GITHUB_ACTOR")
    if not github_actor:
        logger.error("GitHub 액터 정보가 환경 변수에 설정되지 않았습니다.")
        return False
    
    # 스캔 결과 로드
    scan_results = load_scan_results()
    if not scan_results:
        logger.error("스캔 결과를 로드할 수 없습니다.")
        return False
    
    # 워크플로우 차단 여부 결정
    if not should_block_workflow(scan_results):
        logger.info("워크플로우를 차단할 필요가 없습니다.")
        return True
    
    try:
        # GitHub API 클라이언트 초기화
        g = Github(github_token)
        repo = g.get_repo(github_repo)

        # 커밋 상태 변경 시도
        logger.debug(f"커밋 상태 변경 시도: {commit_sha}")
        status = repo.get_commit(commit_sha).create_status(
            state="failure",
            description="심각한 보안 취약점 발견으로 인해 차단됨",
            context="security-sentinel"
        )
        logger.debug(f"상태 변경 결과: {status.state}")


        # 워크플로우 상태 저장
        block_info = {
            "repository": github_repo,
            "commit_sha": commit_sha,
            "actor": github_actor,
            "blocked_at": set_block_state(github_repo, commit_sha, github_actor),
            "reason": "CRITICAL security vulnerabilities detected",
            "vulnerabilities_count": len([v for v in scan_results.get("vulnerabilities", []) if v.get("severity") == "CRITICAL"])
        }
        
        # PR이 있는 경우 라벨 추가 및 상태 변경
        try:
            prs = repo.get_pulls(state='open', sort='created', base='main')
            for pr in prs:
                pr_commits = pr.get_commits()
                for pr_commit in pr_commits:
                    if pr_commit.sha == commit_sha:
                        # 보안 라벨 추가
                        pr.add_to_labels("security-blocked")
                        
                        # PR에 코멘트 추가
                        comment_body = ":no_entry: **배포 자동 차단됨** :no_entry:\n\n"
                        comment_body += f"이 PR에서 {block_info['vulnerabilities_count']}개의 심각한 보안 취약점이 발견되었습니다.\n"
                        comment_body += "관리자의 검토 및 승인이 필요합니다.\n\n"
                        comment_body += "취약점을 해결하거나 관리자 승인을 받아야 진행할 수 있습니다."
                        
                        pr.create_issue_comment(comment_body)
                        logger.info(f"PR #{pr.number}에 보안 라벨 및 코멘트를 추가했습니다.")
                        break
        except Exception as e:
            logger.warning(f"PR 상태 변경 중 오류 발생: {e}")
        
        # 커밋 상태 변경
        repo.get_commit(commit_sha).create_status(
            state="failure",
            description="심각한 보안 취약점 발견으로 인해 차단됨",
            context="security-sentinel"
        )
        
        logger.info(f"워크플로우가 성공적으로 차단되었습니다. 관리자 승인이 필요합니다.")
        logger.info(f"차단 정보: {block_info}")
        
        # GitHub Actions에서 환경 변수로 차단 상태 전달
        if os.environ.get("GITHUB_ACTIONS") == "true":
            with open(os.environ["GITHUB_OUTPUT"], "a") as f:
                f.write("workflow_blocked=true\n")
                f.write(f"block_reason=CRITICAL_SECURITY_ISSUES\n")
        
        return True
    
    except Exception as e:
        logger.exception(f"워크플로우 차단 중 오류 발생: {e}")
        return False

if __name__ == "__main__":
    success = block_workflow()
    sys.exit(0 if success else 1)