#!/usr/bin/env python3
"""
개발자 태깅 모듈 - CRITICAL 취약점 발견 시 GitHub에서 개발자를 태깅합니다.
"""
import os
import sys
import json
import logging
from pathlib import Path
from github import Github

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

def tag_developer():
    """CRITICAL 취약점이 발견되면 GitHub에서 개발자를 태깅합니다."""
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

    # CRITICAL 취약점 확인
    vulnerabilities = scan_results.get("vulnerabilities", [])
    critical_vulns = [v for v in vulnerabilities if v.get("severity") == "CRITICAL"]

    if not critical_vulns:
        logger.info("태깅할 CRITICAL 취약점이 없습니다.")
        return True

    try:
        # GitHub API 클라이언트 초기화
        g = Github(github_token)
        repo = g.get_repo(github_repo)
        commit = repo.get_commit(commit_sha)

        # 커밋에 코멘트 추가
        comment_body = f"@{github_actor} :rotating_light: **중요 알림** :rotating_light:\n\n"
        comment_body += f"이 커밋에서 {len(critical_vulns)}개의 심각한 보안 취약점이 발견되었습니다. 즉시 검토가 필요합니다.\n\n"
        
        # 첫 3개의 취약점만 요약하여 표시
        for i, vuln in enumerate(critical_vulns[:3], 1):
            comment_body += f"{i}. **{vuln.get('check_name')}**\n"
            comment_body += f"   - 파일: `{vuln.get('file_path')}`\n"
            comment_body += f"   - 라인: {vuln.get('line_start')}-{vuln.get('line_end')}\n"
            comment_body += f"   - NIST: {vuln.get('nist_control')} ({vuln.get('nist_details', {}).get('name', '')})\n\n"
        
        if len(critical_vulns) > 3:
            comment_body += f"그 외 {len(critical_vulns) - 3}개의 추가 취약점이 발견되었습니다.\n\n"
        
        comment_body += "이 문제가 해결될 때까지 워크플로우가 자동으로 차단됩니다.\n"
        comment_body += "자세한 내용은 생성된 GitHub 이슈를 참조하세요."

        # 코멘트 추가
        commit.create_comment(comment_body)
        logger.info(f"개발자({github_actor})를 성공적으로 태깅했습니다.")
        
        # PR이 있는 경우 PR에도 코멘트 추가
        try:
            prs = repo.get_pulls(state='open', sort='created', base='main')
            for pr in prs:
                pr_commits = pr.get_commits()
                for pr_commit in pr_commits:
                    if pr_commit.sha == commit_sha:
                        pr.create_issue_comment(comment_body)
                        logger.info(f"PR #{pr.number}에 코멘트를 추가했습니다.")
                        break
        except Exception as e:
            logger.warning(f"PR에 코멘트를 추가하는 중 오류 발생: {e}")
        
        return True
    
    except Exception as e:
        logger.exception(f"개발자 태깅 중 오류 발생: {e}")
        return False

if __name__ == "__main__":
    success = tag_developer()
    sys.exit(0 if success else 1)