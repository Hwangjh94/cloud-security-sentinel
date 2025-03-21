#!/usr/bin/env python3
"""
워크플로우 차단 해제 모듈 - 관리자 인증 후 차단된 워크플로우를 해제합니다.
"""
import os
import sys
import json
import logging
import argparse
from pathlib import Path
from github import Github

# 프로젝트 모듈 임포트
sys.path.append(str(Path(__file__).parent.parent.parent))
from src.user_management.auth_manager import AuthManager
from src.storage.state_manager import get_block_state, clear_block_state

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def release_workflow(repository=None, commit_sha=None, username=None, employee_id=None, force=False):
    """관리자 인증 후 차단된 워크플로우를 해제합니다."""
    # GitHub Actions 환경에서 실행 중인지 확인
    is_github_actions = os.environ.get("GITHUB_ACTIONS") == "true"
    
    # 저장소와 커밋 정보 설정
    if is_github_actions:
        repository = repository or os.environ.get("GITHUB_REPOSITORY")
        commit_sha = commit_sha or os.environ.get("GITHUB_SHA")
    
    if not repository or not commit_sha:
        logger.error("저장소 또는 커밋 정보가 제공되지 않았습니다.")
        return False, "저장소 또는 커밋 정보가 필요합니다."
    
    # 차단 상태 확인
    block_state = get_block_state(repository, commit_sha)
    if not block_state and not force:
        logger.info(f"저장소({repository})의 커밋({commit_sha})에 대한 차단 정보가 없습니다.")
        return True, "차단된 워크플로우가 없습니다."
    
    # 관리자 인증
    auth_manager = AuthManager()
    auth_success, auth_message = auth_manager.authenticate_admin(username, employee_id)
    
    if not auth_success and not force:
        logger.error(f"관리자 인증 실패: {auth_message}")
        return False, f"차단 해제 실패: {auth_message}"
    
    try:
        # GitHub API 클라이언트 초기화
        github_token = os.environ.get("GITHUB_TOKEN")
        if not github_token:
            logger.error("GitHub 토큰이 환경 변수에 설정되지 않았습니다.")
            return False, "GitHub 토큰이 필요합니다."
        
        g = Github(github_token)
        repo = g.get_repo(repository)
        
        # 커밋 상태 변경
        repo.get_commit(commit_sha).create_status(
            state="success",
            description="관리자 승인으로 보안 차단이 해제됨",
            context="security-sentinel"
        )
        
        # PR 상태 변경
        try:
            prs = repo.get_pulls(state='open', sort='created', base='main')
            for pr in prs:
                pr_commits = pr.get_commits()
                for pr_commit in pr_commits:
                    if pr_commit.sha == commit_sha:
                        # 라벨 제거 시도
                        try:
                            pr.remove_from_labels("security-blocked")
                        except:
                            pass
                        
                        # PR에 코멘트 추가
                        comment_body = ":white_check_mark: **보안 차단 해제됨** :white_check_mark:\n\n"
                        comment_body += f"관리자 승인으로 보안 차단이 해제되었습니다.\n"
                        if username:
                            comment_body += f"승인자: @{username}"
                        
                        pr.create_issue_comment(comment_body)
                        logger.info(f"PR #{pr.number}에서 보안 차단이 해제되었습니다.")
                        break
        except Exception as e:
            logger.warning(f"PR 상태 변경 중 오류 발생: {e}")
        
        # 차단 상태 제거
        clear_block_state(repository, commit_sha)
        
        logger.info(f"워크플로우가 성공적으로 해제되었습니다.")
        return True, "워크플로우 차단이 성공적으로 해제되었습니다."
    
    except Exception as e:
        logger.exception(f"워크플로우 해제 중 오류 발생: {e}")
        return False, f"차단 해제 실패: {str(e)}"

def main():
    """명령줄에서 실행 시 사용할 메인 함수"""
    parser = argparse.ArgumentParser(description="워크플로우 차단 해제 도구")
    parser.add_argument("--repo", help="GitHub 저장소 (형식: 'owner/repo')")
    parser.add_argument("--commit", help="GitHub 커밋 SHA")
    parser.add_argument("--username", help="관리자 사용자 이름")
    parser.add_argument("--force", action="store_true", help="강제 해제 (인증 건너뛰기)")
    
    args = parser.parse_args()
    
    # 인자로 전달된 값이 없으면 대화형 모드로 실행
    if not args.repo and not args.commit:
        print("워크플로우 차단 해제 도구")
        print("------------------------")
        args.repo = input("GitHub 저장소 (형식: 'owner/repo'): ")
        args.commit = input("GitHub 커밋 SHA: ")
        args.username = input("관리자 사용자 이름 (선택사항): ")
        args.force = input("강제 해제 (y/n): ").lower() == 'y'
    
    success, message = release_workflow(
        repository=args.repo,
        commit_sha=args.commit,
        username=args.username,
        force=args.force
    )
    
    if success:
        print(f"성공: {message}")
        return 0
    else:
        print(f"실패: {message}")
        return 1

if __name__ == "__main__":
    sys.exit(main())