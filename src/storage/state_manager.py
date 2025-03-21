#!/usr/bin/env python3
"""
상태 관리 모듈 - 보안 스캔 결과와 워크플로우 차단 상태를 관리합니다.
"""
import os
import json
import logging
import datetime
from pathlib import Path

# 로깅 설정
logger = logging.getLogger(__name__)

# 상태 파일 경로
STATE_DIR = Path(__file__).parent.parent.parent / "logs"
SCAN_STATE_FILE = STATE_DIR / "scan_history.json"
BLOCK_STATE_FILE = STATE_DIR / "block_state.json"

def ensure_state_dir():
    """상태 저장 디렉토리가 존재하는지 확인하고 없으면 생성합니다."""
    STATE_DIR.mkdir(exist_ok=True, parents=True)

def save_scan_state(scan_results):
    """스캔 결과를 저장합니다."""
    ensure_state_dir()
    
    # 기존 스캔 이력 로드
    scan_history = []
    if SCAN_STATE_FILE.exists():
        try:
            with open(SCAN_STATE_FILE, "r") as f:
                scan_history = json.load(f)
        except Exception as e:
            logger.error(f"스캔 이력을 로드하는 중 오류 발생: {e}")
            scan_history = []
    
    # 새 스캔 결과 추가
    timestamp = datetime.datetime.now().isoformat()
    repository = os.environ.get("GITHUB_REPOSITORY", "unknown")
    commit_sha = os.environ.get("GITHUB_SHA", "unknown")
    github_actor = os.environ.get("GITHUB_ACTOR", "unknown")
    
    scan_entry = {
        "timestamp": timestamp,
        "repository": repository,
        "commit_sha": commit_sha,
        "github_actor": github_actor,
        "summary": scan_results.get("scan_summary", {}),
        "should_block": scan_results.get("should_block_deployment", False)
    }
    
    # 심각도별 취약점 수 추가
    severity_counts = {}
    for vuln in scan_results.get("vulnerabilities", []):
        severity = vuln.get("severity", "UNKNOWN")
        if severity not in severity_counts:
            severity_counts[severity] = 0
        severity_counts[severity] += 1
    
    scan_entry["severity_counts"] = severity_counts
    
    # 이력에 추가 (최근 100개만 유지)
    scan_history.append(scan_entry)
    if len(scan_history) > 100:
        scan_history = scan_history[-100:]
    
    # 파일에 저장
    try:
        with open(SCAN_STATE_FILE, "w") as f:
            json.dump(scan_history, f, indent=2)
        logger.info(f"스캔 이력이 성공적으로 저장되었습니다.")
        return True
    except Exception as e:
        logger.error(f"스캔 이력을 저장하는 중 오류 발생: {e}")
        return False

def get_scan_history(limit=100):
    """스캔 이력을 가져옵니다."""
    if not SCAN_STATE_FILE.exists():
        return []
    
    try:
        with open(SCAN_STATE_FILE, "r") as f:
            scan_history = json.load(f)
        return scan_history[-limit:]
    except Exception as e:
        logger.error(f"스캔 이력을 로드하는 중 오류 발생: {e}")
        return []

def set_block_state(repository, commit_sha, github_actor):
    """워크플로우 차단 상태를 설정합니다."""
    ensure_state_dir()
    
    # 기존 차단 상태 로드
    block_state = {}
    if BLOCK_STATE_FILE.exists():
        try:
            with open(BLOCK_STATE_FILE, "r") as f:
                block_state = json.load(f)
        except Exception as e:
            logger.error(f"차단 상태를 로드하는 중 오류 발생: {e}")
            block_state = {}
    
    # 차단 정보 생성
    timestamp = datetime.datetime.now().isoformat()
    block_key = f"{repository}:{commit_sha}"
    
    block_state[block_key] = {
        "repository": repository,
        "commit_sha": commit_sha,
        "github_actor": github_actor,
        "blocked_at": timestamp,
        "blocked_by": "security-sentinel",
        "status": "blocked"
    }
    
    # 파일에 저장
    try:
        with open(BLOCK_STATE_FILE, "w") as f:
            json.dump(block_state, f, indent=2)
        logger.info(f"차단 상태가 성공적으로 저장되었습니다.")
        return timestamp
    except Exception as e:
        logger.error(f"차단 상태를 저장하는 중 오류 발생: {e}")
        return timestamp

def get_block_state(repository, commit_sha):
    """워크플로우 차단 상태를 가져옵니다."""
    if not BLOCK_STATE_FILE.exists():
        return None
    
    try:
        with open(BLOCK_STATE_FILE, "r") as f:
            block_state = json.load(f)
        
        block_key = f"{repository}:{commit_sha}"
        return block_state.get(block_key)
    except Exception as e:
        logger.error(f"차단 상태를 로드하는 중 오류 발생: {e}")
        return None

def clear_block_state(repository, commit_sha):
    """워크플로우 차단 상태를 제거합니다."""
    if not BLOCK_STATE_FILE.exists():
        return True
    
    try:
        with open(BLOCK_STATE_FILE, "r") as f:
            block_state = json.load(f)
        
        block_key = f"{repository}:{commit_sha}"
        if block_key in block_state:
            # 상태를 '해제됨'으로 변경하고 해제 시간 추가
            block_state[block_key]["status"] = "released"
            block_state[block_key]["released_at"] = datetime.datetime.now().isoformat()
            
            # 파일에 저장
            with open(BLOCK_STATE_FILE, "w") as f:
                json.dump(block_state, f, indent=2)
            
            logger.info(f"차단 상태가 성공적으로 해제되었습니다.")
        else:
            logger.info(f"제거할 차단 상태가 없습니다.")
        
        return True
    except Exception as e:
        logger.error(f"차단 상태를 제거하는 중 오류 발생: {e}")
        return False

def get_all_blocks(status=None):
    """모든 차단 상태를 가져옵니다."""
    if not BLOCK_STATE_FILE.exists():
        return []
    
    try:
        with open(BLOCK_STATE_FILE, "r") as f:
            block_state = json.load(f)
        
        if status is None:
            return list(block_state.values())
        else:
            return [block for block in block_state.values() if block.get("status") == status]
    except Exception as e:
        logger.error(f"차단 상태를 로드하는 중 오류 발생: {e}")
        return []