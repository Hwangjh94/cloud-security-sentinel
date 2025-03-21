#!/usr/bin/env python3
"""
인증 관리 모듈 - 관리자 인증 및 사원번호 검증을 처리합니다.
"""
import os
import re
import yaml
import json
import hashlib
import logging
import datetime
import getpass
from pathlib import Path

# 로깅 설정
logger = logging.getLogger(__name__)

class AuthManager:
    def __init__(self):
        """인증 관리자 초기화"""
        self.config = self.load_auth_config()
        self.auth_log_path = Path(__file__).parent.parent.parent / "logs"
        self.auth_log_path.mkdir(exist_ok=True)
        
        # 로그 파일 설정
        self.log_file = self.auth_log_path / self.config.get("logging", {}).get("log_file", "auth_attempts.log")
        
        # 인증 시도 제한 설정
        self.max_attempts = self.config.get("max_attempts", 3)
        self.lockout_duration = self.config.get("lockout_duration_minutes", 30)
        
        # 인증 시도 추적을 위한 상태 파일
        self.auth_state_file = self.auth_log_path / "auth_state.json"
        self.auth_state = self.load_auth_state()

    def load_auth_config(self):
        """인증 설정을 로드합니다."""
        config_path = Path(__file__).parent.parent.parent / "config" / "auth_config.yml"
        try:
            with open(config_path, "r") as f:
                return yaml.safe_load(f).get("authentication", {})
        except Exception as e:
            logger.warning(f"인증 설정을 로드하는 중 오류 발생: {e}. 기본 설정을 사용합니다.")
            return {
                "admin_groups": ["security-admins"],
                "max_attempts": 3,
                "lockout_duration_minutes": 30,
                "employee_id": {
                    "min_length": 5,
                    "max_length": 10,
                    "format_regex": "^[A-Z][0-9]{4,9}$"
                },
                "logging": {
                    "log_all_auth_attempts": True,
                    "log_file": "auth_attempts.log"
                }
            }

    def load_auth_state(self):
        """인증 상태를 로드합니다."""
        if not self.auth_state_file.exists():
            return {"locked_users": {}, "last_updated": datetime.datetime.now().isoformat()}
        
        try:
            with open(self.auth_state_file, "r") as f:
                state = json.load(f)
                
                # 잠긴 사용자 목록 정리 (잠금 시간이 지난 사용자 제거)
                current_time = datetime.datetime.now()
                locked_users = {}
                
                for user, user_data in state.get("locked_users", {}).items():
                    lock_time = datetime.datetime.fromisoformat(user_data.get("lock_time"))
                    lock_duration = datetime.timedelta(minutes=self.lockout_duration)
                    
                    # 잠금 시간이 지나지 않은 경우에만 유지
                    if current_time - lock_time < lock_duration:
                        locked_users[user] = user_data
                
                state["locked_users"] = locked_users
                state["last_updated"] = current_time.isoformat()
                
                # 정리된 상태 저장
                self.save_auth_state(state)
                
                return state
        
        except Exception as e:
            logger.error(f"인증 상태를 로드하는 중 오류 발생: {e}")
            return {"locked_users": {}, "last_updated": datetime.datetime.now().isoformat()}

    def save_auth_state(self, state=None):
        """인증 상태를 저장합니다."""
        if state is None:
            state = self.auth_state
        
        try:
            with open(self.auth_state_file, "w") as f:
                json.dump(state, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"인증 상태를 저장하는 중 오류 발생: {e}")
            return False

    def is_user_locked(self, username):
        """사용자가 잠겨있는지 확인합니다."""
        locked_users = self.auth_state.get("locked_users", {})
        
        if username not in locked_users:
            return False
        
        lock_time = datetime.datetime.fromisoformat(locked_users[username].get("lock_time"))
        current_time = datetime.datetime.now()
        lock_duration = datetime.timedelta(minutes=self.lockout_duration)
        
        # 잠금 시간이 지났으면 잠금 해제
        if current_time - lock_time >= lock_duration:
            del self.auth_state["locked_users"][username]
            self.save_auth_state()
            return False
        
        return True

    def lock_user(self, username):
        """사용자를 잠급니다."""
        if "locked_users" not in self.auth_state:
            self.auth_state["locked_users"] = {}
        
        self.auth_state["locked_users"][username] = {
            "lock_time": datetime.datetime.now().isoformat(),
            "attempts": self.max_attempts
        }
        
        self.save_auth_state()
        logger.warning(f"사용자 '{username}'가 {self.max_attempts}회 인증 실패로 {self.lockout_duration}분 동안 잠겼습니다.")

    def log_auth_attempt(self, username, employee_id, success, reason=None):
        """인증 시도를 로그에 기록합니다."""
        if not self.config.get("logging", {}).get("log_all_auth_attempts", True):
            return
        
        timestamp = datetime.datetime.now().isoformat()
        log_entry = {
            "timestamp": timestamp,
            "username": username,
            "employee_id": self.mask_employee_id(employee_id),
            "success": success,
            "reason": reason,
            "ip_address": os.environ.get("REMOTE_ADDR", "unknown")
        }
        
        try:
            log_entry_str = json.dumps(log_entry)
            with open(self.log_file, "a") as f:
                f.write(f"{log_entry_str}\n")
        except Exception as e:
            logger.error(f"인증 시도를 로그에 기록하는 중 오류 발생: {e}")

    def mask_employee_id(self, employee_id):
        """개인정보 보호를 위해 사원번호를 마스킹합니다."""
        if not employee_id or len(employee_id) < 4:
            return "****"
        
        # 앞 1자와 뒤 2자만 표시하고 나머지는 '*'로 마스킹
        masked = employee_id[0] + "*" * (len(employee_id) - 3) + employee_id[-2:]
        return masked

    def validate_employee_id_format(self, employee_id):
        """사원번호 형식을 검증합니다."""
        if not employee_id:
            return False, "사원번호가 비어 있습니다."
        
        # 길이 검증
        min_length = self.config.get("employee_id", {}).get("min_length", 5)
        max_length = self.config.get("employee_id", {}).get("max_length", 10)
        
        if len(employee_id) < min_length or len(employee_id) > max_length:
            return False, f"사원번호는 {min_length}~{max_length}자 사이여야 합니다."
        
        # 형식 검증
        format_regex = self.config.get("employee_id", {}).get("format_regex", "^[A-Z][0-9]{4,9}$")
        if not re.match(format_regex, employee_id):
            return False, "사원번호 형식이 올바르지 않습니다. (예: A로 시작하는 영문+숫자 조합)"
        
        return True, None

    def authenticate_admin(self, username=None, employee_id=None):
        """관리자 권한을 가진 사용자를 인증합니다."""
        # GitHub Actions 환경에서 실행 중인지 확인
        is_github_actions = os.environ.get("GITHUB_ACTIONS") == "true"
        
        # 사용자 이름이 제공되지 않은 경우, 환경 변수에서 가져오거나 입력 요청
        if not username:
            if is_github_actions:
                username = os.environ.get("GITHUB_ACTOR", "")
            else:
                username = input("관리자 사용자 이름: ")
        
        # 사용자가 잠겨있는지 확인
        if self.is_user_locked(username):
            lock_time = datetime.datetime.fromisoformat(
                self.auth_state.get("locked_users", {}).get(username, {}).get("lock_time")
            )
            current_time = datetime.datetime.now()
            remaining_minutes = self.lockout_duration - int((current_time - lock_time).total_seconds() / 60)
            
            message = f"사용자 '{username}'는 인증 실패로 인해 잠겨 있습니다. {remaining_minutes}분 후에 다시 시도하세요."
            logger.warning(message)
            self.log_auth_attempt(username, "", False, "사용자 잠금 상태")
            return False, message
        
        # 사원번호가 제공되지 않은 경우, 입력 요청
        if not employee_id:
            if is_github_actions:
                # GitHub Actions 환경에서는 수동 승인으로 대체
                logger.info("GitHub Actions 환경에서는 수동 승인으로 인증을 대체합니다.")
                return True, "수동 승인 완료"
            else:
                employee_id = getpass.getpass("관리자 사원번호: ")
        
        # 사원번호 형식 검증
        is_valid_format, format_error = self.validate_employee_id_format(employee_id)
        if not is_valid_format:
            # 실패 횟수 증가
            locked_users = self.auth_state.get("locked_users", {})
            if username not in locked_users:
                locked_users[username] = {"attempts": 1, "lock_time": datetime.datetime.now().isoformat()}
            else:
                locked_users[username]["attempts"] = locked_users[username].get("attempts", 0) + 1
            
            self.auth_state["locked_users"] = locked_users
            self.save_auth_state()
            
            # 최대 시도 횟수를 초과하면 잠금
            if locked_users[username].get("attempts", 0) >= self.max_attempts:
                self.lock_user(username)
                message = f"사용자 '{username}'는 인증 실패로 인해 {self.lockout_duration}분 동안 잠겼습니다."
                self.log_auth_attempt(username, employee_id, False, "최대 시도 횟수 초과")
                return False, message
            
            self.log_auth_attempt(username, employee_id, False, format_error)
            return False, format_error
        
        # 여기서는 실제 인증 로직 구현
        # 실제 환경에서는 보안 데이터베이스나 LDAP 등과 연동해야 함
        # 이 예제에서는 간단히 하드코딩된 값으로 대체 (실제 구현 시 변경 필요)
        valid_admins = {
            "admin": "A12345",
            "security-admin": "A67890"
        }
        
        is_valid_admin = (username in valid_admins and valid_admins[username] == employee_id)
        
        # GitHub Actions에서는 항상 성공으로 처리 (실제 구현 시 변경 필요)
        if is_github_actions:
            is_valid_admin = True
        
        if is_valid_admin:
            # 인증 성공 시 실패 기록 초기화
            if username in self.auth_state.get("locked_users", {}):
                del self.auth_state["locked_users"][username]
                self.save_auth_state()
            
            self.log_auth_attempt(username, employee_id, True, "인증 성공")
            return True, "인증 성공"
        else:
            # 실패 횟수 증가
            locked_users = self.auth_state.get("locked_users", {})
            if username not in locked_users:
                locked_users[username] = {"attempts": 1, "lock_time": datetime.datetime.now().isoformat()}
            else:
                locked_users[username]["attempts"] = locked_users[username].get("attempts", 0) + 1
            
            self.auth_state["locked_users"] = locked_users
            self.save_auth_state()
            
            # 최대 시도 횟수를 초과하면 잠금
            if locked_users[username].get("attempts", 0) >= self.max_attempts:
                self.lock_user(username)
                message = f"사용자 '{username}'는 인증 실패로 인해 {self.lockout_duration}분 동안 잠겼습니다."
                self.log_auth_attempt(username, employee_id, False, "최대 시도 횟수 초과")
                return False, message
            
            remaining_attempts = self.max_attempts - locked_users[username].get("attempts", 0)
            message = f"인증 실패. 남은 시도 횟수: {remaining_attempts}회"
            self.log_auth_attempt(username, employee_id, False, "잘못된 사원번호")
            return False, message


# 명령줄에서 직접 실행 시 테스트 함수
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    auth_manager = AuthManager()
    
    # CLI 모드에서 관리자 인증 테스트
    success, message = auth_manager.authenticate_admin()
    
    if success:
        print(f"인증 성공: {message}")
    else:
        print(f"인증 실패: {message}")