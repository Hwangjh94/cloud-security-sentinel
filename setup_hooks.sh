#!/bin/bash

# pre-push 훅 설치
echo "보안 검사 Git 훅 설치 중..."

# hooks 디렉토리 확인
HOOKS_DIR=".git/hooks"
if [ ! -d "$HOOKS_DIR" ]; then
  echo "Git 훅 디렉토리를 찾을 수 없습니다. Git 저장소가 초기화되었는지 확인하세요."
  exit 1
fi

# pre-push 훅 복사
cp git_hooks/pre-push "$HOOKS_DIR/pre-push"
chmod +x "$HOOKS_DIR/pre-push"

echo "Git 훅이 성공적으로 설치되었습니다!"