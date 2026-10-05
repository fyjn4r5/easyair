#!/usr/bin/env bash
# 使用方法：
# 1. 先在 GitHub 创建一个新仓库（如 easyair）
# 2. 运行此脚本，传入你的 GitHub 用户名和仓库名
#    ./push_to_github.sh yourname easyair

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "用法: $0 <GitHub用户名> <仓库名>"
    echo "例: $0 zhangsan easyair"
    exit 1
fi

USER=$1
REPO=$2
DIR="$(cd "$(dirname "$0")" && pwd)"

cd "$DIR"

echo "=== 初始化 Git 并推送到 GitHub ==="
echo "目标: https://github.com/$USER/$REPO.git"

# 初始化
git init
git config user.name "GitHub Action Builder"
git config user.email "action@github.com"

# 添加 .gitignore
cat > .gitignore << 'GITIGNORE'
__pycache__/
*.pyc
.venv/
venv/
build/
dist/
*.spec
config/settings.json
captures/*
wordlists/*
.DS_Store
GITIGNORE

git add .
git commit -m "Initial commit: EasyAir v2 for Mint 21.3"

# 添加远程并推送
git branch -M main
git remote add origin "https://github.com/$USER/$REPO.git"

echo ""
echo "即将推送到 GitHub..."
echo "如果需要认证，请使用 Personal Access Token (Settings -> Developer settings -> Personal access tokens)"
echo ""
git push -u origin main

echo ""
echo "✅ 推送完成！"
echo ""
echo "=== 触发构建 ==="
echo "方法 1: 打标签自动构建并发布 Release"
echo "  git tag v1.0.0 && git push origin v1.0.0"
echo ""
echo "方法 2: 手动触发 (GitHub 网页 Actions -> Build -> Run workflow)"
echo "  版本号填: v1.0.0-dev"
echo ""
echo "构建产物在 Actions -> Artifacts 下载，或 Releases 页面下载"
