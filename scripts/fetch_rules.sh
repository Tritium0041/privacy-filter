#!/usr/bin/env bash
# 下载 / 更新 gitleaks 默认规则集到 rules/gitleaks.toml
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
URL="https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml"

mkdir -p "$DIR/rules"
curl -fsSL "$URL" -o "$DIR/rules/gitleaks.toml"
echo "已保存 gitleaks 规则集 -> rules/gitleaks.toml"
