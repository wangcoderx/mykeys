#!/bin/zsh
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
OLD_APP="/Applications/MyKeys.app"
BUILD_APP="$PROJECT_DIR/target/release/bundle/macos/MyKeys.app"

echo "[1/5] 关闭正在运行的 MyKeys"
pkill -x MyKeys 2>/dev/null || true
pkill -x mykeys 2>/dev/null || true

echo "[2/5] 构建当前版本"
cd "$PROJECT_DIR"
cargo tauri build --bundles app

if [[ ! -d "$BUILD_APP" ]]; then
  echo "构建失败：未找到 $BUILD_APP" >&2
  exit 1
fi

echo "[3/5] 删除上一版测试应用"
if [[ -d "$OLD_APP" ]]; then
  rm -rf -- "$OLD_APP"
fi

echo "[4/5] 安装当前版本"
ditto "$BUILD_APP" "$OLD_APP"
xattr -dr com.apple.quarantine "$OLD_APP" 2>/dev/null || true
codesign --force --deep --sign - "$OLD_APP"

echo "[5/5] 启动并验证"
open "$OLD_APP"
sleep 2
if pgrep -x MyKeys >/dev/null || pgrep -x mykeys >/dev/null; then
  echo "安装测试通过：$OLD_APP"
else
  echo "应用已安装，但未检测到运行进程。请检查系统日志。" >&2
  exit 1
fi
