#!/bin/zsh
# MyKeys · macOS 一键打包
#
# 默认：构建 .app → 安装到 /Applications → 启动并校验进程。
#
#   scripts/install-test-macos.sh --build-only   只构建，不安装也不启动
#   scripts/install-test-macos.sh --no-install   构建后直接运行 target 里的 .app
#   scripts/install-test-macos.sh --dmg          额外产出 .dmg
#   scripts/install-test-macos.sh --help
set -euo pipefail

PROJECT_DIR="${0:A:h:h}"
APP_NAME="MyKeys"
BUILD_APP="$PROJECT_DIR/target/release/bundle/macos/$APP_NAME.app"
INSTALL_APP="/Applications/$APP_NAME.app"
DMG_DIR="$PROJECT_DIR/target/release/bundle/dmg"

INSTALL=1
LAUNCH=1
BUNDLES=(app)

while (( $# > 0 )); do
  case "$1" in
    --build-only) INSTALL=0; LAUNCH=0 ;;
    --no-install) INSTALL=0 ;;
    --dmg) BUNDLES+=(dmg) ;;
    -h|--help) sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) print -u2 "未知参数：$1（用 --help 查看用法）"; exit 2 ;;
  esac
  shift
done

step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }

step "检查环境"
[[ "$(uname -s)" == "Darwin" ]] || { print -u2 "该脚本仅支持 macOS"; exit 1 }
command -v cargo >/dev/null || { print -u2 "未找到 cargo，请先安装 Rust 工具链：https://rustup.rs"; exit 1 }
cargo tauri --version >/dev/null 2>&1 || {
  print -u2 "未找到 Tauri CLI，请先执行：cargo install tauri-cli --locked --version '^2'"
  exit 1
}
print -r -- "  macOS $(sw_vers -productVersion) · $(uname -m) · $(cargo tauri --version)"

step "关闭正在运行的 MyKeys"
pkill -x "$APP_NAME" 2>/dev/null || true
pkill -x "${APP_NAME:l}" 2>/dev/null || true
sleep 1

step "构建 Release（含 CSP 脚本哈希断言，首次可能需要几分钟）"
cd "$PROJECT_DIR"
cargo tauri build --bundles "${(j:,:)BUNDLES}"

[[ -d "$BUILD_APP" ]] || { print -u2 "构建失败：未找到 $BUILD_APP"; exit 1 }
print -r -- "  产物：$BUILD_APP"
print -r -- "  体积：$(du -sh "$BUILD_APP" | cut -f1)"

if (( INSTALL )); then
  step "安装到 /Applications"
  if [[ -d "$INSTALL_APP" ]]; then
    print -r -- "  替换旧版本 $INSTALL_APP（保险库数据在 ~/Library/Application Support/MyKeys，不受影响）"
    rm -rf -- "$INSTALL_APP"
  fi
  ditto "$BUILD_APP" "$INSTALL_APP"
  xattr -dr com.apple.quarantine "$INSTALL_APP" 2>/dev/null || true
  codesign --force --deep --sign - "$INSTALL_APP"
  TARGET_APP="$INSTALL_APP"
else
  step "跳过安装"
  TARGET_APP="$BUILD_APP"
fi

if (( LAUNCH )); then
  step "启动并校验进程"
  open "$TARGET_APP"
  sleep 3
  if pgrep -x "$APP_NAME" >/dev/null || pgrep -x "${APP_NAME:l}" >/dev/null; then
    print -r -- "  MyKeys 正在运行"
  else
    print -u2 "  应用已就绪，但未检测到运行进程，请用 Console.app 查看系统日志"
    exit 1
  fi
else
  step "跳过启动"
fi

if (( ${BUNDLES[(Ie)dmg]} )); then
  for file in "$DMG_DIR"/*.dmg(N); do
    printf '\n  DMG：%s\n' "$file"
  done
fi

printf '\n\033[1m完成\033[0m  %s\n' "$TARGET_APP"
