# MyKeys 2.0 · Brand Spec

> 固化日期：2026-09-12  
> 资产来源：用户提供的 `设计方案/icons/` 与 `设计方案/providers/`  
> 资产完整度：完整，可直接用于原型与桌面端实现

## 核心资产

### Logo

- 矢量主版本：`../设计方案/icons/icon.svg`
- 高精度品牌版本：`../设计方案/icons/mykeys-logo-v2.png`
- 通用应用图标：`../设计方案/icons/icon.png`
- macOS 打包版本：`../设计方案/icons/icon-macos.icns`（1024 画布内使用 824 主体，保留约 9.8% 四周安全区）
- 平台图标：`../设计方案/icons/icon.icns`、`../设计方案/icons/icon.ico` 及 iOS / Windows 尺寸集
- 使用场景：欢迎页、解锁页、窗口品牌区、完成状态
- 禁止：拉伸、旋转、描边、改变内部白色钥匙图形、把蓝紫渐变扩散到所有功能组件

### 厂商 Logo

已提供 OpenAI、Anthropic、Google Gemini、DeepSeek、AWS、Microsoft Azure、GitHub、Cloudflare、xAI 与 Mistral AI 的本地 SVG。

- 用于厂商选择器与密钥列表识别
- 保留厂商原始颜色，不统一强制改色
- Logo 容器使用中性浅色面，不制造彩色卡片墙

## 色板

- Brand Blue：`#0A84FF`，关键主操作与选中状态
- Brand Indigo：`#5E5CE6`，仅用于品牌渐变尾端和少量身份性强调
- Success Green：`#30D158`，验证成功与可用状态
- Warning Orange：`#FF9F0A`，临期与需要注意
- Danger Red：`#FF453A`，失效、删除和不可逆操作
- Canvas：`#F5F5F7`
- Surface：`#FFFFFF`
- Ink：`#1D1D1F`
- Secondary Ink：`#6E6E73`
- Separator：`rgba(60, 60, 67, 0.16)`

## 字型

- 界面正文：`-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif`
- 密钥与技术值：`"SFMono-Regular", Consolas, "Liberation Mono", monospace`
- 不从网络加载字体，保证离线与跨平台可用

## 签名细节

- Logo 出现时使用一次克制的蓝紫光晕与轻微景深
- 页面切换由同一个内容舞台完成空间连续运动，不做生硬整页闪切
- 彩色只表达动作和状态；大面积布局依靠留白、字重与分隔完成

## 禁区

- 不把所有卡片做成蓝紫渐变
- 不使用装饰性统计数据、欢迎横幅或无意义图标
- 不用绿色单独表示“可用”，必须同时提供文字
- 危险操作不与普通设置并列成同等视觉权重

## 气质关键词

安静、可信、清晰、轻盈、可控。
