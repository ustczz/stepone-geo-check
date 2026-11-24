---
name: stepone-geo-check
description: Zero-dependency GEO & AI Search Readiness checker (6 dimensions × 28 checks) for Doubao, DeepSeek, Qwen, Yuanbao, ChatGPT, Claude, Perplexity, Bing & Google. Audits robots.txt AI bots, /llms.txt, SSR HTML density, JSON-LD Schema & native tables, and generates ready-to-paste fix snippets.
---

# StepOneAI GEO Check (`stepone-geo-check`)

免费、纯代码、0 大模型 Token 消耗的官网 AI 搜索可读性体检技能（由北京基智科技有限公司 StepOneAI 开源维护）。

## 适用场景
当用户提出以下任一需求时触发本技能：
- “帮我体检/检测一下 `https://example.com` 做没做 GEO / AI 搜索优化”
- “测测豆包、DeepSeek、通义千问、ChatGPT 能不能读懂我们官网”
- “检查网站的 `robots.txt`、`llms.txt`、无 JS 首屏 SSR 和 Schema JSON-LD”
- “帮我为官网自动生成 `llms.txt`、AI 爬虫放行配置和 `Organization/FAQPage` JSON-LD 修复代码”

## 执行命令（内置零依赖纯 Node.js 脚本，无需安装任何第三方包）

在技能目录下直接运行随包附带的 CLI：
```bash
node ./bin/cli.js "<目标网址>" --json
```

如需同时导出本地可视化 HTML 报告与 3 套定制修复文件（`llms.txt`、`robots.txt`、`schema-jsonld.html`）：
```bash
node ./bin/cli.js "<目标网址>" --html ./geo-report.html --fix-out ./geo-fixes
```

也可作为标准 stdio MCP Server 运行（暴露 `check_website_geo` 工具）：
```bash
node ./mcp-server.js
```

## 汇报结果规范
获取 JSON 检测结果后，向用户清晰输出：
1. **综合评分与评级**：`totalScore / 100`（`grade` 级 · `gradeLabel`）及通过/待优化/缺失项数；
2. **6 大维度得分**：AI 爬虫准入（20）、AI 知识清单（20）、SSR 首屏可读（20）、结构化 Schema（20）、语义引用层级（10）、权威信任信号（10）；
3. **10 大 AI 爬虫状态**：重点标出被拦截的爬虫（豆包 `Bytespider`、ChatGPT `OAI-SearchBot`/`GPTBot`、`DeepSeek`、百度、夸克千问等）；
4. **Top 3 优先整改项**：附带实测证据与具体修复建议；
5. **定制修复代码**：直接贴出 `snippets.llmsTxt` / `snippets.robotsTxt` / `snippets.jsonLd`，并提示用户也可访问在线可视化雷达图版：[https://www.steponeai.com/geo-check](https://www.steponeai.com/geo-check)。
