# bobo-code-review

对抗式代码审查 skill for Claude Code。

## 这是什么

不是"读 diff 给意见"——这是**对抗式审查 + 第一性原理根因升华**的完整工作流。

唯一硬输出：**通过**（零 P0/P1 + 零 plausible_blocking）或**不通过**。

### 与普通 review 的区别

| 普通 review | 本工作流 |
|---|---|
| 读 diff → 列问题 | 先确定性扫描（事实清单，零幻觉） |
| 单人判断 | 对抗式——review agent 判定 + skeptic agent 从三视角质疑 |
| "这里没鉴权" | "为什么鉴权靠手动加？同类还有哪些？是 isolated 还是 systemic？" |
| 修完结束 | 修完→重扫→重审→闭环判定通过 |

## 快速安装

### Linux / macOS

```bash
git clone https://github.com/wangbo12bob2-source/bobo-code-review.git
cd bobo-code-review
bash install.sh
```

### Windows (PowerShell)

```powershell
git clone https://github.com/wangbo12bob2-source/bobo-code-review.git
cd bobo-code-review
# 手动复制文件：
Copy-Item skills\bobo-code-review\SKILL.md $env:USERPROFILE\.claude\skills\bobo-code-review\
Copy-Item docs\code-review-workflow-template.md $env:USERPROFILE\.claude\docs\
Copy-Item tools\review_scan.py $env:USERPROFILE\.claude\tools\

# 创建 review-scan.cmd（放到 PATH 中，如 Python Scripts 目录）
# 内容见 install/review-scan.cmd
```

### 卸载

```bash
bash install.sh --uninstall
```

## 依赖

- **Claude Code** CLI
- **Python 3.8+**（review_scan.py 仅用标准库，零第三方依赖）
- **semgrep**（可选，用于 SAST 扫描）

## 仓库结构

```
bobo-code-review/
├── skills/bobo-code-review/SKILL.md   # Skill 定义（八步审查流程）
├── docs/code-review-workflow-template.md  # 通用方法论模板
├── tools/review_scan.py               # 确定性扫描器（零幻觉、可复现）
├── install.sh                         # Linux/macOS 安装脚本
├── install.ps1                        # Windows 安装参考
└── README.md
```

## 使用

安装后在 Claude Code 中输入：

- `/bobo-code-review` — 启动完整审查流程
- "代码审查" / "CR" / "review 一下" — 如果 CLAUDE.md 配了触发词，自动触发

### 模式选择

| 用户说 | 走哪些步 |
|---|---|
| "代码审查" / "CR" / "review 一下" | 全流程 1→2→3→4→5→6→7→8 |
| "快速扫一下" / "有没有明显问题" | 1→2→7（只扫描，不做对抗） |
| "验证修复" / "重审" | 5→6→8（重扫+重审已修复项） |

## 八步流程概览

1. **确定范围** — 审查目标、分支、diff 基线
2. **阶段 A 确定性扫描** — review-scan 输出事实清单（7 维度，零幻觉）
3. **阶段 B 对抗审查** — review agent 四态判定 + skeptic agent 三视角质疑
4. **第一性原理根因升华** — isolated vs systemic
5. **修复 P0/P1** — 先出方案再改
6. **重扫 + 验证** — 确认问题消除、无新引入
7. **报告** — 通过/不通过 + 每条 finding 最终状态
8. **闭环判定** — 零 P0/P1 + 零 plausible_blocking = 通过

## 跨模型对抗

skeptic agent 必须用与 review agent **不同**的模型，确保盲区不重叠。

## License

MIT
