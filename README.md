# bobo-code-review

对抗式代码审查 skill for Claude Code。

## 这是什么

不是"读 diff 给意见"——这是**对抗式审查 + 第一性原理根因升华**的完整工作流。

唯一硬输出：**通过**（零 P0/P1 + 零 plausible_blocking + 验证通过）或**不通过**。

### 与普通 review 的区别

| 普通 review | 本工作流 |
|---|---|
| 读 diff → 列问题 | 先确定性扫描（事实清单，零幻觉） |
| 单人判断 | 对抗式——review agent 判定 + skeptic agent 从三视角质疑 |
| "这里没鉴权" | "为什么鉴权靠手动加？同类还有哪些？是 isolated 还是 systemic？" |
| 修完结束 | 修完→重扫→**验证**→重审→闭环判定通过 |

---

## 设计思路：为什么这样设计

### 问题 1：AI 生成代码的盲区

在 vibe coding（AI 生成代码比例高）场景下，AI 助手会"自审自"——它认可自己的判断，导致盲区无法发现。两轮审查的巨大落差证明了这一点：第一轮自报 78+ 条问题，第二轮复查又补充发现一大批第一轮漏掉的严重问题（含 P0 级）。

**解决**：引入**对抗式审查**——review agent 判定后，skeptic agent（不同模型）从三个 lens 质疑：
- 正确性：代码逻辑上是否真的错？
- 可复现：能否构造触发路径？
- 攻击者 lens：恶意用户会怎么利用？

### 问题 2：只审不验，闭环断裂

修复建议给出后，没人验证修复是否真的解决、有没有副作用。历史案例：
- **R1**：删掉下发给前端的 AI Key → 改空串后前端 `if(!apiKey) throw` → 分镜/剧本/资产提取/Seedance 等 LLM 全线不可用
- **R2**：SSRF 校验拒绝内网 IP → 补丁漏 CGN 段 `100.64.0.0/10` 和阿里云元数据 `100.100.100.200`

**解决**：把"验证"从"建议"变成**强制步骤**。修复后必须跑 `review-scan --verify`，验证失败 = 不通过。

### 问题 3：静态扫描不覆盖运行时回归

确定性扫描器（`review_scan.py`）能发现"路由无鉴权""硬编码密钥"等问题，但**修了 bug 后是否破坏了原有功能**？扫描器回答不了。

**解决**：在扫描器上增加 `--verify` 参数，扫描后自动运行项目的测试/构建/类型检查命令，把"功能回归"也纳入审查闭环。

---

## 核心设计原则

1. **对抗 > 数量**：每条发现经独立 skeptic 反驳，过滤"AI 认可自己的判断"
2. **验证是审查的一部分**：修复必须追调用链 + 跑回归，不是审完就完
3. **结构化维度 > 自由发挥**：盲区变成必答 checklist，不能用统计结论代替逐点核对
4. **根因优先于症状（第一性原理）**：补丁治症状、根因治复发
5. **攻击者视角**：skeptic 不只判"是不是 bug"，更问"恶意攻击者会怎么利用"
6. **审查-修复-再审查闭环**：不通过必须修复后重审，不允许"我改完了"代替验证

---

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

---

## 依赖

- **Claude Code** CLI
- **Python 3.8+**（review_scan.py 仅用标准库，零第三方依赖）
- **opengrep**（可选，用于 SAST 扫描）

---

## 仓库结构

```
bobo-code-review/
├── skills/bobo-code-review/SKILL.md         # Skill 定义（八步审查流程）
├── docs/code-review-workflow-template.md    # 通用方法论模板
├── tools/review_scan.py                     # 确定性扫描器（零幻觉、可复现）
├── install.sh                               # Linux/macOS 安装脚本
├── install.ps1                              # Windows 安装参考
├── install/review-scan                      # Unix wrapper
├── install/review-scan.cmd                  # Windows wrapper
└── README.md
```

---

## 使用

安装后在 Claude Code 中输入：

- `/bobo-code-review` — 启动完整审查流程
- "代码审查" / "CR" / "review 一下" — 如果 CLAUDE.md 配了触发词，自动触发

### 模式选择

| 用户说 | 走哪些步 |
|---|---|
| "代码审查" / "CR" / "review 一下" | 全流程 1→2→3→4→5→6→7→8 |
| "快速扫一下" / "有没有明显问题" | 1→2→7（只扫描，不做对抗） |
| "验证修复" / "重审" | 5→6→8（重扫+验证+重审已修复项） |

---

## 八步流程概览

1. **确定范围** — 审查目标、分支、diff 基线
2. **阶段 A 确定性扫描** — review-scan 输出事实清单（9 维度，零幻觉）
3. **阶段 B 对抗审查** — review agent 四态判定 + skeptic agent 三视角质疑
4. **第一性原理根因升华** — isolated vs systemic
5. **修复 P0/P1** — 先出方案再改
6. **重扫 + 验证** — 两个独立子步骤，缺一不可：
   - **6a. 重扫**：确认问题消除、无新引入 P0/P1
   - **6b. 验证**：`review-scan --verify` 跑测试/构建/类型检查，确认无回归
7. **报告** — 通过/不通过 + 每条 finding 最终状态
8. **闭环判定** — 零 P0/P1 + 零 plausible_blocking + **验证通过** = 通过

---

## 确定性扫描器（review-scan）

### 为什么需要确定性扫描器

AI 审查的问题：
- **幻觉**：AI 可能"看到"不存在的 bug，或漏掉真实问题
- **不一致**：同一处代码，不同会话结论可能不同
- **不可复现**：今天审出问题，明天重审可能找不到了

`review_scan.py` 的设计目标：**零模型、零幻觉、可复现**。同样的代码跑多少次，输出完全一致。它只输出事实（路由列表、鉴权标志、URL 参数等），不做判断。判断交给阶段 B 的对抗审查。

### 9 个扫描维度

| ID | 维度 | 说明 |
|---|---|---|
| S1 | 路由清单 | 多框架自动识别（FastAPI/Flask/Django/Express/NestJS/Koa/Spring/gin/echo/axum/actix） |
| S2 | 鉴权 | 路由是否有鉴权标志（跨框架通用 + `.code-review.yml` 可追加） |
| S3 | SSRF | URL 参数是否校验目标地址 |
| S4 | 密钥 | 硬编码密钥/密码/Token（16 位以上字符串赋值） |
| S5 | 跨存储删除 | 删实体函数是否覆盖全部关联存储 |
| S6 | 裸 fetch | 前端直接 `fetch()` 调用（排除 auth client 封装） |
| S7 | 错误吞没 | `except: pass` / `catch: return null` 不 raise |
| S8 | 无界重试/OOM | `while True` 无 break / 循环内无界 append |
| S9 | 时间戳污染 | 客户端 `Date.now()` 用于比较/排序 |

### 用法

```bash
# 扫描未提交改动
review-scan --root <项目目录>

# 全量扫描
review-scan --root <项目目录> --full

# 扫描 + 验证（修复后必须跑）
review-scan --root <项目目录> --verify

# JSON 输出
review-scan --root <项目目录> --json

# 自检
review-scan --selftest
```

### 项目配置 `.code-review.yml`

在项目根目录创建 `.code-review.yml`：

```yaml
auth_markers:
  - "Depends(get_current_user"
  - "require_admin"

ssrf_guard_functions:
  - "is_safe_external_url"

verification:
  commands:
    - name: "pytest"
      run: "pytest"
      cwd: "."
      on_risk: ["HIGH", "MID"]
      on_paths:
        - "backend/**/*.py"

    - name: "frontend build"
      run: "npm run build"
      cwd: "frontend"
      on_paths:
        - "frontend/**"
```

配置项说明：
- `auth_markers`：追加项目特有的鉴权标志
- `ssrf_guard_functions`：SSRF 校验函数名
- `verification.commands`：修复后的验证命令（测试/构建/类型检查）
- `on_risk`：按风险级别过滤
- `on_paths`：按改动路径过滤

未配置 `verification` 时，扫描器自动发现默认命令（pytest / mvn test / npm test / tsc 等）。

---

## 验证闭环：为什么修复后必须跑验证

### 历史教训

| 案例 | 修复建议 | 第二轮发现的回归 | 原因 |
|---|---|---|---|
| R1 | 删掉下发给前端的 AI Key | 改空串后前端 `if(!apiKey) throw` → LLM 全线不可用 | 没意识到删 key 会打断跨文件调用链 |
| R2 | SSRF 校验拒绝内网 IP | 补丁漏 CGN 段 `100.64.0.0/10` 和阿里云元数据 | 提了方向，没验证补丁是否覆盖所有内网段 |

### 验证分层

修复后不能只重扫——必须跑验证确认无回归。

| 级别 | 触发条件 | 验证要求 |
|---|---|---|
| P0 / 高危 | 任意 P0，或改动鉴权/数据库/计费/部署/跨存储删除 | 跑项目完整测试套件 + 复现红→绿 + 追调用链声明副作用 |
| P1（鉴权/计费/DB写/外部付费API） | 涉及上述领域 | 跑相关模块测试或最小验证脚本（至少一个正向 + 一个越权/边界负向用例） |
| P1（其他） | 其他 P1 | 最小验证或构建/类型验证 |
| P2 / 低危 | 纯 UI/注释/文档/小重构 | 构建/类型验证 |

验证失败 = 不通过，必须修复后重新触发流程。

---

## 跨模型对抗

skeptic agent 必须用与 review agent **不同**的模型，确保盲区不重叠。

当前可用模型：
- `model: 'fable'` — glm-5.2（智谱）
- 默认模型 — deepseek-v4-pro

不同训练数据、不同架构 → 盲区不重叠 → 真正的对抗，而非同模型自审。

---

## License

MIT
