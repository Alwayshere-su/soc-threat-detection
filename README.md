# soc-threat-detection

**2026 人工智能算法挑战赛 · 算法2** — 基于 SOC 日志的网络安全威胁检测（正常 / 可疑 / 恶意 三分类）。

[![CI](https://github.com/Alwayshere-su/soc-threat-detection/actions/workflows/ci.yml/badge.svg)](https://github.com/Alwayshere-su/soc-threat-detection/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

平台 B 榜成绩 **0.97279254**。最终提交 `submission/res.csv` 共 55,837 行，
SHA256 `d792a4f9eb6327bf7b4af157e4e8940dd3310954a728e10db4f91f230a26189d`。

本仓库是赛后整理的可复现交付包：227 个文件的推理链、两个模型权重、冻结的 LLM 辅助判断、
独立性校验工具与训练/推理记录。官方数据与 API 凭据不随仓库分发（见 [数据与外部模型](#数据与外部模型)）。

---

## 结果

| 项目 | 数值 |
| --- | --- |
| 平台 B 榜综合分 | **0.97279254** |
| 提交行数 | 55,837 |
| benign / suspicious / malicious | 31,654 / 5,601 / 18,582 |
| 结果 SHA256 | `d792a4f9eb6327bf7b4af157e4e8940dd3310954a728e10db4f91f230a26189d` |
| 包内文件数 | 227（`submission/manifest.json` 逐个绑定 SHA256） |

`submission/score.json` 记录了成绩来源与上一版最好成绩 `0.97134111`（提升 `0.00145143`）。
B 榜逐行答案不公开，因此仓库无法给出逐类别的官方指标。

---

## 方法

方案不是单一模型，而是一条 17 段的决策链：

1. **三种子 LightGBM 集成**：在 SOC 日志的结构化特征上训练三个随机种子的 LightGBM，
   投票得到基础标签与置信度。
2. **语义模型与路由**：按日志内容特征路由到本地 Qwen3-4B / 8B / 14B（GGUF 量化），
   对模棱两可的样本做辅助判断；17 段链路中不同阶段使用不同模型与提示词。
3. **内容规则**：SQL 注入、路径穿越、弱口令、WebShell、扫描器等 payload 规则，
   以及证据锚点校验（`evidence_anchor_verified`）。
4. **LLM 辅助判断的冻结回放**：推理时不重新调用 LLM，而是按内容哈希查
   `semantic_predictions_frozen.json` 中已冻结的判断（1,567 条，含标签、置信度与简短理由）。
   这样既保留 LLM 的贡献，又保证离线、逐字节可复现。

最终入口是 `submission/runtime/lib/stages/17_refinement/predict.py`。

---

## 复现与校验

### 只做完整性校验（不需要推理环境）

```bash
cd submission
python verify.py
# {"passed": true, "files": 227, "rows": 55837, "prediction_sha256": "d792a4f9..."}
```

`verify.py` 只依赖 pandas：重算 `manifest.json` 中 227 个文件的哈希，
再检查 `res.csv` 的行数、列名、唯一性与标签取值。

仓库根目录还提供一份**纯标准库**的等价校验（CI 使用）：

```bash
python scripts/verify_manifest.py
```

### 完整离线复现

```bash
cd submission
python -m pip install -r requirements.txt
python reproduce.py --input <官方 test_input.csv> --out ../outputs/res.csv
```

注意：

- `reproduce.py` 绑定了官方 B 集输入的 SHA256（`5a3db3aa…`），**其他输入会被拒绝**，
  因此没有官方数据时只能跑完整性校验，不能跑端到端复现。
- 整个推理过程禁网、不调用任何 LLM API；冻结判断按内容哈希回放。
- 2026-10-20 在 Anaconda CPython 3.12.13 + numpy 1.26.4 上实测逐字节复现，
  55,837 行、哈希 `d792a4f9…`，耗时约 878 秒。基线环境见 `submission/environment.json`。
- 复现产物写到 `outputs/`，该目录被 `.gitignore` 忽略。

---

## 目录结构

```text
soc-threat-detection/
├─ submission/                    最终交付包（227 个文件，原样保留）
│  ├─ res.csv                     最终提交结果（55,837 行）
│  ├─ manifest.json               227 个文件的 SHA256 清单
│  ├─ verify.py                   只校验清单与 res.csv
│  ├─ reproduce.py / predict.py   离线复现入口
│  ├─ runtime/src/                特征、训练、评分、数据检查源码
│  ├─ runtime/lib/stages/         17 段决策链
│  ├─ tools/offline_guard/        推理子进程禁网审计
│  ├─ docs/                       独立验证、最终规则验证
│  └─ 复测材料/                   推理记录、训练报告、权重清单
├─ docs/
│  ├─ package-layout.md           交付包内部结构与易混淆点
│  └─ reproduction-check-20261020.md   一次完整复现的记录
├─ scripts/verify_manifest.py     纯标准库的清单校验（CI 使用）
├─ NOTICE                         第三方资源与授权边界
└─ .github/workflows/ci.yml       每次推送重算 227 个文件的哈希
```

---

## 完整性约定

- `submission/manifest.json` 用 SHA256 绑定每个文件的**字节**，
  因此 `.gitattributes` 对 `submission/**` 关闭了换行转换（`-text`）。
- **不要格式化或重新保存 `submission/` 下的文件**，否则哈希校验会失败。
- 整包重新压缩成 zip 时，zip 本身的哈希会变，但包内文件哈希不变；
  官方核验以 `manifest.json` 为准。

---

## 数据与外部模型

按赛事允许使用 LLM 辅助判断的规则，完整披露见
[`submission/复测材料/数据与外部模型使用说明.md`](submission/复测材料/数据与外部模型使用说明.md)。

| 资源 | 来源 | 用途 |
| --- | --- | --- |
| Qwen3-4B-Instruct-2507 | Qwen / lmstudio-community GGUF | 本地量化模型辅助判断 |
| Qwen3-8B | Qwen / lmstudio-community GGUF | 本地量化模型辅助判断 |
| Qwen3-14B | Qwen / bartowski GGUF | 本地量化模型辅助判断 |
| DeepSeek API | DeepSeek 外部服务 | 测试日志辅助判断（结果已冻结） |

- **不含**官方数据、验证集私有答案、API Key、历史 Qwen 大权重或虚拟环境。
- 冻结记录只保存内容哈希、标签、置信度与简短理由，不保存原始日志文本。
- 两个随包分发的 `.pkl` 是作者训练的 LightGBM 模型（34.4 MB + 9.5 MB），
  不含第三方模型权重。

---

## 局限

- B 榜逐行答案不公开，无法独立复核分类指标；仓库只能保证提交文件与推理链的完整性。
- 端到端复现依赖官方 B 集输入，数据不可得时只能做完整性校验。
- 方案包含大量人工规则与外部 LLM 辅助判断，属于竞赛语境下的工程组合，
  不是可直接上线的安全产品。
- 推理链对输入 schema 敏感，换数据分布需要重新校准。

---

## 许可与致谢

- 作者编写的代码、规则与模型权重：Apache License 2.0，见 [LICENSE](LICENSE) 与 [NOTICE](NOTICE)。
- Qwen 系列模型、LightGBM 等第三方组件遵循各自许可证，未随仓库分发。
- 赛题、官方数据与评分规则归主办方所有。
