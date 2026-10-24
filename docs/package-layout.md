# 交付包内部结构

本页说明 `submission/` 里各目录的用途，以及几个容易混淆的文件。

## 顶层

| 路径 | 用途 |
| --- | --- |
| `submission/` | 最终交付包，内部相对路径与原 zip 保持一致 |
| `submission/res.csv` | 最终提交结果，55,837 行 |
| `submission/manifest.json` | 227 个文件的 SHA256 清单 |
| `submission/reproduce.py` / `reproduce.ps1` / `predict.py` | 离线复现入口 |
| `submission/verify.py` | 只校验清单与 `res.csv`，不跑推理 |
| `submission/runtime/src/` | 特征、训练、评分、数据检查等源码 |
| `submission/runtime/lib/stages/` | 17 段推理决策链；`17_refinement/predict.py` 为最终入口 |
| `submission/runtime/exp/experiments/` | 语义特征与候选模型训练代码 |
| `submission/tools/offline_guard/` | 推理子进程禁网审计 |
| `submission/docs/` | 独立验证、最终规则验证（后者是提交前快照） |
| `submission/复测材料/` | 推理记录、训练报告、数据与外部模型使用说明、权重清单 |

仓库另外提供：

| 路径 | 用途 |
| --- | --- |
| `docs/reproduction-check-20261020.md` | 一次完整复现的记录 |
| `scripts/verify_manifest.py` | 纯标准库的清单校验，CI 使用 |

## 容易混淆的点

1. **两个 `res.csv`**
   - `submission/res.csv`：最终提交结果，55,837 行，哈希 `d792a4f9…`。
   - `submission/runtime/res.csv`：推理链输出的副本，内容相同，也受清单约束。
   - 官方数据包里的 `res.csv` 是约 200 万行的验证集样例，**不是**最终结果，也不在本仓库中。

2. **`manifest.json` 绑定的是字节**
   `.gitattributes` 对 `submission/**` 设置了 `-text`，避免 Git 转换换行。
   不要格式化、重新保存或批量替换 `submission/` 下的文件，否则校验会失败。

3. **复测记录与当前包不是同一版**
   `submission/复测材料/推理记录/archive_verification.json` 与 `最终核验.json`
   描述的是 10 月 18 日那版 70 MB / 486 文件的打包（`e8313f02…`）；
   当前包是 10 月 19 日精简重打包的 227 文件版本，以 `manifest.json` 为准。
   `verify.py` 对当前版本是通过的。

4. **`最终规则验证.json` 是提交前快照**
   其中 `submitted` 仍为 `false`、`official_score` 为 `null`；
   最终成绩以 `submission/score.json` 为准。该文件在清单中，保持原样。

5. **原始 zip 不在目录中**
   `算法2提交材料.zip` 已解压为 `submission/`。重新压缩时内容一致，但 zip 的 SHA256 会变化，
   不能再用 `e8313f02…` / `720276dc…` 核对。

6. **不随仓库分发的内容**
   官方数据、验证集私有答案、含个人信息的提交邮件、测试集 payload 原文、
   历史 Qwen 大权重与虚拟环境都不在仓库中；`.gitignore` 已覆盖常见路径。
