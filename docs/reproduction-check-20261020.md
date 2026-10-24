# 复现验证记录（2026-10-20）

在重排后的目录上做了一次完整的离线复现，用来确认 `submission/` 与官方数据的相对位置调整
没有破坏推理链路。

> 本仓库不包含官方数据。下面记录的是当时的本地布局；如果你有官方数据，
> 把它放到任意位置并通过 `--input` 传入即可，脚本会用输入哈希校验是否为官方 B 集。

## 输入

- 官方 B 集输入 `test_input.csv`
- SHA256：`5a3db3aab57c33680e4627b0df75f9d526445c17964fd9f09d36f44eb6ae1d0b`
- 行数：55,837

## 命令

```powershell
cd submission
python reproduce.py --input "<官方数据目录>\test_input.csv" --out ..\outputs\res.csv
```

## 实际环境

- Windows 11 x64
- Anaconda CPython 3.12.13
- numpy 1.26.4、pandas 3.0.3、pyarrow 21.0.0、scikit-learn 1.9.0、lightgbm 4.6.0

这套环境与 `submission/environment.json` 的基线（CPython 3.13.5、numpy 2.4.4、pyarrow 25.0.0）
不同，但结果仍然逐字节一致。

## 结果

| 项目 | 结果 |
| --- | --- |
| 包完整性 | 227 个文件全部通过 |
| `verify.py` | `passed: true` |
| 输出行数 | 55,837 |
| 输出 SHA256 | `d792a4f9eb6327bf7b4af157e4e8940dd3310954a728e10db4f91f230a26189d` |
| 与 `EXPECTED` 对比 | 一致 |
| 耗时 | 877.5 秒 |
| 新增 LLM/API 调用 | 0 |
| 网络 | 推理子进程禁网 |
| 标签分布 | benign 31,654 / malicious 18,582 / suspicious 5,601 |

`outputs/` 下的 `res.csv`、`res.log`、`res.report.json` 是临时产物，验证后已清理；
该目录被 `.gitignore` 忽略，不影响 `manifest.json`。
