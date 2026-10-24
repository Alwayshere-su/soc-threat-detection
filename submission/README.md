# 算法2：模型及结果复现说明

赛题：基于SOC日志网络安全威胁检测算法设计与实现。

平台最终成绩为0.97279254。结果文件为本目录res.csv，共55,837条，字段为event\_id、pred\_label。

结果SHA256：d792a4f9eb6327bf7b4af157e4e8940dd3310954a728e10db4f91f230a26189d。

## 方法

方案由三种子LightGBM集成、语义模型与路由、内容规则及LLM辅助判断组成。LLM辅助判断按赛事允许的使用方式作为方法组成部分披露，使用过Qwen系列本地量化模型及DeepSeek API。

最终复现重新计算特征、运行本地模型与规则，并按内容哈希回放已冻结的LLM辅助判断；并非每次重新调用LLM，也不是仅由一个训练模型直接输出。

## 环境与执行

```powershell
# 1. 创建本机虚拟环境
py -m venv .venv

# 2. 安装依赖，需要联网
.\.venv\Scripts\python.exe -m pip install -r .\requirements.txt

# 3. 检查提交材料完整性
.\.venv\Scripts\python.exe .\verify.py

# 4. 执行离线复现
.\.venv\Scripts\python.exe .\predict.py --input ".\test_input.csv" --out ".\outputs\res.csv"
```

也可执行：

```powershell
.\reproduce.ps1 -InputFile "D:\官方数据\test_input.csv"
```

输出路径须不存在。程序生成res.csv、res.report.json、res.log，并检查全部event\_id、顺序、标签及最终文件哈希。可添加--keep-intermediates保留逐层输出。

## 复测范围

入口核验原始官方B集CSV或对应的已验证Parquet哈希，用于重建本次提交；重新排序、重新另存的输入或新测试集会被拒绝。CSV和Parquet两种输入已在独立目录完成复现，得到与提交文件字节一致的结果。

## 文件组织

runtime中的历史说明、报告、清单及来源配置作为原始溯源材料保留，部分文字描述的是当时实验状态；最终提交状态以本说明和score.json为准。原始冻结文件保持字节不变，以维持逐层完整性检查。

包内不含官方原始数据、虚拟环境、API凭据或历史Qwen原始大权重。当前离线复现不依赖这些大模型权重。现存训练材料为摘要报告，详见复测材料。
