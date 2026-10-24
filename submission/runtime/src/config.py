"""项目根目录的共享配置。

由于脚本位于 <项目根目录>/src/ 下，这里从脚本自身所在位置向上两级推导根目录，
因此可在任意电脑上运行，无需硬编码绝对路径。
"""
import os

# 项目根目录 = src 的上一级（本文件位于 <root>/src/config.py）
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
