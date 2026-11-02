# strix-ctf-agent - Claude Code 准则

## 这是什么
改造自 strix 1.7.0，参加清华 CTFY 智能体赛道。vendor/src/strix 一行不改，所有增强都在 src/ctf_strix，运行时挂载注入。

## 必读
- docs/11-实验台账.md 改动历史与回滚路径
- docs/08-CTFY-0001协议原文.md 平台契约
- docs/12-规则核对.md 规则逐条核对
- docs/25-防过拟合守则.md 评测改动红线
- docs/23-覆盖矩阵与对标.md 各方向覆盖现状
- docs/24-Codex工作框架.md 工作流程

## 红线
- 不改 vendor/ 下的上游代码
- 不 git commit、不建分支，除非用户明确要求
- 改前备份到 backup/<slug>-<日期>/，改后在 docs/11-实验台账.md 追加一节并写回滚路径
- 正式规则出来前不跑题，experiments/pools.json 一个字节都不动
- 预算（时间/轮次/并发/token）不得单独调，必须依附能力改动并写物理依据
- 一次只改一处；接线类修复（工具没注册、变量名写错、路径拼错）可合并
- reference/ 含 misc-bank 真 flag，已在 .dockerignore 与 .gitignore 排除，不要加回来

## 防过拟合
- 任何改动必须在它没参与过的题上验证过才算改完
- 命名测试：改动描述里不许出现题号、IP、具体路径、具体 flag
- 迁移测试：留出集提升小于 5 个百分点一律判过拟合
- 消融：撤掉改动再跑同题，变差才算有效，没变化是噪声，变好就回滚
- 上下文按龄裁剪是负优化（缓存命中 95.7% 降到 57.8%），已回滚为内容封顶

## 环境坑
- 本机 shell 会吞引号，不要用 python -c，先把脚本写到磁盘再执行
- 临时脚本放 C:\Users\rjq\AppData\Local\Temp\ctfwork，Temp 根目录有 mcp.py 会遮蔽 mcp 包
- pytest 前必须把 TMP 和 TEMP 指向 C:\Users\rjq\AppData\Local\Temp\ctfwork\pytmp，否则 pytest-of-rjq 触发 WinError 5
- Windows 下 rg 用 -g，不要用 *.py 通配

## 测试
set TMP=C:\Users\rjq\AppData\Local\Temp\ctfwork\pytmp
set TEMP=%TMP%
.venv\Scripts\python.exe -m pytest tests -q
基线：Windows 347 passed

## VM
ssh rjq@192.168.38.130 密码 54qhdxrjq
代码在 /home/rjq/work/strix-ctf-agent（非 git 仓库），传文件用 paramiko sftp.put()

## 汇报
中文、结论先行、给数据、10 行以内为常态
