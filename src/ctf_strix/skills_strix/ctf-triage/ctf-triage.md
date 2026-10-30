---
name: ctf-triage
description: 拿到一道还没有分类的 CTF 题时的第一站。Use when the challenge arrives as an unknown file, a remote host, an HTTP endpoint, or only a title — and you must decide which specialised skill to load before spending effort. Runs a fixed, cheap triage sequence and maps findings to the right category skill. Do not use it when the category is already known and the specialised skill is already loaded.
license: MIT
compatibility: Requires bash and Python 3 with file/binwalk/exiftool/checksec available (or install on demand).
allowed-tools: Bash Read Glob Grep
metadata:
  user-invocable: "false"
  origin: 本仓库自建，补上游缺失的统一分流入口
---

# CTF Triage：先定型，再深挖

**分流花的时间应当少于 2 分钟。** 定型错了，后面所有努力都是浪费；定型对了，专用技能才起作用。

## 一分钟定型

```bash
TARGET="$1"
[ -e "$TARGET" ] && file "$TARGET" && head -c 64 "$TARGET" | xxd | head -4
```

按 `file` 输出直接路由：

| `file` 说 | 先加载 |
|---|---|
| `ELF * pie executable`、`ELF * shared object`（带 PIE / canary / NX 差异） | `ctf-pwn/ctf-pwn` |
| `ELF` 但明显是被 strip 的处理链、`PE32`、`.apk`、`.wasm`、`.pyc` | `ctf-reverse/ctf-reverse` |
| `Zip`、`PDF`、`pcap`、`disk image`、`JPEG/PNG` 但体积反常 | `ctf-forensics/ctf-forensics` |
| 纯文本、base 家族、谜题式 | `ctf-misc/ctf-misc` |
| 一大串数字 / 曲线参数 / 密钥 | `ctf-crypto/ctf-crypto` |
| 空文件 / 只有 URL / 只有 `nc host port` | 见下方"远程题" |

## 远程题：先看端口服务说什么

```bash
##########
# 不要一上来就 nc 空等，先抓 banner
##########
timeout 4 bash -c "exec 3<>/dev/tcp/HOST/PORT; head -c 300 <&3" || echo "[无 banner]"
```

| banner 特征 | 方向 |
|---|---|
| `HTTP/1.` | `ctf-web/ctf-web`；若页面像 AI 工具（Gradio / 聊天框 / 工作流画布）→ `ctf-ai-infra/ctf-ai-infra` |
| `SSH-` | 通常是跳板，找凭据（`ctf-forensics` 或 `ctf-misc`） |
| 自定义提示语（"Enter your name:"） | `ctf-pwn/ctf-pwn`，先要二进制附件 |
| 返回一堆 JSON / 版本号 | `ctf-ai-infra/ctf-ai-infra` |

**HTTP 题再补一步**——看技术栈，别急着扫：

```bash
curl -sI "http://HOST:PORT/" | grep -iE 'server|x-powered-by|x-version'
curl -s "http://HOST:PORT/" | grep -oiE '(gradio|dify|comfyui|ollama|open-webui|langflow|n8n)' | sort -u
```

## 二进制题的 30 秒体检

```bash
checksec --file=./chall 2>/dev/null || pwn checksec ./chall 2>/dev/null
readelf -h ./chall | grep -E 'Type|Machine'
strings -n 6 ./chall | grep -iE 'flag|/bin/sh|system|win|seccomp' | head
```

**判决表**：

| 看到 | 结论 |
|---|---|
| 有 `win` / `flag` 函数且无 PIE | 最简单的一类，溢出改返回地址即可 |
| 有 `system` 且有 `/bin/sh` | ret2libc 或直接注入 |
| 有 `seccomp` / `prctl` | 沙箱题，用 `ctf-pwn` 的 seccomp 章节 |
| 大量无意义的跳转 / 解释器循环 | 是 VM 题，转 `ctf-reverse/ctf-reverse` |
| 静态链接 + musl | 堆题且 libc 算法不同，看 `ctf-pwn` 的 musl 章节 |

## 逆向题的 30 秒体检

```bash
strings -n 8 ./chall | head -20
# 有 Go / Rust 特征就直接找符号，不要硬看反汇编
readelf -p .comment ./chall 2>/dev/null | head -3
nm -C ./chall 2>/dev/null | head -5     # 没 strip 的话这一步就结束了
```

**Go / Rust 题的捷径**：符号没被 strip 时，函数名直接告诉你逻辑在哪；被 strip 了用
`go tool objdump` 或找 `runtime.` 前缀恢复。**不要从 `main` 开始逐行读。**

## 别做的事

- **不要对未知文件跑 `binwalk -e`** 就以为在做题——先看 `file`，很多题根本不是嵌入文件
- **不要一开始就上网搜题面**。同名题很多，抄错方向比不做更浪费时间；先本地定型
- **不要在未定型时加载重型技能**。`ctf-crypto` 索引 10.5k token，加载错了就是纯浪费
- **不要相信题目分类标签**。写着 Misc 的经常是 pwn，写着 Web 的经常是 AI 栈

## 输出

定型后，用一句话写下你的判断和依据，例如：

```
分类: pwn（ELF x86-64, PIE=off, NX=on, 有 win 函数）
下一步: 找溢出偏移 -> 覆盖返回地址到 win
```

**这句话本身就值得写**——后面卡住回看时，你会知道自己当初是不是定错型了。
