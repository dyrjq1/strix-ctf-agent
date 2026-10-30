#!/usr/bin/env bash
# 离线自检：不联网、不花 LLM 额度，验证"这套东西在本机是活的"。
#
# 五项：依赖能 import / 回归测试 / 规则库能读 / 技能包能装 / 沙箱能力探测。
# 任何一项红，先别去跑真题——那只会把环境问题伪装成"模型解不出题"。
set -uo pipefail
cd "$(dirname "$0")"
export PYTHONPATH=src:vendor/src
PY=.venv/bin/python
fail=0

say() { printf '\n== %s\n' "$1"; }
ok()  { printf '   PASS %s\n' "$1"; }
bad() { printf '   FAIL %s\n' "$1"; fail=$((fail+1)); }

if [ ! -x "$PY" ]; then
  echo "没有 .venv，先跑 ./setup.sh" >&2
  exit 1
fi

say "1. 关键模块 import"
if "$PY" -c "import strix, ctf_strix, agents, litellm" 2>/dev/null; then
  ok "strix / ctf_strix / agents / litellm"
else
  bad "import 失败，依赖没装全"
fi

say "2. 回归测试"
if "$PY" -m pytest -q >/tmp/ctf-selftest-pytest.log 2>&1; then
  ok "$(tail -2 /tmp/ctf-selftest-pytest.log | tr -d '\n')"
else
  bad "pytest 有失败，详见 /tmp/ctf-selftest-pytest.log"
fi

say "3. 规则库"
"$PY" - <<'EOF' || fail=$((fail+1))
from ctf_strix.aisec import aig_probe
root = aig_probe.data_dir()
assert root, "找不到规则库（src/ctf_strix/aisec/data）"
rb = aig_probe._RULES
fp, idx = len(rb.fingerprints()), len(rb.vuln_index())
rules = sum(len(v) for v in rb.vuln_index().values())
print(f"   PASS 指纹 {fp} / 组件 {idx} / 规则 {rules}")
assert (fp, idx, rules) == (163, 147, 2581), "条数和预期不一致，数据被换过"
n = len(aig_probe.lookup("ollama", "0.1.29"))
print(f"   PASS ollama 0.1.29 -> {n} 条 CVE")
assert n == 27
EOF

say "4. 技能包"
"$PY" - <<'EOF' || fail=$((fail+1))
from ctf_strix import skillpack
names = skillpack.register()
print(f"   PASS 注册 {len(names)} 个索引技能")
assert len(names) == 12, f"预期 12 个索引，实际 {len(names)}"
from strix.skills import load_skills
body = load_skills(["ctf-triage/ctf-triage"])
text = list(body.values())[0]
assert "子文件目录" in text, "路径提示没插进索引"
print(f"   PASS ctf-triage 可加载（{len(text)} 字符，含路径提示）")
EOF

say "5. 沙箱能力"
"$PY" - <<'EOF'
from ctf_strix import jail
if jail.available():
    print("   PASS unshare mount namespace 可用（eval_sample 平台评测可跑）")
else:
    print("   SKIP 当前环境不允许 unshare：平台评测 eval_sample 不可用，")
    print("        但 run_strix_ctf.py 单跑一题仍然可用（只是少了隔离）")
EOF

echo
if [ "$fail" -eq 0 ]; then
  echo "全部通过"
  exit 0
fi
echo "有 $fail 项失败"
exit 1
