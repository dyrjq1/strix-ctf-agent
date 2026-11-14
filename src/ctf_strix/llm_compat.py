"""显式 ``max_tokens`` 注入（2026-11-14，网关兼容）。

比赛网关（DashScope 系 OpenAI 兼容端点）要求每次 chat/completions 请求
**显式携带 max_tokens**：缺参时返回 400 ``Range of max_tokens should be
[1, 8192]``——文案说的是范围，实测纯 ``{"model","messages"}`` 请求（无
stream、无任何其他字段）也报同样的错，所以它实际是「缺参」，报错文案
有误导性。

为什么此前没暴露：

* ``llm_preflight`` 探针固定发 ``max_tokens=1``，预检永远探测不到；
* 人工 curl 探针习惯带 ``max_tokens=5``，同样测不出；
* agent 主循环的 ``ModelSettings.max_tokens`` 为 None，OpenAI SDK 会把
  None 字段从请求体里剔除——于是初选赛配置（网关路由）下**每一次调用**
  都 400，整局零工具输出（CTFARENA-108 冒烟实测：18+ 次重放、837s 空烧）。

修复方式是环境变量 ``LLM_MAX_TOKENS``：

* 不设置 → 行为与现在完全一致（api.deepseek.com 等端点缺参可用）；
* 设置为正整数 → 透明模型代理在 ``model_settings.max_tokens`` 为 None 时
  注入该值；调用方已显式设置的（如 compaction 摘要的 4096）**不被覆盖**。

这是协议兼容接线，不是预算调节：值必须落在端点公布的范围内（比赛网关
为 [1, 8192]），由部署配置声明，代码不做任何推断。

回滚：删掉 agent.py 挂载点的 ``llm_compat.install()`` 调用即可（或
``LLM_MAX_TOKENS`` 不设）。无环境变量时本模块的代理就是纯转发。
"""

from __future__ import annotations

import logging
import os
from typing import Any, Final

logger = logging.getLogger(__name__)

#: 注入开关。名字沿用 ``LLM_*`` 家族（与 ``LLM_API_BASE`` 等部署配置同侧），
#: 不用 ``STRIX_*``：那是 agent 自身行为的旋钮，这里描述的是对端协议。
_ENV_NAME: Final = "LLM_MAX_TOKENS"


def max_tokens_from_env() -> int | None:
    """读 ``LLM_MAX_TOKENS``；非正整数告警并视为未设置。"""
    raw = os.environ.get(_ENV_NAME, "").strip()
    if not raw:
        return None
    try:
        value = int(raw)
    except ValueError:
        logger.warning("ctf-llm: %s=%r 不是整数，忽略", _ENV_NAME, raw)
        return None
    if value <= 0:
        logger.warning("ctf-llm: %s=%d 非正，忽略", _ENV_NAME, value)
        return None
    return value


def _settings_of(args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any | None:
    """ModelSettings 是第 3 个位置参数，也可能按关键字传。"""
    if "model_settings" in kwargs:
        return kwargs["model_settings"]
    if len(args) >= 3:
        return args[2]
    return None


def _inject(args: tuple[Any, ...], kwargs: dict[str, Any]) -> tuple[tuple[Any, ...], dict[str, Any]]:
    """把 ``LLM_MAX_TOKENS`` 注入一次调用的 model_settings（不覆盖显式值）。"""
    from agents.model_settings import ModelSettings

    value = max_tokens_from_env()
    if value is None:
        return args, kwargs
    settings = _settings_of(args, kwargs)
    if settings is None:
        return args, kwargs
    if getattr(settings, "max_tokens", None) is not None:
        return args, kwargs
    resolved = settings.resolve(ModelSettings(max_tokens=value))
    if "model_settings" in kwargs:
        kwargs = {**kwargs, "model_settings": resolved}
    else:
        args = (args[0], args[1], resolved, *args[3:])
    return args, kwargs


class _MaxTokensProxy:
    """透明代理：只补 ``max_tokens``，其余一律转发给内层 Model。

    与 ``context._CappingProxy`` 同一条接缝（包 ``StrixProvider.get_model``
    的返回值）：两条代理互不感知、可叠加，顺序无关。
    """

    def __init__(self, inner: Any) -> None:
        self._inner = inner

    async def close(self) -> None:
        await self._inner.close()

    async def _cleanup_on_run_end(self, owner: object) -> None:
        await self._inner._cleanup_on_run_end(owner)

    def get_retry_advice(self, request: Any) -> Any:
        return self._inner.get_retry_advice(request)

    async def get_response(self, *args: Any, **kwargs: Any) -> Any:
        args, kwargs = _inject(args, kwargs)
        return await self._inner.get_response(*args, **kwargs)

    def stream_response(self, *args: Any, **kwargs: Any) -> Any:
        args, kwargs = _inject(args, kwargs)
        return self._inner.stream_response(*args, **kwargs)


def install() -> bool:
    """把代理挂到 ``StrixProvider.get_model`` 上（幂等）。

    Returns:
        ``True`` 当代理已安装（或本就在位）。
    """
    from strix.config.models import StrixProvider

    if getattr(StrixProvider, "_ctf_max_tokens_patched", False):
        return True
    original = StrixProvider.get_model

    def patched(self: Any, model_name: str | None) -> Any:
        return _MaxTokensProxy(original(self, model_name))

    StrixProvider.get_model = patched  # type: ignore[method-assign]
    StrixProvider._ctf_max_tokens_patched = True  # type: ignore[attr-defined]
    value = max_tokens_from_env()
    if value is not None:
        logger.info("ctf-llm: explicit max_tokens=%d from %s", value, _ENV_NAME)
    else:
        logger.debug("ctf-llm: %s unset, proxy is pass-through", _ENV_NAME)
    return True
