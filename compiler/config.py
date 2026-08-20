from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .build import OutputMode
from .models import SourceFormat
from .optimize import OptimizeMode

# ============================================================
# 异常
# ============================================================

class ConfigError(ValueError):
    """
    配置文件格式错误。
    """


# ============================================================
# 配置对象
# ============================================================

@dataclass(slots=True)
class DefaultConfig:
    output_mode: OutputMode = OutputMode.STRICT

    optimize_mode: OptimizeMode = OptimizeMode.SAFE

    sort_output: bool = True

    timeout: int = 30

    continue_on_source_error: bool = True


@dataclass(slots=True)
class SourceConfig:
    name: str

    url: str

    enabled: bool = True

    format: SourceFormat | None = None

    timeout: int | None = None

    metadata: dict[str, Any] = field(
        default_factory=dict
    )


@dataclass(slots=True)
class GroupConfig:
    name: str

    enabled: bool = True

    output: str = ""

    report: str = ""

    sources: list[SourceConfig] = field(
        default_factory=list
    )

    output_mode: OutputMode = OutputMode.STRICT

    optimize_mode: OptimizeMode = OptimizeMode.SAFE

    sort_output: bool = True

    timeout: int = 30

    continue_on_source_error: bool = True

    metadata: dict[str, Any] = field(
        default_factory=dict
    )


@dataclass(slots=True)
class AppConfig:
    version: int

    defaults: DefaultConfig

    groups: dict[str, GroupConfig]

    path: Path | None = None


# ============================================================
# 基础工具
# ============================================================

def _require_mapping(
    value: Any,
    *,
    field_name: str,
) -> dict[str, Any]:
    if value is None:
        return {}

    if not isinstance(
        value,
        dict,
    ):
        raise ConfigError(
            f"{field_name} 必须是对象/map"
        )

    return value


def _require_list(
    value: Any,
    *,
    field_name: str,
) -> list[Any]:
    if value is None:
        return []

    if not isinstance(
        value,
        list,
    ):
        raise ConfigError(
            f"{field_name} 必须是列表"
        )

    return value


def _as_bool(
    value: Any,
    *,
    default: bool,
    field_name: str,
) -> bool:
    if value is None:
        return default

    if isinstance(
        value,
        bool,
    ):
        return value

    raise ConfigError(
        f"{field_name} 必须是 true/false"
    )


def _as_int(
    value: Any,
    *,
    default: int,
    field_name: str,
    minimum: int | None = None,
) -> int:
    if value is None:
        return default

    if isinstance(
        value,
        bool,
    ):
        raise ConfigError(
            f"{field_name} 必须是整数"
        )

    if not isinstance(
        value,
        int,
    ):
        raise ConfigError(
            f"{field_name} 必须是整数"
        )

    if (
        minimum is not None
        and value < minimum
    ):
        raise ConfigError(
            f"{field_name} 不能小于 {minimum}"
        )

    return value


def _as_string(
    value: Any,
    *,
    default: str = "",
    field_name: str,
) -> str:
    if value is None:
        return default

    if not isinstance(
        value,
        str,
    ):
        raise ConfigError(
            f"{field_name} 必须是字符串"
        )

    return value.strip()


# ============================================================
# 枚举转换
# ============================================================

def _parse_output_mode(
    value: Any,
    *,
    default: OutputMode,
    field_name: str,
) -> OutputMode:
    if value is None:
        return default

    if isinstance(
        value,
        OutputMode,
    ):
        return value

    if not isinstance(
        value,
        str,
    ):
        raise ConfigError(
            f"{field_name} 必须是字符串"
        )

    try:
        return OutputMode(
            value.strip().lower()
        )

    except ValueError as exc:
        allowed = ", ".join(
            item.value
            for item in OutputMode
        )

        raise ConfigError(
            f"{field_name} 无效: {value!r}；"
            f"允许值: {allowed}"
        ) from exc


def _parse_optimize_mode(
    value: Any,
    *,
    default: OptimizeMode,
    field_name: str,
) -> OptimizeMode:
    if value is None:
        return default

    if isinstance(
        value,
        OptimizeMode,
    ):
        return value

    if not isinstance(
        value,
        str,
    ):
        raise ConfigError(
            f"{field_name} 必须是字符串"
        )

    try:
        return OptimizeMode(
            value.strip().lower()
        )

    except ValueError as exc:
        allowed = ", ".join(
            item.value
            for item in OptimizeMode
        )

        raise ConfigError(
            f"{field_name} 无效: {value!r}；"
            f"允许值: {allowed}"
        ) from exc


def _parse_source_format(
    value: Any,
    *,
    field_name: str,
) -> SourceFormat | None:
    """
    auto / null:
        返回 None
        交给 detect.py 自动判断
    """

    if value is None:
        return None

    if isinstance(
        value,
        SourceFormat,
    ):
        return value

    if not isinstance(
        value,
        str,
    ):
        raise ConfigError(
            f"{field_name} 必须是字符串"
        )

    normalized = (
        value.strip().lower()
    )

    if normalized in {
        "",
        "auto",
        "detect",
    }:
        return None

    try:
        return SourceFormat(
            normalized
        )

    except ValueError as exc:
        allowed = [
            "auto",
            *[
                item.value
                for item in SourceFormat
            ],
        ]

        raise ConfigError(
            f"{field_name} 无效: {value!r}；"
            f"允许值: {', '.join(allowed)}"
        ) from exc


# ============================================================
# Defaults
# ============================================================

def parse_defaults(
    raw: dict[str, Any],
) -> DefaultConfig:
    return DefaultConfig(
        output_mode=_parse_output_mode(
            raw.get(
                "output_mode"
            ),
            default=OutputMode.STRICT,
            field_name=(
                "defaults.output_mode"
            ),
        ),
        optimize_mode=_parse_optimize_mode(
            raw.get(
                "optimize_mode"
            ),
            default=OptimizeMode.SAFE,
            field_name=(
                "defaults.optimize_mode"
            ),
        ),
        sort_output=_as_bool(
            raw.get(
                "sort_output"
            ),
            default=True,
            field_name=(
                "defaults.sort_output"
            ),
        ),
        timeout=_as_int(
            raw.get(
                "timeout"
            ),
            default=30,
            minimum=1,
            field_name=(
                "defaults.timeout"
            ),
        ),
        continue_on_source_error=_as_bool(
            raw.get(
                "continue_on_source_error"
            ),
            default=True,
            field_name=(
                "defaults."
                "continue_on_source_error"
            ),
        ),
    )


# ============================================================
# Source
# ============================================================

def parse_source(
    raw: dict[str, Any],
    *,
    group_name: str,
    index: int,
    group_timeout: int,
) -> SourceConfig:

    prefix = (
        f"groups.{group_name}."
        f"sources[{index}]"
    )

    name = _as_string(
        raw.get(
            "name"
        ),
        field_name=f"{prefix}.name",
    )

    if not name:
        raise ConfigError(
            f"{prefix}.name 不能为空"
        )

    url = _as_string(
        raw.get(
            "url"
        ),
        field_name=f"{prefix}.url",
    )

    if not url:
        raise ConfigError(
            f"{prefix}.url 不能为空"
        )

    if not url.startswith(
        (
            "http://",
            "https://",
        )
    ):
        raise ConfigError(
            f"{prefix}.url 必须是 "
            "http:// 或 https:// 地址"
        )

    enabled = _as_bool(
        raw.get(
            "enabled"
        ),
        default=True,
        field_name=f"{prefix}.enabled",
    )

    source_format = (
        _parse_source_format(
            raw.get(
                "format"
            ),
            field_name=f"{prefix}.format",
        )
    )

    timeout_raw = raw.get(
        "timeout"
    )

    if timeout_raw is None:
        timeout = None

    else:
        timeout = _as_int(
            timeout_raw,
            default=group_timeout,
            minimum=1,
            field_name=f"{prefix}.timeout",
        )

    known_keys = {
        "name",
        "url",
        "enabled",
        "format",
        "timeout",
        "metadata",
    }

    metadata_raw = _require_mapping(
        raw.get(
            "metadata"
        ),
        field_name=f"{prefix}.metadata",
    )

    # 未知字段先保留下来。
    # 这样以后扩展 source 配置时，
    # 不会立刻破坏旧 loader。
    metadata = dict(
        metadata_raw
    )

    extra = {
        key: value
        for key, value in raw.items()
        if key not in known_keys
    }

    if extra:
        metadata[
            "_extra"
        ] = extra

    return SourceConfig(
        name=name,
        url=url,
        enabled=enabled,
        format=source_format,
        timeout=timeout,
        metadata=metadata,
    )


# ============================================================
# Group
# ============================================================

def parse_group(
    name: str,
    raw: dict[str, Any],
    *,
    defaults: DefaultConfig,
) -> GroupConfig:

    prefix = (
        f"groups.{name}"
    )

    enabled = _as_bool(
        raw.get(
            "enabled"
        ),
        default=True,
        field_name=f"{prefix}.enabled",
    )

    output = _as_string(
        raw.get(
            "output"
        ),
        default=f"rules/{name}.yaml",
        field_name=f"{prefix}.output",
    )

    report = _as_string(
        raw.get(
            "report"
        ),
        default=f"reports/{name}.json",
        field_name=f"{prefix}.report",
    )

    if not output:
        raise ConfigError(
            f"{prefix}.output 不能为空"
        )

    if not report:
        raise ConfigError(
            f"{prefix}.report 不能为空"
        )

    output_mode = _parse_output_mode(
        raw.get(
            "output_mode"
        ),
        default=defaults.output_mode,
        field_name=(
            f"{prefix}.output_mode"
        ),
    )

    optimize_mode = _parse_optimize_mode(
        raw.get(
            "optimize_mode"
        ),
        default=defaults.optimize_mode,
        field_name=(
            f"{prefix}.optimize_mode"
        ),
    )

    sort_output = _as_bool(
        raw.get(
            "sort_output"
        ),
        default=defaults.sort_output,
        field_name=(
            f"{prefix}.sort_output"
        ),
    )

    timeout = _as_int(
        raw.get(
            "timeout"
        ),
        default=defaults.timeout,
        minimum=1,
        field_name=f"{prefix}.timeout",
    )

    continue_on_source_error = (
        _as_bool(
            raw.get(
                "continue_on_source_error"
            ),
            default=(
                defaults.
                continue_on_source_error
            ),
            field_name=(
                f"{prefix}."
                "continue_on_source_error"
            ),
        )
    )

    raw_sources = _require_list(
        raw.get(
            "sources"
        ),
        field_name=f"{prefix}.sources",
    )

    sources: list[
        SourceConfig
    ] = []

    for index, source_raw in enumerate(
        raw_sources
    ):
        if not isinstance(
            source_raw,
            dict,
        ):
            raise ConfigError(
                f"{prefix}.sources[{index}] "
                "必须是对象/map"
            )

        sources.append(
            parse_source(
                source_raw,
                group_name=name,
                index=index,
                group_timeout=timeout,
            )
        )

    known_keys = {
        "enabled",
        "output",
        "report",
        "sources",
        "output_mode",
        "optimize_mode",
        "sort_output",
        "timeout",
        "continue_on_source_error",
        "metadata",
    }

    metadata_raw = _require_mapping(
        raw.get(
            "metadata"
        ),
        field_name=(
            f"{prefix}.metadata"
        ),
    )

    metadata = dict(
        metadata_raw
    )

    extra = {
        key: value
        for key, value in raw.items()
        if key not in known_keys
    }

    if extra:
        metadata[
            "_extra"
        ] = extra

    return GroupConfig(
        name=name,
        enabled=enabled,
        output=output,
        report=report,
        sources=sources,
        output_mode=output_mode,
        optimize_mode=optimize_mode,
        sort_output=sort_output,
        timeout=timeout,
        continue_on_source_error=(
            continue_on_source_error
        ),
        metadata=metadata,
    )


# ============================================================
# 主解析
# ============================================================

def parse_config(
    data: dict[str, Any],
    *,
    path: Path | None = None,
) -> AppConfig:

    if not isinstance(
        data,
        dict,
    ):
        raise ConfigError(
            "配置文件根节点必须是对象/map"
        )

    version = data.get(
        "version",
        1,
    )

    if not isinstance(
        version,
        int,
    ):
        raise ConfigError(
            "version 必须是整数"
        )

    if version != 1:
        raise ConfigError(
            f"不支持的配置版本: {version}"
        )

    defaults_raw = _require_mapping(
        data.get(
            "defaults"
        ),
        field_name="defaults",
    )

    defaults = parse_defaults(
        defaults_raw
    )

    groups_raw = _require_mapping(
        data.get(
            "groups"
        ),
        field_name="groups",
    )

    groups: dict[
        str,
        GroupConfig
    ] = {}

    for group_name, group_raw in (
        groups_raw.items()
    ):
        if not isinstance(
            group_name,
            str,
        ):
            raise ConfigError(
                "groups 的名称必须是字符串"
            )

        group_name = (
            group_name.strip()
        )

        if not group_name:
            raise ConfigError(
                "group 名称不能为空"
            )

        if not isinstance(
            group_raw,
            dict,
        ):
            raise ConfigError(
                f"groups.{group_name} "
                "必须是对象/map"
            )

        if group_name in groups:
            raise ConfigError(
                f"重复 group: {group_name}"
            )

        groups[
            group_name
        ] = parse_group(
            group_name,
            group_raw,
            defaults=defaults,
        )

    return AppConfig(
        version=version,
        defaults=defaults,
        groups=groups,
        path=path,
    )


# ============================================================
# 文件读取
# ============================================================

def load_config(
    path: str | Path = (
        "config/sources.yaml"
    ),
) -> AppConfig:

    path = Path(
        path
    )

    if not path.exists():
        raise FileNotFoundError(
            f"配置文件不存在: {path}"
        )

    if not path.is_file():
        raise ConfigError(
            f"配置路径不是文件: {path}"
        )

    try:
        raw_text = path.read_text(
            encoding="utf-8-sig"
        )

    except OSError as exc:
        raise ConfigError(
            f"无法读取配置文件: {path}"
        ) from exc

    try:
        data = yaml.safe_load(
            raw_text
        )

    except yaml.YAMLError as exc:
        raise ConfigError(
            f"YAML 解析失败: {exc}"
        ) from exc

    if data is None:
        data = {}

    return parse_config(
        data,
        path=path,
    )


# ============================================================
# 查询辅助
# ============================================================

def enabled_groups(
    config: AppConfig,
) -> list[GroupConfig]:
    """
    获取 enabled=true 的组。
    """
    return [
        group
        for group in config.groups.values()
        if group.enabled
    ]


def enabled_sources(
    group: GroupConfig,
) -> list[SourceConfig]:
    """
    获取组内 enabled=true 的源。
    """
    return [
        source
        for source in group.sources
        if source.enabled
    ]


def get_group(
    config: AppConfig,
    name: str,
) -> GroupConfig:
    """
    获取指定 group。
    """

    try:
        return config.groups[
            name
        ]

    except KeyError as exc:
        raise ConfigError(
            f"找不到 group: {name}"
        ) from exc


# ============================================================
# 配置摘要
# ============================================================

def config_summary(
    config: AppConfig,
) -> str:

    groups = list(
        config.groups.values()
    )

    enabled_group_list = [
        group
        for group in groups
        if group.enabled
    ]

    source_count = sum(
        len(group.sources)
        for group in groups
    )

    enabled_source_count = sum(
        len(
            enabled_sources(
                group
            )
        )
        for group in enabled_group_list
    )

    lines = [
        "=== Config Summary ===",
        (
            "version: "
            f"{config.version}"
        ),
        (
            "groups: "
            f"{len(groups)}"
        ),
        (
            "enabled groups: "
            f"{len(enabled_group_list)}"
        ),
        (
            "sources: "
            f"{source_count}"
        ),
        (
            "enabled sources: "
            f"{enabled_source_count}"
        ),
    ]

    for group in groups:
        status = (
            "enabled"
            if group.enabled
            else "disabled"
        )

        source_enabled = len(
            enabled_sources(
                group
            )
        )

        lines.append(
            f"- {group.name}: "
            f"{status}, "
            f"{source_enabled}/"
            f"{len(group.sources)} sources"
        )

    return "\n".join(
        lines
    )
