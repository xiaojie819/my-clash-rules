from __future__ import annotations

import argparse
import sys
from pathlib import Path

from compiler.config import (
    ConfigError,
    config_summary,
    load_config,
)
from compiler.pipeline import (
    pipeline_summary,
    run_pipeline,
)

# ============================================================
# 常量
# ============================================================

DEFAULT_CONFIG = (
    "config/sources.yaml"
)


# ============================================================
# Command
# ============================================================

def command_build(
    args: argparse.Namespace,
) -> int:

    try:

        config = load_config(
            args.config
        )


    except (
        FileNotFoundError,
        ConfigError,
    ) as exc:

        print(
            f"[ERROR] 配置加载失败: {exc}"
        )

        return 1



    print(
        config_summary(
            config
        )
    )


    print()


    result = run_pipeline(
        config
    )


    print(
        pipeline_summary(
            result
        )
    )


    if result.success:

        print()

        print(
            "[OK] 构建完成"
        )

        return 0


    else:

        print()

        print(
            "[FAIL] 构建失败"
        )

        return 1



def command_check(
    args: argparse.Namespace,
) -> int:

    try:

        config = load_config(
            args.config
        )


    except (
        FileNotFoundError,
        ConfigError,
    ) as exc:

        print(
            f"[ERROR] 配置检查失败: {exc}"
        )

        return 1



    print(
        "[OK] 配置格式正确"
    )

    print()

    print(
        config_summary(
            config
        )
    )


    return 0



def command_summary(
    args: argparse.Namespace,
) -> int:

    try:

        config = load_config(
            args.config
        )


    except (
        FileNotFoundError,
        ConfigError,
    ) as exc:

        print(
            f"[ERROR] 配置读取失败: {exc}"
        )

        return 1



    print(
        config_summary(
            config
        )
    )


    return 0



def command_clean(
    args: argparse.Namespace,
) -> int:

    """
    清理生成文件。

    默认只清理：
        rules/
        reports/

    不删除：
        config/
        compiler/
    """


    targets = [

        Path("rules"),

        Path("reports"),

    ]


    removed = 0


    for target in targets:

        if not target.exists():

            continue


        for item in target.rglob("*"):

            if item.is_file():

                item.unlink()

                removed += 1



    print(
        f"[OK] 清理完成，删除 {removed} 个文件"
    )


    return 0



# ============================================================
# CLI
# ============================================================

def create_parser() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(

        description=(

            "Universal Clash Rule Compiler"

        )

    )


    parser.add_argument(

        "--config",

        default=DEFAULT_CONFIG,

        help=(

            "sources.yaml 路径"

        ),

    )


    subparsers = (
        parser.add_subparsers(
            dest="command",
            required=True,
        )
    )


    # build

    build_parser = (
        subparsers.add_parser(
            "build",
            help="构建所有规则",
        )
    )

    build_parser.set_defaults(
        func=command_build
    )


    # check

    check_parser = (
        subparsers.add_parser(
            "check",
            help="检查配置",
        )
    )

    check_parser.set_defaults(
        func=command_check
    )


    # summary

    summary_parser = (
        subparsers.add_parser(
            "summary",
            help="查看配置摘要",
        )
    )

    summary_parser.set_defaults(
        func=command_summary
    )


    # clean

    clean_parser = (
        subparsers.add_parser(
            "clean",
            help="清理生成文件",
        )
    )

    clean_parser.set_defaults(
        func=command_clean
    )


    return parser



# ============================================================
# Entry
# ============================================================

def main() -> int:

    parser = create_parser()

    args = parser.parse_args()

    return args.func(
        args
    )


if __name__ == "__main__":

    sys.exit(
        main()
    )
