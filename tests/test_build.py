from compiler.config import load_config
from compiler.pipeline import run_pipeline


def test_full_build_pipeline():

    config = load_config()

    result = run_pipeline(
        config
    )

    assert result.success

    assert len(result.groups) > 0

    group = result.groups[0]

    assert group.success

    assert len(group.rules) > 0
