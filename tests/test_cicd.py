from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(relative_path):
    return (ROOT / relative_path).read_text(encoding="utf-8")


def test_github_action_installs_pinned_pypi_release():
    action = read("action.yml")

    assert 'default: "0.2.0"' in action
    assert 'pickle-sentry==${PICKLE_SENTRY_VERSION}' in action
    assert "git+https://github.com/Sun-Wukhan/pickle-sentry" not in action
    for input_name in ("path:", "fail-on:", "format:", "output:", "exclude:", "version:"):
        assert input_name in action


def test_cicd_examples_call_the_released_package_or_action():
    expected = {
        "examples/cicd/github-actions.yml": "uses: Sun-Wukhan/pickle-sentry@main",
        "examples/cicd/github-actions-sarif.yml": "github/codeql-action/upload-sarif@v3",
        "examples/cicd/gitlab-ci.yml": 'pickle-sentry==0.2.0',
        "examples/cicd/azure-pipelines.yml": 'pickle-sentry==0.2.0',
        "examples/cicd/Jenkinsfile": 'pickle-sentry==0.2.0',
    }

    for relative_path, needle in expected.items():
        assert needle in read(relative_path), relative_path


def test_cicd_document_explains_exit_code_contract():
    guide = read("docs/CI-CD.md")

    assert "## Exit-code contract" in guide
    assert "No finding reached the selected `--fail-on` threshold" in guide
    assert "At least one finding reached the selected `--fail-on` threshold" in guide
    assert 'pickle-sentry==0.2.0' in guide
