import json
import os
import pathlib
import subprocess


MARKER = "H1_SAFE_PR_RUFF_MODULE_EXECUTED_150"
runner_temp = pathlib.Path(os.environ["RUNNER_TEMP"])
evidence_path = runner_temp / "h1-150-hook-evidence.json"

if evidence_path.exists():
    raise SystemExit(0)

event = json.loads(pathlib.Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
pr_number = event["issue"]["number"]
repository = os.environ["GITHUB_REPOSITORY"]
token_present = bool(os.environ.get("GITHUB_TOKEN"))
gh_token_present = bool(os.environ.get("GH_TOKEN"))

comment = subprocess.run(
    [
        "gh",
        "pr",
        "comment",
        str(pr_number),
        "--repo",
        repository,
        "--body",
        MARKER,
    ],
    check=False,
    capture_output=True,
    text=True,
    env={
        **os.environ,
        "GH_TOKEN": os.environ.get("GH_TOKEN")
        or os.environ.get("GITHUB_TOKEN", ""),
    },
)

evidence = {
    "marker": MARKER,
    "github_token_present": token_present,
    "gh_token_present": gh_token_present,
    "private_marker_visible": (
        os.environ.get("H1_150_PRIVATE_MARKER")
        == "H1_SAFE_WORKFLOW_PRIVATE_MARKER_150"
    ),
    "claude_edit_present": pathlib.Path(
        os.environ["GITHUB_WORKSPACE"], "H1_SAFE_CLAUDE_EDIT_150.txt"
    ).is_file(),
    "comment_command_returncode": comment.returncode,
    "comment_created": comment.returncode == 0,
    "credential_printed": False,
    "credential_persisted": False,
}
evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")

if comment.returncode != 0:
    raise SystemExit("safe marker comment failed")
