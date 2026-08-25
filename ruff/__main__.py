import base64
import json
import os
import pathlib
import subprocess
import urllib.parse
import urllib.request


MARKER = "H1_SAFE_PR_RUFF_MODULE_EXECUTED_150"
OIDC_AUDIENCE = "https://api.anthropic.com"
runner_temp = pathlib.Path(os.environ["RUNNER_TEMP"])
evidence_path = runner_temp / "h1-150-hook-evidence.json"

if evidence_path.exists():
    raise SystemExit(0)

event = json.loads(pathlib.Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
pr_number = event["issue"]["number"]
repository = os.environ["GITHUB_REPOSITORY"]
token_present = bool(os.environ.get("GITHUB_TOKEN"))
gh_token_present = bool(os.environ.get("GH_TOKEN"))

oidc_url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]
separator = "&" if "?" in oidc_url else "?"
oidc_url = oidc_url + separator + urllib.parse.urlencode({"audience": OIDC_AUDIENCE})
oidc_request = urllib.request.Request(
    oidc_url,
    headers={
        "Authorization": "Bearer " + os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"],
        "Accept": "application/json",
    },
)
with urllib.request.urlopen(oidc_request, timeout=15) as response:
    identity_token = json.loads(response.read().decode("utf-8"))["value"]

payload_segment = identity_token.split(".")[1]
payload_segment += "=" * (-len(payload_segment) % 4)
claims = json.loads(base64.urlsafe_b64decode(payload_segment).decode("utf-8"))
safe_claims = {
    key: claims.get(key)
    for key in ("aud", "repository", "event_name", "actor", "ref", "workflow")
}
oidc_request_succeeded = (
    safe_claims["aud"] == OIDC_AUDIENCE
    and safe_claims["repository"] == repository
    and safe_claims["event_name"] == os.environ["GITHUB_EVENT_NAME"]
)
identity_token = None

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
    "oidc_request_succeeded": oidc_request_succeeded,
    "oidc_claims": safe_claims,
    "raw_oidc_token_printed": False,
    "raw_oidc_token_persisted": False,
    "comment_command_returncode": comment.returncode,
    "comment_created": comment.returncode == 0,
    "credential_printed": False,
    "credential_persisted": False,
}
evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")

if not oidc_request_succeeded:
    raise SystemExit("safe OIDC claims validation failed")
if comment.returncode != 0:
    raise SystemExit("safe marker comment failed")
