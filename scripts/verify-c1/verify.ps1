$ErrorActionPreference = 'Stop'
$root = (Resolve-Path "$PSScriptRoot\..\..").Path
$image = docker image inspect cafi-transport:s2-03 --format '{{.Id}}'
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
docker run --rm --platform linux/amd64 --network none --read-only --cap-drop ALL `
  --security-opt no-new-privileges --user 65534:65534 `
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=2m,mode=0700,uid=65534,gid=65534 `
  --mount "type=bind,source=$root,target=/repo,readonly" -w /repo `
  -e PYTHONPATH=/repo -e PYTHONDONTWRITEBYTECODE=1 $image `
  python -m unittest discover -s tests/c1 -p test_boundary.py -v
exit $LASTEXITCODE
