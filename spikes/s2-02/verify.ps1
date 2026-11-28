$ErrorActionPreference = 'Stop'
$root = (Resolve-Path "$PSScriptRoot\..\..").Path
$revision = git -C $root rev-parse HEAD
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$image = docker image inspect cafi-soap:s1 --format '{{.Id}}'
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
docker run --rm --platform linux/amd64 --network none --read-only --cap-drop ALL `
  --security-opt no-new-privileges --user 65534:65534 `
  --mount "type=bind,source=$root,target=/repo,readonly" `
  -e "CAFI_CODE_REVISION=$revision" -e "CAFI_IMAGE_ID=$image" `
  $image python /repo/spikes/s2-02/proof.py
exit $LASTEXITCODE
