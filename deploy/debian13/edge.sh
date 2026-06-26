#!/usr/bin/env bash
# The authoritative edge-enrollment script is SERVED BY THE CONTROL PLANE at
#   <CONTROL_PLANE_URL>/install/edge.sh
# rendered with the live control-plane URL (source: control-plane/internal/httpapi/edge.sh).
#
# Operators run the one-liner shown in the Admin → Edge servers UI:
#   curl -fsSL https://cp.example.com/install/edge.sh | sudo ENROLL_TOKEN=xxxx bash
#
# This file is a pointer so the path exists in the repo. Multi-node enrollment
# is finalized in Phase 3.
echo "Fetch the live installer from <CONTROL_PLANE_URL>/install/edge.sh (see Admin → Edge servers)."
