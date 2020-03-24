#!/bin/bash -e

REPO_DIR=$(git rev-parse --show-toplevel)

mkdir "$REPO_DIR/tests/integration/targets/azuread_group/vars"
cat > tests/integration/targets/azuread_group/vars/main.yml <<EOF
client_id: ${ARM_CLIENT_ID}
client_secret: ${ARM_CLIENT_SECRET}
tenant_id: ${ARM_TENANT_ID}
EOF
