#!/bin/sh
set -u

SCC_PROFILE_NAME="${SCC_PROFILE_NAME:-default}"

if [ -n "${SCC_SERVER_URL:-}" ] && { [ -n "${SCC_USERNAME:-}" ] || [ -n "${SCC_CSP_API_TOKEN:-}" ]; }; then
    echo "entrypoint: connecting to RaaS as profile '$SCC_PROFILE_NAME'..."

    connected=0
    if [ -n "${SCC_CSP_API_TOKEN:-}" ]; then
        scc connect --name "$SCC_PROFILE_NAME" --server "$SCC_SERVER_URL" --csp-token "$SCC_CSP_API_TOKEN" \
            && connected=1 || echo "entrypoint: scc connect failed, continuing anyway." >&2
    elif [ -n "${SCC_PASSWORD:-}" ]; then
        echo "$SCC_PASSWORD" | scc connect --name "$SCC_PROFILE_NAME" --server "$SCC_SERVER_URL" \
            --username "$SCC_USERNAME" --password-stdin \
            && connected=1 || echo "entrypoint: scc connect failed, continuing anyway." >&2
    else
        echo "entrypoint: SCC_PASSWORD or SCC_CSP_API_TOKEN must be set to connect; skipping RaaS setup." >&2
    fi

    if [ "$connected" = "1" ]; then
        scc profile use "$SCC_PROFILE_NAME"
        scc profile test "$SCC_PROFILE_NAME" --no-prompt || echo "entrypoint: profile test failed, continuing anyway." >&2
    fi

    if [ -n "${CUSTOMER_VALUES_REPO_URL:-}" ]; then
        echo "entrypoint: registering customer-values data repo..."
        scc repo add customer-values \
            --kind data \
            --url "$CUSTOMER_VALUES_REPO_URL" \
            --ref main \
            --root . \
            --layout '{environment}/{version}/{resource}/values.yaml' \
            --auth token \
            --default || echo "entrypoint: repo add failed (may already exist), continuing anyway." >&2
    else
        echo "entrypoint: CUSTOMER_VALUES_REPO_URL not set; skipping customer-values repo registration." >&2
    fi
else
    echo "entrypoint: SCC_SERVER_URL and SCC_USERNAME/SCC_CSP_API_TOKEN not set; skipping RaaS connect/repo setup." >&2
fi

exec "$@"
