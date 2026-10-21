#!/bin/sh
# Keep private seeds and provider credentials in the process environment.
set -eu

# Match the artifacts installed by docker/Dockerfile (which sets this to the
# development setup in an ALLOW_DEV_SETUP=1 image); allow an explicit override.
ZKAPI_PROOF_SETUP_DIR=${ZKAPI_PROOF_SETUP_DIR:-/srv/zkapi/protocol/setup/v2-concession}
# The deployment manifest (trusted_deployment profile) compose.yml mounts.
ZKAPI_DEPLOYMENT_MANIFEST=${ZKAPI_DEPLOYMENT_MANIFEST:-/srv/zkapi/deployment.json}

require() {
    for name in "$@"; do
        if ! value=$(printenv "$name") || [ -z "$value" ]; then
            echo "Missing required environment variable: $name" >&2
            exit 1
        fi
    done
}

# A launcher setting that must be a decimal number of seconds; an unset or
# empty value means the default.
seconds() {
    value=$(printenv "$1" || true)
    value=${value:-$2}
    case "$value" in
        '' | *[!0-9]* | 0?* | ??????????*)
            echo "$1 must be a decimal number of seconds" >&2
            exit 1
            ;;
    esac
    printf '%s\n' "$value"
}

require CHAIN_ID VAULT_ADDRESS DEPLOY_BLOCK CIRCUIT_ID
if [ "$CIRCUIT_ID" != zkapi-v2-concession-v1 ]; then
    echo "This image requires the zkapi-v2-concession-v1 circuit and a fresh vault" >&2
    exit 1
fi

case "${1:-}" in
    server)
        require ZKAPI_STATE_SEED ZKAPI_CLEAR_SEED REQUEST_CHARGE_CAP ZKAPI_NATIVE_BILLING_RPC_URL ZKAPI_NATIVE_PRICE_FEED_ADDRESS
        # zkapi serverd reads the seeds from this environment and validates them
        # itself: it refuses development keys in any spelling (by derived public
        # key), weak or reused seeds, and keys that differ from the vault's,
        # before it opens /data/server.db. A string match here would be bypassable.
        # ZKAPI_CLEARANCE_ROOT_WINDOW_SECONDS, ZKAPI_ROOT_MAX_STALENESS_SECONDS,
        # ZKAPI_REQUEST_LIMIT_MAX_USD_MICROS and ZKAPI_ALLOW_LEGACY_CLEARANCE (which
        # serverd refuses on this circuit) also reach serverd from the environment.
        set -- zkapi --protocol-version 2 --chain-id "$CHAIN_ID" \
            --contract-address "$VAULT_ADDRESS" \
            --request-charge-cap "$REQUEST_CHARGE_CAP" \
            --proof-setup-dir "$ZKAPI_PROOF_SETUP_DIR" \
            serverd --listen 0.0.0.0:3000 \
            --indexer-url http://indexer:3001 \
            --native-billing-rpc-url "$ZKAPI_NATIVE_BILLING_RPC_URL" \
            --native-price-feed-address "$ZKAPI_NATIVE_PRICE_FEED_ADDRESS" \
            --native-price-feed-decimals "${ZKAPI_NATIVE_PRICE_FEED_DECIMALS:-8}" \
            --native-price-max-age-seconds "${ZKAPI_NATIVE_PRICE_MAX_AGE_SECONDS:-4500}" \
            --openrouter-lease-ttl-seconds "${LEASE_TTL_SECONDS:-300}" \
            --openrouter-settlement-grace-seconds "${SETTLEMENT_GRACE_SECONDS:-5}" \
            --openrouter-settlement-deadline-seconds "${ZKAPI_OPENROUTER_SETTLEMENT_DEADLINE_SECONDS:-21600}" \
            --deployment "$ZKAPI_DEPLOYMENT_MANIFEST" \
            --db-path /data/server.db
        if [ -n "${OA_ORG_URL:-}" ]; then
            set -- "$@" --oa-org-url "$OA_ORG_URL"
        fi
        exec "$@"
        ;;
    db-init)
        # Run once before the challenger and the server: creates (or migrates)
        # /data/server.db with its append-only request evidence and binds it to
        # the deployment manifest and the loaded verifying keys. Idempotent for
        # the same deployment; refuses a database bound to anything else.
        exec zkapi --proof-setup-dir "$ZKAPI_PROOF_SETUP_DIR" \
            db init --deployment "$ZKAPI_DEPLOYMENT_MANIFEST" --db /data/server.db
        ;;
    indexer)
        require RPC_URL
        # The checkpoint commits at --confirmations; the served tree tracks the
        # verified head. Touch /data/indexer.cursor.resync and restart to rebuild.
        exec zkapi-indexerd --listen 0.0.0.0:3001 --rpc-url "$RPC_URL" \
            --contract-address "$VAULT_ADDRESS" --from-block "$DEPLOY_BLOCK" \
            --chain-id "$CHAIN_ID" --confirmations "${INDEXER_CONFIRMATIONS:-12}" \
            --max-head-age-secs "${INDEXER_MAX_HEAD_AGE_SECS:-180}" \
            --cursor-path /data/indexer.cursor
        ;;
    challenger)
        require ZKAPI_CHALLENGE_RPC_URL ZKAPI_CHALLENGE_SENDER \
            ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI ZKAPI_CHALLENGE_MAX_PRIORITY_FEE_PER_GAS_WEI
        # The API server's settlement window (lease TTL + grace + settlement
        # deadline, from the deployment.env the server reads) for the
        # challenger's startup timing checks; it may not exceed the manifest's
        # settlement_window_seconds.
        ttl=$(seconds LEASE_TTL_SECONDS 300)
        grace=$(seconds SETTLEMENT_GRACE_SECONDS 5)
        deadline=$(seconds ZKAPI_OPENROUTER_SETTLEMENT_DEADLINE_SECONDS 21600)
        # The RPC, sender, fee, raise-lead, raise-minimum and retire-on-miss
        # settings reach zkapi-challenged from the environment. Its status
        # listener stays on the container's loopback, for the healthcheck and
        # `docker compose exec`; never publish it.
        exec zkapi-challenged --indexer-url http://indexer:3001 \
            --deployment "$ZKAPI_DEPLOYMENT_MANIFEST" \
            --settlement-window-seconds "$((ttl + grace + deadline))" \
            --chain-id "$CHAIN_ID" --contract-address "$VAULT_ADDRESS" \
            --from-block "$DEPLOY_BLOCK" --confirmations "${CHALLENGE_CONFIRMATIONS:-2}" \
            --db-path /data/server.db --checkpoint /data/challenges.json \
            --proof-setup-dir "$ZKAPI_PROOF_SETUP_DIR" \
            --status-listen 127.0.0.1:3002
        ;;
    *)
        echo "Usage: zkapi-run server|db-init|indexer|challenger" >&2
        exit 2
        ;;
esac
