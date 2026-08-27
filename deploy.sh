#!/usr/bin/env bash
# McLean Plaid Proxy — one-time Fly.io deploy script
#
# Prerequisites:
#   1. flyctl installed (you likely already have it — check with `flyctl version`)
#      If not: `brew install flyctl` or `curl -L https://fly.io/install.sh | sh`
#   2. Signed in: `flyctl auth login` (opens your browser once)
#
# Usage:
#   cd fly-plaid-proxy
#   chmod +x deploy.sh
#   ./deploy.sh
#
# What this does:
#   - Creates a Fly app named "mclean-plaid-proxy" (or the name you pick if that's taken)
#   - Sets your Plaid credentials + a random HMAC secret as Fly secrets (encrypted, never in git)
#   - Deploys the proxy
#   - Prints the URL and the HMAC secret you'll paste back to me
#
set -euo pipefail

APP_NAME="${APP_NAME:-mclean-plaid-proxy}"
REGION="${REGION:-iad}"
PLAID_ENV_VALUE="${PLAID_ENV_VALUE:-production}"
PLAID_CLIENT_ID_VALUE="6a822a71109ebc000dee4ad7"
ALLOWED_ORIGIN_VALUE="https://mclean-solutions-calculators-diagnostic.pplx.app"

echo ""
echo "================================================================"
echo "  McLean Plaid Proxy — Fly.io deploy"
echo "================================================================"
echo ""

# 1. Check flyctl is installed and authed
if ! command -v flyctl >/dev/null 2>&1; then
  echo "❌ flyctl not found. Install it:"
  echo "   brew install flyctl    (or)    curl -L https://fly.io/install.sh | sh"
  exit 1
fi

if ! flyctl auth whoami >/dev/null 2>&1; then
  echo "You're not signed in to Fly. Running 'flyctl auth login' — this opens your browser."
  flyctl auth login
fi

FLY_USER=$(flyctl auth whoami)
echo "✓ Signed in to Fly as: $FLY_USER"
echo ""

# 2. Prompt for the Plaid Production secret (not stored anywhere on disk)
echo "Paste your Plaid Production secret and press Enter."
echo "(Get it from https://dashboard.plaid.com → Team Settings → Keys → Production)"
read -r -s -p "Plaid Production Secret: " PLAID_SECRET_VALUE
echo ""
if [[ -z "$PLAID_SECRET_VALUE" ]]; then
  echo "❌ Empty secret. Aborting."
  exit 1
fi
echo "✓ Secret captured (not echoed, not saved to disk)"
echo ""

# 3. Generate a strong HMAC shared secret (used to authenticate calls from your app to the proxy)
HMAC_SECRET_VALUE=$(openssl rand -hex 32)
echo "✓ Generated a 256-bit HMAC shared secret"
echo ""

# 4. Create the Fly app if it doesn't exist
if flyctl status --app "$APP_NAME" >/dev/null 2>&1; then
  echo "✓ Fly app '$APP_NAME' already exists — will redeploy"
else
  echo "→ Creating Fly app '$APP_NAME' in region '$REGION'..."
  flyctl apps create "$APP_NAME" --org personal || {
    echo ""
    echo "  Name may be taken. Try again with a different name:"
    echo "    APP_NAME=mclean-plaid-proxy-2 ./deploy.sh"
    exit 1
  }
fi

# 5. Set secrets (encrypted at rest on Fly, only decrypted inside the running VM)
echo ""
echo "→ Setting secrets on Fly..."
flyctl secrets set --app "$APP_NAME" --stage \
  PLAID_ENV="$PLAID_ENV_VALUE" \
  PLAID_CLIENT_ID="$PLAID_CLIENT_ID_VALUE" \
  PLAID_SECRET="$PLAID_SECRET_VALUE" \
  HMAC_SHARED_SECRET="$HMAC_SECRET_VALUE" \
  ALLOWED_ORIGIN="$ALLOWED_ORIGIN_VALUE"

# 6. Deploy
echo ""
echo "→ Deploying..."
flyctl deploy --app "$APP_NAME" --ha=false

# 7. Print the info you need to send back
APP_URL="https://${APP_NAME}.fly.dev"
echo ""
echo "================================================================"
echo "  ✅ Deploy complete"
echo "================================================================"
echo ""
echo "Proxy URL:       $APP_URL"
echo "HMAC secret:     $HMAC_SECRET_VALUE"
echo ""
echo "Verify health:"
echo "  curl $APP_URL/healthz"
echo ""
echo "COPY BOTH VALUES ABOVE and paste them back to me in Perplexity."
echo "I'll wire them into the mclean-calculators app and finish the integration."
echo ""
