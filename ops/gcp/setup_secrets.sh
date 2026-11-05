#!/usr/bin/env bash
#
# Create the ARTO secrets in Google Secret Manager and grant each service
# account only the ones it needs.
#
# Reads values from a local .env, which is gitignored and must never be baked
# into an image or committed. Nothing is printed: the script reports names and
# versions only, so a shared terminal or a screen recording cannot leak a key.
#
#   ./ops/gcp/setup_secrets.sh                 create or add a version
#   ./ops/gcp/setup_secrets.sh --dry-run       show what would happen
#
set -euo pipefail

PROJECT="${GCP_PROJECT:-artonexa-prod}"
ENV_FILE="${ENV_FILE:-.env}"
DRY_RUN=false
[ "${1:-}" = "--dry-run" ] && DRY_RUN=true

# Secrets only. Plain configuration is passed as ordinary environment
# variables on the service and does not belong here -- see
# ops/internal/secrets_env.md for the split and the reasoning.
SECRETS=(
  TESSERA_SECRET_KEY TESSERA_ADMIN_KEY TESSERA_DB_DSN
  VESTIGIA_API_KEY VESTIGIA_SECRET_SALT VESTIGIA_DB_DSN
  VERITYFLUX_API_KEY VERITYFLUX_JWT_SECRET VERITYFLUX_DB_DSN
  NVIDIA_API_KEY VERITYFLUX_SCORER_API_KEY VERITYFLUX_NEMOGUARD_API_KEY
  MLRT_VESTIGIA_API_KEY
)

# Which service may read which secret. Least privilege: Tessera has no reason
# to read the VerityFlux JWT secret, and a compromise of one service should
# not hand over the others.
declare -A GRANTS=(
  [tessera]="TESSERA_SECRET_KEY TESSERA_ADMIN_KEY TESSERA_DB_DSN MLRT_VESTIGIA_API_KEY"
  [vestigia]="VESTIGIA_API_KEY VESTIGIA_SECRET_SALT VESTIGIA_DB_DSN"
  [verityflux]="VERITYFLUX_API_KEY VERITYFLUX_JWT_SECRET VERITYFLUX_DB_DSN NVIDIA_API_KEY VERITYFLUX_SCORER_API_KEY VERITYFLUX_NEMOGUARD_API_KEY MLRT_VESTIGIA_API_KEY"
)

say() { printf '  %s\n' "$*"; }

[ -f "$ENV_FILE" ] || { echo "No $ENV_FILE. Copy .env.example and fill it in."; exit 1; }

# Refuse to run against a world-readable .env.
perms=$(stat -c '%a' "$ENV_FILE")
if [ "${perms:1:2}" != "00" ]; then
  echo "$ENV_FILE is mode $perms. Run: chmod 600 $ENV_FILE"
  exit 1
fi

echo "Project: $PROJECT   source: $ENV_FILE"
$DRY_RUN && echo "DRY RUN - nothing will be created"
echo

missing=()
for name in "${SECRETS[@]}"; do
  value=$(grep -E "^${name}=" "$ENV_FILE" | head -1 | cut -d= -f2- | sed 's/^"//;s/"$//' || true)
  if [ -z "$value" ]; then missing+=("$name"); say "SKIP   $name (not set in $ENV_FILE)"; continue; fi

  if $DRY_RUN; then say "would set $name (${#value} chars)"; continue; fi

  if ! gcloud secrets describe "$name" --project "$PROJECT" >/dev/null 2>&1; then
    gcloud secrets create "$name" --replication-policy=automatic --project "$PROJECT" >/dev/null
    say "created $name"
  fi
  # printf, not echo, so no trailing newline is stored in the secret value
  printf '%s' "$value" | gcloud secrets versions add "$name" --data-file=- --project "$PROJECT" >/dev/null
  ver=$(gcloud secrets versions list "$name" --project "$PROJECT" --limit=1 --format='value(name)')
  say "set     $name -> version $ver"
done

echo
if $DRY_RUN; then echo "Dry run complete."; exit 0; fi

echo "Granting access, one service account per service:"
for svc in "${!GRANTS[@]}"; do
  sa="arto-${svc}@${PROJECT}.iam.gserviceaccount.com"
  if ! gcloud iam service-accounts describe "$sa" --project "$PROJECT" >/dev/null 2>&1; then
    say "SKIP   $sa does not exist yet"
    continue
  fi
  for name in ${GRANTS[$svc]}; do
    gcloud secrets add-iam-policy-binding "$name" \
      --member="serviceAccount:${sa}" \
      --role=roles/secretmanager.secretAccessor \
      --project "$PROJECT" >/dev/null 2>&1 || true
  done
  say "granted $svc ($(echo ${GRANTS[$svc]} | wc -w) secrets)"
done

echo
if [ ${#missing[@]} -gt 0 ]; then
  echo "Not set in $ENV_FILE, so not created:"
  printf '  - %s\n' "${missing[@]}"
  echo
fi
cat <<'NOTE'
Reminders:
  - VESTIGIA_SECRET_SALT is effectively permanent. Changing it invalidates
    every existing integrity hash and the ledger stops verifying.
  - The root signing key and the attestation key are key material, not
    configuration. They are not handled here; load them from Secret Manager
    as mounted files, never from a path inside the image.
  - Every value is read once at startup, so rotating any of these needs a
    new revision, not a reload.
NOTE
