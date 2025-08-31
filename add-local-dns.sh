#!/bin/bash

# Usage: ./add-local-dns.sh fqdn ip

set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <fqdn> <ip>"
  exit 1
fi

FQDN="$1"
IP="$2"

# === Configuration ===

# Load .env if present (from script directory)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/.env" ]; then
  # shellcheck disable=SC1090
  set -a
  . "$SCRIPT_DIR/.env"
  set +a
fi

# Defaults (can be overridden via .env)
USE_HTTPS=${USE_HTTPS:-false}         # Set to true if using HTTPS
INSECURE=${INSECURE:--k}              # Use "" to validate certs

# PIHOLES may be provided as CSV in env (e.g., PIHOLES="10.10.0.2,10.10.0.3")
# Fallback to legacy hardcoded values if not provided
if [ -n "${PIHOLES:-}" ]; then
  IFS=',' read -r -a PIHOLES_ARRAY <<< "$PIHOLES"
else
  PIHOLES_ARRAY=("10.10.0.2" "10.10.0.3")
fi

# PASSWORDS may be provided as CSV in env aligned with PIHOLES; avoided if using Keychain
if [ -n "${PASSWORDS:-}" ]; then
  IFS=',' read -r -a PASSWORDS_ARRAY <<< "$PASSWORDS"
else
  PASSWORDS_ARRAY=()
fi

# Optional: macOS Keychain service name to fetch passwords by host as account
# Create items with: security add-generic-password -s "$KEYCHAIN_SERVICE" -a "<host>" -w
KEYCHAIN_SERVICE=${KEYCHAIN_SERVICE:-}

sanitize_host_for_env() {
  echo "$1" | tr -c '[:alnum:]' '_'
}

get_password_for_host() {
  local host=$1
  local idx=$2

  local env_key
  env_key="PIHOLE_PASSWORD_$(sanitize_host_for_env "$host")"
  # Indirect expansion to read $PIHOLE_PASSWORD_<HOST>
  local pw_from_env=${!env_key-}
  if [ -n "$pw_from_env" ]; then
    printf '%s' "$pw_from_env"
    return 0
  fi

  if [ -n "$KEYCHAIN_SERVICE" ] && command -v security >/dev/null 2>&1; then
    local pw
    if pw=$(security find-generic-password -s "$KEYCHAIN_SERVICE" -a "$host" -w 2>/dev/null); then
      if [ -n "$pw" ]; then
        printf '%s' "$pw"
        return 0
      fi
    fi
  fi

  if [ ${#PASSWORDS_ARRAY[@]} -gt "$idx" ]; then
    printf '%s' "${PASSWORDS_ARRAY[$idx]}"
    return 0
  fi

  return 1
}

# === Validation ===

# Validate IP address format
validate_ip() {
  local ip=$1
  if [[ ! $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    echo "❌ Invalid IP address format: $ip"
    exit 1
  fi
  
  IFS='.' read -ra ADDR <<< "$ip"
  for i in "${ADDR[@]}"; do
    if [[ $i -lt 0 || $i -gt 255 ]]; then
      echo "❌ Invalid IP address: $ip"
      exit 1
    fi
  done
}

# Validate FQDN format
validate_fqdn() {
  local fqdn=$1
  if [[ ! $fqdn =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
    echo "❌ Invalid FQDN format: $fqdn"
    exit 1
  fi
}

# Run validations
validate_ip "$IP"
validate_fqdn "$FQDN"

# === Script ===

add_record() {
  local HOST=$1
  local PASSWORD=$2
  local PROTO="http"
  [ "$USE_HTTPS" = true ] && PROTO="https"

  echo "🔐 Logging into $HOST..."

  # Try authentication with /api/auth endpoint
  echo "🔍 Authenticating with /api/auth..."
  
  AUTH_RESPONSE=$(curl -s --max-time 30 $INSECURE -X POST "$PROTO://$HOST/api/auth" \
    -H 'accept: application/json' \
    -H 'content-type: application/json' \
    -d "{\"password\":\"$PASSWORD\"}")
  
  echo "📡 Raw auth response: $AUTH_RESPONSE"
  
  # Check if authentication was successful
  SESSION_VALID=$(echo "$AUTH_RESPONSE" | jq -r '.session.valid // false')
  SID=$(echo "$AUTH_RESPONSE" | jq -r '.session.sid // empty')
  
  if [[ "$SESSION_VALID" == "true" && -n "$SID" ]]; then
    echo "✅ Authentication successful for $HOST"
    echo "🔑 Session ID: $SID"
  else
    echo "❌ Authentication failed for $HOST"
    echo "❌ Session valid: $SESSION_VALID"
    echo "❌ Session ID: $SID"
    return 1
  fi

  # Get current DNS configuration
  echo "🔍 Getting current DNS configuration from $HOST..."
  
  DNS_CONFIG_RESPONSE=$(curl -s --max-time 30 $INSECURE -X GET "$PROTO://$HOST/api/config/dns" \
    -H "sid: $SID" \
    -H "accept: application/json")
  
  echo "📡 DNS config response received"
  
  # Check if the record already exists
  EXISTING_RECORD=$(echo "$DNS_CONFIG_RESPONSE" | jq -r --arg domain "$FQDN" '.config.dns.hosts[] | select(test(".* " + $domain + "$")) // empty')
  
  if [[ -n "$EXISTING_RECORD" ]]; then
    echo "⚠️  Record already exists on $HOST: $EXISTING_RECORD"
    EXISTING_IP=$(echo "$EXISTING_RECORD" | cut -d' ' -f1)
    if [[ "$EXISTING_IP" == "$IP" ]]; then
      echo "✅ IP address matches, no update needed"
      return 0
    else
      echo "🔄 Removing old record before update..."
      ENCODED_OLD_RECORD=$(printf "%s" "$EXISTING_RECORD" | jq -sRr @uri)
      REMOVE_RESPONSE=$(curl -s --max-time 30 -v $INSECURE -X DELETE "$PROTO://$HOST/api/config/dns/hosts/$ENCODED_OLD_RECORD" \
        -H "sid: $SID" \
        -H "accept: application/json" 2>&1)
      echo "📡 Remove response: $REMOVE_RESPONSE"
    fi
  fi

  echo "📦 Creating DNS entry: $FQDN → $IP on $HOST"

  # Path-based API requires URL-encoded "IP FQDN"
  NEW_RECORD="$IP $FQDN"
  ENCODED_NEW_RECORD=$(printf "%s" "$NEW_RECORD" | jq -sRr @uri)
  echo "📡 Adding record (encoded): $ENCODED_NEW_RECORD"
  
  RESPONSE=$(curl -s --max-time 30 -v $INSECURE -X PUT "$PROTO://$HOST/api/config/dns/hosts/$ENCODED_NEW_RECORD" \
    -H "sid: $SID" \
    -H "accept: application/json" 2>&1)

  echo "📡 Raw response: $RESPONSE"

  if echo "$RESPONSE" | grep -q "HTTP/.* 2[0-9][0-9]"; then
    echo "✅ Successfully created/updated DNS record on $HOST"
    return 0
  else
    echo "❌ Failed to create/update DNS record on $HOST"
    echo "Response: $RESPONSE"
    return 1
  fi
}

# Track overall success
SUCCESS_COUNT=0
TOTAL_COUNT=${#PIHOLES_ARRAY[@]}

if [ "$TOTAL_COUNT" -eq 0 ]; then
  echo "❌ No Pi-hole hosts configured. Define PIHOLES in .env (CSV) or set PIHOLES_ARRAY."
  exit 1
fi

for i in "${!PIHOLES_ARRAY[@]}"; do
  HOST="${PIHOLES_ARRAY[$i]}"
  
  echo ""
  echo "🌐 Processing Pi-hole: $HOST"
  echo "=================================="

  if ! PASSWORD=$(get_password_for_host "$HOST" "$i"); then
    echo "❌ No password found for $HOST. Provide PIHOLE_PASSWORD_$(sanitize_host_for_env "$HOST"), or use KEYCHAIN_SERVICE, or align PASSWORDS CSV."
    continue
  fi
  
  if add_record "$HOST" "$PASSWORD"; then
    ((SUCCESS_COUNT++))
  fi
done

echo ""
echo "📊 Summary: $SUCCESS_COUNT/$TOTAL_COUNT Pi-hole servers updated successfully"

if [ $SUCCESS_COUNT -eq $TOTAL_COUNT ]; then
  echo "🎉 All Pi-hole servers updated successfully!"
  exit 0
else
  echo "⚠️  Some Pi-hole servers failed to update"
  exit 1
fi