#!/bin/vbash
# firewall.sh - Combined VyOS inbound/outbound firewall control
# Compatible with VyOS 1.4+ / rolling (2026)
#
# Usage:
#   firewall.sh --iface IFACE [--inbound MODE] [--csv FILE] [--outbound MODE]
#
# --iface    Interface to apply rules to (required)
#
# --inbound  off          Remove inbound rules for this interface
#            whitelist    Allow only IP:port pairs from --csv, drop rest
#
# --outbound off          Remove outbound rules for this interface
#            allow        Allow TCP/80,443 + UDP/53, drop rest
#            block        Drop all outbound (no exceptions)
#
# --csv      Path to CSV file (required when --inbound whitelist)
#
# At least one of --inbound or --outbound must be provided.
#
# NOTE: Rules are added to firewall ipv4 forward filter.
#       Inbound rules match traffic arriving on --iface.
#       Outbound rules match traffic leaving on --iface.
#       Rule number ranges:
#         1        - established/related (shared)
#         100-499  - inbound whitelist rules
#         500      - inbound default drop
#         600-899  - outbound allow rules
#         900      - outbound default drop

source /opt/vyatta/etc/functions/script-template

# Defaults
IFACE=""
INBOUND_MODE=""
OUTBOUND_MODE=""
CSV_FILE=""

# Rule number ranges
IN_BASE=100
IN_DROP=500
OUT_BASE=600
OUT_DROP=900

# Arg parsing
while [[ $# -gt 0 ]]; do
  case "$1" in
    --iface)     IFACE="$2";         shift 2 ;;
    --inbound)   INBOUND_MODE="$2";  shift 2 ;;
    --outbound)  OUTBOUND_MODE="$2"; shift 2 ;;
    --csv)       CSV_FILE="$2";      shift 2 ;;
    *)           echo "ERROR: Unknown arg '$1'" >&2; exit 1 ;;
  esac
done

# Validation
if [[ -z "$IFACE" ]]; then
  echo "ERROR: --iface is required" >&2; exit 1
fi
if [[ -z "$INBOUND_MODE" && -z "$OUTBOUND_MODE" ]]; then
  echo "ERROR: provide at least --inbound or --outbound" >&2; exit 1
fi
if [[ "$INBOUND_MODE" == "whitelist" && -z "$CSV_FILE" ]]; then
  echo "ERROR: --inbound whitelist requires --csv FILE" >&2; exit 1
fi
if [[ -n "$CSV_FILE" && ! -f "$CSV_FILE" ]]; then
  echo "ERROR: CSV file '$CSV_FILE' not found" >&2; exit 1
fi
if [[ -n "$INBOUND_MODE" ]] && \
   [[ "$INBOUND_MODE" != "off" && "$INBOUND_MODE" != "whitelist" ]]; then
  echo "ERROR: --inbound must be 'off' or 'whitelist'" >&2; exit 1
fi
if [[ -n "$OUTBOUND_MODE" ]] && \
   [[ "$OUTBOUND_MODE" != "off" && "$OUTBOUND_MODE" != "allow" && "$OUTBOUND_MODE" != "block" ]]; then
  echo "ERROR: --outbound must be 'off', 'allow', or 'block'" >&2; exit 1
fi

# ==============================================================
# HELPERS
# ==============================================================

# Ensure rule 1 exists for established/related (shared, safe to re-set)
ensure_established() {
  set firewall ipv4 forward filter rule 1 action accept
  set firewall ipv4 forward filter rule 1 description 'Allow established/related'
  set firewall ipv4 forward filter rule 1 state established
  set firewall ipv4 forward filter rule 1 state related
}

# Delete all rules in a number range on a given interface direction
# Usage: delete_rules_in_range START END inbound-interface|outbound-interface IFACE
delete_rules_in_range() {
  local START=$1
  local END=$2
  local DIR=$3
  local IF=$4
  local N=$START
  while [[ $N -le $END ]]; do
    delete firewall ipv4 forward filter rule $N 2>/dev/null
    N=$(( N + 10 ))
  done
}

# ==============================================================
# FUNCTIONS
# ==============================================================

fn_inbound_off() {
  echo "[inbound] Removing inbound rules for $IFACE..."
  delete_rules_in_range $IN_BASE $IN_DROP inbound-interface $IFACE
}

fn_inbound_whitelist() {
  echo "[inbound] Applying whitelist from $CSV_FILE on $IFACE..."

  # Clear existing inbound rules for this interface
  delete_rules_in_range $IN_BASE $IN_DROP inbound-interface $IFACE

  ensure_established

  RULE_NUM=$IN_BASE
  while IFS=, read -r IP PORT || [[ -n "$IP" ]]; do
    [[ -z "$IP" || "$IP" == \#* ]] && continue
    IP=$(echo "$IP" | tr -d ' \r')
    PORT=$(echo "$PORT" | tr -d ' \r')
    if [[ -z "$PORT" ]]; then
      echo "  WARN: skipping line with no port - '$IP'"; continue
    fi
    echo "  + Rule $RULE_NUM: $IP -> port $PORT"
    set firewall ipv4 forward filter rule $RULE_NUM action accept
    set firewall ipv4 forward filter rule $RULE_NUM description "Whitelist $IP:$PORT"
    set firewall ipv4 forward filter rule $RULE_NUM inbound-interface name $IFACE
    set firewall ipv4 forward filter rule $RULE_NUM source address $IP
    set firewall ipv4 forward filter rule $RULE_NUM destination port $PORT
    set firewall ipv4 forward filter rule $RULE_NUM protocol tcp_udp
    RULE_NUM=$(( RULE_NUM + 10 ))
  done < "$CSV_FILE"

  # Default drop for unmatched inbound on this interface
  echo "  + Rule $IN_DROP: default drop inbound $IFACE"
  set firewall ipv4 forward filter rule $IN_DROP action drop
  set firewall ipv4 forward filter rule $IN_DROP description "Default drop inbound $IFACE"
  set firewall ipv4 forward filter rule $IN_DROP inbound-interface name $IFACE
}

fn_outbound_off() {
  echo "[outbound] Removing outbound rules for $IFACE..."
  delete_rules_in_range $OUT_BASE $OUT_DROP outbound-interface $IFACE
}

fn_outbound_allow() {
  echo "[outbound] Allowing TCP/80,443 + UDP/53 on $IFACE, dropping rest..."

  delete_rules_in_range $OUT_BASE $OUT_DROP outbound-interface $IFACE

  ensure_established

  # Allow HTTP
  set firewall ipv4 forward filter rule $OUT_BASE action accept
  set firewall ipv4 forward filter rule $OUT_BASE description 'Allow HTTP'
  set firewall ipv4 forward filter rule $OUT_BASE outbound-interface name $IFACE
  set firewall ipv4 forward filter rule $OUT_BASE protocol tcp
  set firewall ipv4 forward filter rule $OUT_BASE destination port 80

  # Allow HTTPS
  set firewall ipv4 forward filter rule $(( OUT_BASE + 10 )) action accept
  set firewall ipv4 forward filter rule $(( OUT_BASE + 10 )) description 'Allow HTTPS'
  set firewall ipv4 forward filter rule $(( OUT_BASE + 10 )) outbound-interface name $IFACE
  set firewall ipv4 forward filter rule $(( OUT_BASE + 10 )) protocol tcp
  set firewall ipv4 forward filter rule $(( OUT_BASE + 10 )) destination port 443

  # Allow DNS
  set firewall ipv4 forward filter rule $(( OUT_BASE + 20 )) action accept
  set firewall ipv4 forward filter rule $(( OUT_BASE + 20 )) description 'Allow DNS'
  set firewall ipv4 forward filter rule $(( OUT_BASE + 20 )) outbound-interface name $IFACE
  set firewall ipv4 forward filter rule $(( OUT_BASE + 20 )) protocol udp
  set firewall ipv4 forward filter rule $(( OUT_BASE + 20 )) destination port 53

  # Default drop
  echo "  + Rule $OUT_DROP: default drop outbound $IFACE"
  set firewall ipv4 forward filter rule $OUT_DROP action drop
  set firewall ipv4 forward filter rule $OUT_DROP description "Default drop outbound $IFACE"
  set firewall ipv4 forward filter rule $OUT_DROP outbound-interface name $IFACE
}

fn_outbound_block() {
  echo "[outbound] Blocking ALL outbound on $IFACE..."

  delete_rules_in_range $OUT_BASE $OUT_DROP outbound-interface $IFACE

  set firewall ipv4 forward filter rule $OUT_DROP action drop
  set firewall ipv4 forward filter rule $OUT_DROP description "Block all outbound $IFACE"
  set firewall ipv4 forward filter rule $OUT_DROP outbound-interface name $IFACE
}

# ==============================================================
# MAIN
# ==============================================================

configure

case "$INBOUND_MODE" in
  off)       fn_inbound_off ;;
  whitelist) fn_inbound_whitelist ;;
esac

case "$OUTBOUND_MODE" in
  off)   fn_outbound_off ;;
  allow) fn_outbound_allow ;;
  block) fn_outbound_block ;;
esac

commit || { echo "ERROR: commit failed - rolling back" >&2; discard; exit 1; }
save
echo "Done."

exit
