#!/bin/vbash
# firewall.sh - Combined VyOS inbound/outbound firewall control
#
# Usage:
#   firewall.sh --iface IFACE [--inbound MODE] [--csv FILE] [--outbound MODE]
#
# --iface    Interface to apply rules to (required)
#
# --inbound  off          Remove inbound ruleset and binding
#            whitelist    Apply IP:port whitelist from --csv
#
# --outbound off          Remove outbound ruleset and binding
#            allow        Allow TCP/80,443 + UDP/53, drop rest
#            block        Drop all outbound (no exceptions)
#
# --csv      Path to CSV file (required when --inbound whitelist)
#
# At least one of --inbound or --outbound must be provided.

source /opt/vyatta/etc/functions/script-template

# Defaults
IFACE=""
INBOUND_MODE=""
OUTBOUND_MODE=""
CSV_FILE=""
IN_RULESET="INBOUND-WHITELIST"
OUT_RULESET="OUTBOUND-LOCKDOWN"

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
# FUNCTIONS
# ==============================================================

fn_inbound_off() {
  echo "[inbound] Removing ruleset and binding..."
  delete interfaces ethernet $IFACE firewall in
  delete firewall name $IN_RULESET
}

fn_inbound_whitelist() {
  echo "[inbound] Applying whitelist from $CSV_FILE..."
  delete firewall name $IN_RULESET

  set firewall name $IN_RULESET default-action drop
  set firewall name $IN_RULESET description 'Inbound IP:port whitelist'

  set firewall name $IN_RULESET rule 1 action accept
  set firewall name $IN_RULESET rule 1 description 'Allow established/related'
  set firewall name $IN_RULESET rule 1 state established enable
  set firewall name $IN_RULESET rule 1 state related enable

  RULE_NUM=10
  while IFS=, read -r IP PORT || [[ -n "$IP" ]]; do
    [[ -z "$IP" || "$IP" == \#* ]] && continue
    IP=$(echo "$IP" | tr -d ' \r')
    PORT=$(echo "$PORT" | tr -d ' \r')
    if [[ -z "$PORT" ]]; then
      echo "  WARN: skipping line with no port - '$IP'"; continue
    fi
    echo "  + Rule $RULE_NUM: $IP -> port $PORT"
    set firewall name $IN_RULESET rule $RULE_NUM action accept
    set firewall name $IN_RULESET rule $RULE_NUM description "Whitelist $IP:$PORT"
    set firewall name $IN_RULESET rule $RULE_NUM source address $IP
    set firewall name $IN_RULESET rule $RULE_NUM destination port $PORT
    set firewall name $IN_RULESET rule $RULE_NUM protocol tcp_udp
    RULE_NUM=$(( RULE_NUM + 10 ))
  done < "$CSV_FILE"

  set interfaces ethernet $IFACE firewall in name $IN_RULESET
}

fn_outbound_off() {
  echo "[outbound] Removing ruleset and binding..."
  delete interfaces ethernet $IFACE firewall out
  delete firewall name $OUT_RULESET
}

fn_outbound_allow() {
  echo "[outbound] Allowing TCP/80,443 + UDP/53, dropping rest..."
  delete firewall name $OUT_RULESET

  set firewall name $OUT_RULESET default-action drop
  set firewall name $OUT_RULESET description 'Outbound: allow HTTP/HTTPS/DNS only'

  set firewall name $OUT_RULESET rule 1 action accept
  set firewall name $OUT_RULESET rule 1 description 'Allow established/related'
  set firewall name $OUT_RULESET rule 1 state established enable
  set firewall name $OUT_RULESET rule 1 state related enable

  set firewall name $OUT_RULESET rule 10 action accept
  set firewall name $OUT_RULESET rule 10 description 'Allow HTTP'
  set firewall name $OUT_RULESET rule 10 protocol tcp
  set firewall name $OUT_RULESET rule 10 destination port 80

  set firewall name $OUT_RULESET rule 20 action accept
  set firewall name $OUT_RULESET rule 20 description 'Allow HTTPS'
  set firewall name $OUT_RULESET rule 20 protocol tcp
  set firewall name $OUT_RULESET rule 20 destination port 443

  set firewall name $OUT_RULESET rule 30 action accept
  set firewall name $OUT_RULESET rule 30 description 'Allow DNS'
  set firewall name $OUT_RULESET rule 30 protocol udp
  set firewall name $OUT_RULESET rule 30 destination port 53

  set interfaces ethernet $IFACE firewall out name $OUT_RULESET
}

fn_outbound_block() {
  echo "[outbound] Blocking ALL outbound traffic..."
  delete firewall name $OUT_RULESET

  set firewall name $OUT_RULESET default-action drop
  set firewall name $OUT_RULESET description 'Outbound: BLOCK ALL'

  set interfaces ethernet $IFACE firewall out name $OUT_RULESET
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
