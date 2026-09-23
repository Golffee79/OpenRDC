#!/bin/bash
# OpenRDC M0 E2E smoke: Xvfb -> host -> API positive + negative cases -> MCP gateway stdio.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
DISP=:99; PORT=18799
export OPENRDC_TOKEN_FILE=/tmp/openrdc-e2e-token AUDIT=/tmp/openrdc-e2e-audit.jsonl
rm -f "$OPENRDC_TOKEN_FILE" "$AUDIT"
# full caps incl. dangerous (separate no-danger host later for negative test)
cat > /tmp/openrdc-e2e-caps.json <<'EOF'
{"granted": ["screen.capture", "mouse.click", "keyboard.type", "keyboard.press", "keyboard.press.dangerous"]}
EOF
Xvfb $DISP -screen 0 800x600x24 & XVFB=$!
export DISPLAY=$DISP
sleep 1
"$ROOT/openrdc-host/target/debug/openrdc-host" --port $PORT --caps /tmp/openrdc-e2e-caps.json --audit "$AUDIT" & HOST=$!
sleep 1.5
TOKEN=$(cat "$OPENRDC_TOKEN_FILE")
BASE="http://127.0.0.1:$PORT"
pass=0; fail=0
chk() { # chk <desc> <expected-code> <curl-args...>
  local desc="$1" want="$2"; shift 2
  local code; code=$(curl -s -o /tmp/e2e-body.json -w "%{http_code}" "$@")
  if [ "$code" = "$want" ]; then echo "PASS $desc [$code]"; pass=$((pass+1)); else echo "FAIL $desc want=$want got=$code body=$(cat /tmp/e2e-body.json)"; fail=$((fail+1)); fi
}
H=(-H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json")
chk "health no-auth" 200 "$BASE/health"
chk "no token -> 401" 401 -X GET "$BASE/v1/system"
chk "bad token -> 401" 401 -H "Authorization: Bearer wrong" "$BASE/v1/system"
chk "system ok" 200 "${H[@]}" "$BASE/v1/system"
chk "capture ok" 200 "${H[@]}" -d '{}' "$BASE/v1/screen/capture"
FID=$(python3 -c "import json;print(json.load(open('/tmp/e2e-body.json'))['frame_id'])")
W=$(python3 -c "import json;print(json.load(open('/tmp/e2e-body.json'))['output_width'])")
chk "click frame coords" 200 "${H[@]}" -d "{\"frame_id\":\"$FID\",\"x\":10,\"y\":10}" "$BASE/v1/mouse/click"
chk "type text" 200 "${H[@]}" -d '{"text":"E2E-SECRET-TYPED-TEXT hello"}' "$BASE/v1/keyboard/type"
chk "press Enter" 200 "${H[@]}" -d '{"key":"Enter","modifiers":[]}' "$BASE/v1/keyboard/press"
chk "stale frame -> 410" 410 "${H[@]}" -d '{"frame_id":"00000000-0000-0000-0000-000000000000","x":1,"y":1}' "$BASE/v1/mouse/click"
chk "oob coords -> 400" 400 "${H[@]}" -d "{\"frame_id\":\"$FID\",\"x\":99999,\"y\":0}" "$BASE/v1/mouse/click"
chk ">1024 chars -> 400" 400 "${H[@]}" -d "{\"text\":\"$(python3 -c "print('x'*1025)")\"}" "$BASE/v1/keyboard/type"
chk "malformed -> 400" 400 "${H[@]}" -d 'not json{{{' "$BASE/v1/keyboard/type"
# dangerous without grant: second host with reduced caps
PORT2=18798; AUDIT2=/tmp/openrdc-e2e-audit2.jsonl; rm -f "$AUDIT2"
echo '{"granted": ["keyboard.press"]}' > /tmp/openrdc-e2e-caps2.json
OPENRDC_TOKEN_FILE=/tmp/openrdc-e2e-token2 DISPLAY=$DISP "$ROOT/openrdc-host/target/debug/openrdc-host" --port $PORT2 --caps /tmp/openrdc-e2e-caps2.json --audit "$AUDIT2" & HOST2=$!
sleep 1.5
T2=$(cat /tmp/openrdc-e2e-token2)
chk "dangerous w/o grant -> 403 forbidden_capability" 403 -H "Authorization: Bearer $T2" -H "Content-Type: application/json" -d '{"key":"F4","modifiers":["alt"]}' "http://127.0.0.1:$PORT2/v1/keyboard/press"
CODE=$(curl -s -o /tmp/e2e-body.json -w "%{http_code}" -H "Authorization: Bearer $T2" -H "Content-Type: application/json" -d '{"key":"F4","modifiers":["alt"]}' "http://127.0.0.1:$PORT2/v1/keyboard/press")
python3 -c "import json,sys; assert json.load(open('/tmp/e2e-body.json'))['error']['code']=='forbidden_capability'" && echo "PASS dangerous code is forbidden_capability" && pass=$((pass+1)) || { echo "FAIL dangerous code"; fail=$((fail+1)); }
chk "missing cap (click w/o grant) -> 403" 403 -H "Authorization: Bearer $T2" -H "Content-Type: application/json" -d '{"frame_id":"00000000-0000-0000-0000-000000000000","x":1,"y":1}' "http://127.0.0.1:$PORT2/v1/mouse/click"
# MCP gateway stdio E2E: full tools/call slice through gateway -> real host.
# No mocks: initialize -> capture -> click(frame_id) -> type -> key(Enter).
# Runs BEFORE the rate-limit hammer (shared input bucket).
export OPENRDC_HOST="$BASE" OPENRDC_TOKEN="$TOKEN"
if timeout 60 node "$ROOT/openrdc-gateway/scripts/e2e-mcp-calls.mjs"; then
  echo "PASS gateway tools/call slice"; pass=$((pass+1))
else
  echo "FAIL gateway tools/call slice"; fail=$((fail+1))
fi
# rate limit: hammer type endpoint
LIMITED=0
for i in $(seq 1 30); do
  c=$(curl -s -o /dev/null -w "%{http_code}" "${H[@]}" -d '{"text":"hi"}' "$BASE/v1/keyboard/type")
  if [ "$c" = "429" ]; then LIMITED=1; break; fi
done
if [ "$LIMITED" = 1 ]; then echo "PASS rate-limit 429 observed"; pass=$((pass+1)); else echo "FAIL rate-limit never hit"; fail=$((fail+1)); fi
kill $HOST $HOST2 $XVFB 2>/dev/null || true
echo "---- audit inspector ----"
python3 "$ROOT/scripts/verify-audit.py" "$AUDIT"
echo "---- real hash-chain verifier ----"
"$ROOT/openrdc-host/target/debug/openrdc-host" --verify --audit "$AUDIT" && pass=$((pass+1)) || { echo "FAIL audit chain verify"; fail=$((fail+1)); }
echo "E2E pass=$pass fail=$fail"
[ "$fail" = 0 ]
