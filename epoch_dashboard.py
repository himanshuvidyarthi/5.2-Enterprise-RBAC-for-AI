"""
epoch_dashboard.py — small local dashboard for EPOCH Session 15.2

Not part of the graded deliverable (epoch_auth.py is). This is a thin
Flask viewer over the same objects epoch_auth.py already exposes:

  - run_session_verification()  -> the 8/8 check results
  - ROLE_TOOLS / tools_for_role -> the RBAC matrix
  - AUDIT_LOG                   -> every tool call ever recorded
  - verify_jwt / tools_for_role -> the actual enforcement path

The "Simulate a call" form below does NOT call Gemini. It calls
tools_for_role() + the tool function directly, so the RBAC boundary is
provable with zero API key required: pick a role and a tool that role
isn't bound to, and the request is rejected before the tool ever runs
— same compiler-level guarantee BoundGeminiModel gives the LLM path.

Run:
    python epoch_dashboard.py
    open http://127.0.0.1:5050
"""

import inspect
from datetime import datetime, timezone

from flask import Flask, redirect, render_template_string, request, url_for

from epoch_auth import (
    AUDIT_LOG,
    AuthError,
    ROLE_TOOLS,
    TOOL_REGISTRY,
    audit_tool_call,
    mint_jwt,
    run_session_verification,
    tools_for_role,
    verify_jwt,
)

app = Flask(__name__)

# One token per persona, minted once at startup so the dashboard has
# something real to verify_jwt() against on every simulated call.
PERSONAS = {
    'viewer':             'intern-lee',
    'analyst':            'dr-jones',
    'multimodal_analyst': 'dr-patel',
    'admin':              'chief-morgan',
}
TOKENS = {
    role: mint_jwt('hospital_a', user_id, role)
    for role, user_id in PERSONAS.items()
}

LAST_BLOCK = {}  # last rejected attempt, shown as a banner


def _demo_args(fn) -> dict:
    """Fill a tool's required params with obviously-fake demo values."""
    args = {}
    for name, param in inspect.signature(fn).parameters.items():
        if param.default is not inspect.Parameter.empty:
            continue
        if name in ('expert_id',):
            args[name] = 'chen'
        else:
            args[name] = f'demo-{name}'
    return args


PAGE = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>EPOCH 15.2 Dashboard</title>
<style>
  :root {
    --bg: #0f1216; --panel: #171b21; --border: #262c35;
    --text: #e6e9ef; --muted: #8b93a1; --ok: #3fce7a; --bad: #f0576a;
    --accent: #6ea8fe;
  }
  * { box-sizing: border-box; }
  body {
    background: var(--bg); color: var(--text);
    font-family: -apple-system, "SF Pro Text", Helvetica, Arial, sans-serif;
    margin: 0; padding: 32px; line-height: 1.45;
  }
  h1 { font-size: 20px; margin: 0 0 4px; }
  .sub { color: var(--muted); font-size: 13px; margin-bottom: 28px; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  .panel {
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 10px; padding: 18px 20px; margin-bottom: 20px;
  }
  .panel h2 {
    font-size: 13px; text-transform: uppercase; letter-spacing: .04em;
    color: var(--muted); margin: 0 0 14px;
  }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); font-weight: 500; }
  td.mono, th.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .ok { color: var(--ok); } .bad { color: var(--bad); }
  .pill {
    display: inline-block; padding: 1px 8px; border-radius: 999px;
    font-size: 11px; font-weight: 600;
  }
  .pill.ok { background: rgba(63,206,122,.15); color: var(--ok); }
  .pill.bad { background: rgba(240,87,106,.15); color: var(--bad); }
  select, button {
    background: #10141a; color: var(--text); border: 1px solid var(--border);
    border-radius: 6px; padding: 7px 10px; font-size: 13px;
  }
  button { background: var(--accent); color: #0b1220; border: none; font-weight: 600; cursor: pointer; }
  button:hover { opacity: .9; }
  form { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
  .banner {
    padding: 12px 16px; border-radius: 8px; margin-bottom: 20px; font-size: 13px;
  }
  .banner.blocked { background: rgba(240,87,106,.1); border: 1px solid rgba(240,87,106,.4); }
  .banner.allowed { background: rgba(63,206,122,.1); border: 1px solid rgba(63,206,122,.4); }
  .note { color: var(--muted); font-size: 12px; margin-top: 10px; }
  code { background: #10141a; padding: 1px 5px; border-radius: 4px; }
</style>
</head>
<body>
  <h1>EPOCH — Session 15.2 Dashboard</h1>
  <div class="sub">RBAC via dynamic tool binding · epoch_auth.py · read-only view, no Gemini required</div>

  {% if last_block %}
    <div class="banner {{ 'blocked' if last_block.blocked else 'allowed' }}">
      {% if last_block.blocked %}
        <b>Blocked.</b> Role <code>{{ last_block.role }}</code> attempted
        <code>{{ last_block.tool }}</code> — not in that role's bound tool set.
        The call never ran.
      {% else %}
        <b>Executed.</b> Role <code>{{ last_block.role }}</code> called
        <code>{{ last_block.tool }}</code> successfully. Recorded in the audit log below.
      {% endif %}
    </div>
  {% endif %}

  <div class="panel">
    <h2>Verification — {{ verification.summary }}</h2>
    <table>
      <tr><th>Check</th><th>Result</th></tr>
      {% for c in verification.checks %}
      <tr>
        <td>{{ c.label }}</td>
        <td class="{{ 'ok' if c.passed else 'bad' }}">{{ '✓ pass' if c.passed else '✗ fail' }}</td>
      </tr>
      {% endfor %}
    </table>
  </div>

  <div class="grid">
    <div class="panel">
      <h2>RBAC Matrix</h2>
      <table>
        <tr><th>Role</th><th>Tools</th></tr>
        {% for role, tools in role_tools.items() %}
        <tr>
          <td class="mono">{{ role }}</td>
          <td class="mono">{{ tools|join(', ') }}</td>
        </tr>
        {% endfor %}
      </table>
    </div>

    <div class="panel">
      <h2>Simulate a call</h2>
      <form method="post" action="{{ url_for('simulate') }}">
        <select name="role">
          {% for role in role_tools.keys() %}
          <option value="{{ role }}">{{ role }}</option>
          {% endfor %}
        </select>
        <select name="tool">
          {% for tool in all_tools %}
          <option value="{{ tool }}">{{ tool }}</option>
          {% endfor %}
        </select>
        <button type="submit">Run</button>
      </form>
      <div class="note">
        Tool list is intentionally NOT filtered by role — pick any role +
        any tool. The backend calls <code>tools_for_role()</code> and
        rejects anything not bound, before the tool function ever executes.
        Try <code>viewer</code> + <code>generate_client_deliverable</code>.
      </div>
    </div>
  </div>

  <div class="panel">
    <h2>Audit log ({{ audit_log|length }} entries, newest first)</h2>
    <table>
      <tr><th>Time (UTC)</th><th>Role</th><th>User</th><th>Tool</th><th>OK</th><th class="mono">jti</th><th class="mono">hash</th></tr>
      {% for row in audit_log %}
      <tr>
        <td class="mono">{{ row.ts[11:19] }}</td>
        <td>{{ row.role }}</td>
        <td>{{ row.user_id }}</td>
        <td class="mono">{{ row.tool }}</td>
        <td class="{{ 'ok' if row.ok else 'bad' }}">{{ '✓' if row.ok else '✗' }}</td>
        <td class="mono">{{ row.jti[:8] }}…</td>
        <td class="mono">{{ row.hash }}</td>
      </tr>
      {% else %}
      <tr><td colspan="7" class="note">No tool calls simulated yet.</td></tr>
      {% endfor %}
    </table>
  </div>

</body>
</html>
"""


@app.route('/')
def dashboard():
    verification = run_session_verification()
    return render_template_string(
        PAGE,
        verification=verification,
        role_tools={r: [t.__name__ for t in tools_for_role(r)] for r in ROLE_TOOLS},
        all_tools=sorted(TOOL_REGISTRY.keys()),
        audit_log=list(reversed(AUDIT_LOG))[:50],
        last_block=LAST_BLOCK or None,
    )


@app.route('/simulate', methods=['POST'])
def simulate():
    global LAST_BLOCK
    role = request.form.get('role', '')
    tool_name = request.form.get('tool', '')

    token = TOKENS.get(role)
    try:
        claims = verify_jwt(token) if token else None
    except AuthError:
        claims = None

    allowed_names = ROLE_TOOLS.get(role, [])
    if not claims or tool_name not in allowed_names:
        LAST_BLOCK = {'blocked': True, 'role': role, 'tool': tool_name}
        return redirect(url_for('dashboard'))

    fn = TOOL_REGISTRY[tool_name]
    try:
        result = fn(**_demo_args(fn))
        ok = True
    except Exception as exc:
        result = {'error': str(exc)}
        ok = False

    audit_tool_call(claims, tool_name, result, ok)
    LAST_BLOCK = {'blocked': False, 'role': role, 'tool': tool_name}
    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5050, debug=False)
