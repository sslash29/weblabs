import html as _html


def e(s):
    return _html.escape(str(s), quote=True)


def layout(title, body, user=None, extra_head=""):
    if user:
        nav_right = f'''
        <span class="nav-user">Signed in as <strong>{e(user["username"])}</strong> ({e(user["role"])})</span>
        <a href="/accounts">Accounts</a>
        <a href="/transfer">Transfer</a>
        <a href="/support">Support</a>
        <a href="/logout">Logout</a>
        '''
    else:
        nav_right = '<a href="/login">Log in</a> <a href="/register">Open an account</a>'

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(title)} · MeridianPay</title>
<link rel="stylesheet" href="/static/css/style.css">
{extra_head}
</head>
<body>
<header class="site-header">
  <div class="wrap">
    <a class="brand" href="/">Meridian<span>Pay</span></a>
    <nav class="main-nav">
      <a href="/">Home</a>
      <a href="/about">About</a>
      <a href="/security">Security</a>
      <a href="/contact">Contact</a>
    </nav>
    <nav class="user-nav">{nav_right}</nav>
  </div>
</header>
<main class="wrap content">
{body}
</main>
<footer class="site-footer">
  <div class="wrap">
    <p>&copy; 2026 MeridianPay Financial Technologies, Inc. · A fictional company for security training purposes only. Not a real bank.</p>
  </div>
</footer>
</body>
</html>"""


def flag_banner(flag):
    return f'<div class="flag-banner">🚩 Objective complete: <code>{e(flag)}</code></div>'


CSS = """
:root {
  --teal: #0a4a45;
  --teal-light: #0f6b63;
  --gold: #c9922a;
  --bg: #f5f7f6;
  --card: #ffffff;
  --text: #1b2624;
  --muted: #5d6b68;
  --border: #dfe6e3;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.55;
}
.wrap { max-width: 1080px; margin: 0 auto; padding: 0 20px; }
.site-header { background: var(--teal); color: #fff; }
.site-header .wrap { display: flex; align-items: center; gap: 24px; padding: 14px 20px; flex-wrap: wrap; }
.brand { color: #fff; font-weight: 700; font-size: 1.3rem; text-decoration: none; }
.brand span { color: var(--gold); }
.main-nav, .user-nav { display: flex; gap: 16px; align-items: center; flex-wrap: wrap; }
.main-nav { margin-right: auto; }
.site-header a { color: #cfe3df; text-decoration: none; font-size: 0.95rem; }
.site-header a:hover { color: #fff; }
.nav-user { color: #9fc4bc; font-size: 0.9rem; }
.content { padding: 36px 20px 60px; min-height: 60vh; }
h1 { color: var(--teal); }
h2 { color: var(--teal-light); }
a { color: #0f6b63; }
.card {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 20px 24px;
  margin-bottom: 20px;
}
.hero {
  background: linear-gradient(120deg, var(--teal), var(--teal-light));
  color: #fff;
  border-radius: 10px;
  padding: 48px 36px;
  margin-bottom: 32px;
}
.hero h1 { color: #fff; margin-top: 0; }
.hero p { color: #d9ebe7; font-size: 1.1rem; max-width: 640px; }
.btn {
  display: inline-block;
  background: var(--gold);
  color: #fff;
  padding: 10px 18px;
  border-radius: 6px;
  text-decoration: none;
  font-weight: 600;
  border: none;
  cursor: pointer;
  font-size: 0.95rem;
}
.btn:hover { background: #b07f1f; }
.btn.secondary { background: var(--teal); }
.btn.small { padding: 6px 12px; font-size: 0.85rem; }
.btn.danger { background: #a4231c; }
table { width: 100%; border-collapse: collapse; margin: 12px 0; }
th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border); font-size: 0.93rem; }
th { color: var(--muted); text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.04em; }
input, textarea, select {
  width: 100%;
  padding: 10px 12px;
  border: 1px solid var(--border);
  border-radius: 6px;
  font-size: 0.95rem;
  margin-bottom: 14px;
  font-family: inherit;
}
label { font-weight: 600; font-size: 0.88rem; color: var(--muted); display: block; margin-bottom: 4px; }
.form-narrow { max-width: 420px; }
.msg-error { background: #fdecea; color: #a4231c; padding: 10px 14px; border-radius: 6px; margin-bottom: 16px; }
.msg-ok { background: #e6f4ef; color: #0f6b3f; padding: 10px 14px; border-radius: 6px; margin-bottom: 16px; }
.badge { display: inline-block; padding: 2px 9px; border-radius: 10px; font-size: 0.75rem; font-weight: 600; }
.badge.open { background: #fff3cd; color: #8a6d00; }
.badge.closed { background: #e2e3e5; color: #41464b; }
.badge.pending { background: #fde9d0; color: #8a5a00; }
.badge.approved { background: #e2f3ea; color: #146c2e; }
.balance { font-size: 1.6rem; font-weight: 700; color: var(--teal); }
.balance.negative { color: #a4231c; }
.comment { border-left: 3px solid var(--gold); padding: 8px 14px; margin: 10px 0; background: #fafbfa; }
.flag-banner {
  background: #0a4a45;
  color: #f5d68a;
  padding: 14px 18px;
  border-radius: 8px;
  font-size: 1.05rem;
  margin: 18px 0;
  border: 1px dashed #f5d68a;
}
pre { background: #0d1f1c; color: #d7e8e2; padding: 14px; border-radius: 6px; overflow-x: auto; font-size: 0.85rem; }
.footer-note { color: var(--muted); font-size: 0.85rem; }
.site-footer { background: #fff; border-top: 1px solid var(--border); padding: 22px 0; margin-top: 40px; }
.site-footer p { color: var(--muted); font-size: 0.85rem; margin: 0; }
.acct-row { display: flex; justify-content: space-between; align-items: center; padding: 12px 0; border-bottom: 1px solid var(--border); }
.acct-row:last-child { border-bottom: none; }
"""
