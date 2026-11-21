"""Static configuration for decoy-http.

Everything the server can ever send back is defined here as static text.
Responses are looked up by exact path in a dict: the requested path is never
used to touch the filesystem, so path traversal is impossible by construction.

All "secrets" below are deliberately and obviously fake. They do not follow any
real key format, so they can't be mistaken for real credentials.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# --------------------------------------------------------------------------
# Identity the server pretends to have
# --------------------------------------------------------------------------

SERVER_HEADER = "Apache/2.4.52 (Ubuntu)"
X_POWERED_BY = "PHP/7.4.3"
# Shown in Apache-style error pages. Fixed value: we never reflect the
# client's Host header back into a page.
SERVER_NAME = "localhost"
SERVER_PORT_LABEL = 80


@dataclass(frozen=True)
class FakeResponse:
    status: int
    body: str
    content_type: str = "text/html; charset=UTF-8"
    # Add "X-Powered-By: PHP/..." to make it look like a PHP page.
    php: bool = False
    headers: tuple[tuple[str, str], ...] = field(default_factory=tuple)


# --------------------------------------------------------------------------
# Fake page contents
# --------------------------------------------------------------------------

APACHE_DEFAULT_PAGE = """<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <title>Apache2 Ubuntu Default Page: It works</title>
    <style type="text/css" media="screen">
      body { background-color: #D8DBE2; font-family: Verdana, sans-serif; font-size: 11pt; margin: 0; }
      div.main_page { width: 1000px; margin: 20px auto; background-color: #fff; border: 1px solid #000; }
      div.page_header { height: 99px; border-bottom: 1px solid #000; background-color: #fff; }
      div.page_header span { margin: 15px 0 0 50px; font-size: 180%; font-weight: bold; display: inline-block; }
      div.content_section_text { padding: 4px 8px; color: #000; }
      div.section_header { padding: 3px 6px; margin-top: 5px; background-color: #8E9CB2; color: #fff; font-weight: bold; }
      div.section_header_red { background-color: #CD214F; }
      pre { border: 1px dotted #000; background-color: #F5F6F7; padding: 0.5em; }
    </style>
  </head>
  <body>
    <div class="main_page">
      <div class="page_header floating_element">
        <span class="floating_element">Apache2 Ubuntu Default Page</span>
      </div>
      <div class="content_section floating_element">
        <div class="section_header section_header_red">
          <div id="about"></div>
          It works!
        </div>
        <div class="content_section_text">
          <p>
            This is the default welcome page used to test the correct operation
            of the Apache2 server after installation on Ubuntu systems.
            If you can read this page, it means that the Apache HTTP server
            installed at this site is working properly. You should
            <b>replace this file</b> (located at <tt>/var/www/html/index.html</tt>)
            before continuing to operate your HTTP server.
          </p>
        </div>
        <div class="section_header">
          <div id="changes"></div>
          Configuration Overview
        </div>
        <div class="content_section_text">
          <p>
            Ubuntu's Apache2 default configuration is split into several files
            optimized for interaction with Ubuntu tools. The configuration layout
            for an Apache2 web server installation on Ubuntu systems is as follows:
          </p>
          <pre>
/etc/apache2/
|-- apache2.conf
|       `--  ports.conf
|-- mods-enabled
|       |-- *.load
|       `-- *.conf
|-- conf-enabled
|       `-- *.conf
|-- sites-enabled
|       `-- *.conf
          </pre>
        </div>
        <div class="section_header">
          <div id="docroot"></div>
          Document Roots
        </div>
        <div class="content_section_text">
          <p>
            By default, Ubuntu does not allow access through the web browser to
            <em>any</em> file outside of those located in <tt>/var/www</tt>,
            <a href="http://httpd.apache.org/docs/2.4/mod/mod_userdir.html" rel="nofollow">public_html</a>
            directories (when enabled) and <tt>/usr/share</tt> (for web applications).
          </p>
        </div>
      </div>
      <div class="validator"></div>
    </div>
  </body>
</html>
"""

FAKE_DOTENV = """APP_NAME=Laravel
APP_ENV=production
APP_KEY=decoy_not_a_real_app_key
APP_DEBUG=false
APP_URL=http://localhost

LOG_CHANNEL=stack

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=webapp_prod
DB_USERNAME=webapp
DB_PASSWORD=decoy_not_a_real_secret

REDIS_HOST=127.0.0.1
REDIS_PASSWORD=decoy_not_a_real_secret
REDIS_PORT=6379

MAIL_MAILER=smtp
MAIL_HOST=smtp.example.invalid
MAIL_PORT=587
MAIL_USERNAME=noreply@example.invalid
MAIL_PASSWORD=decoy_not_a_real_secret

AWS_ACCESS_KEY_ID=DECOY_NOT_A_REAL_KEY_ID
AWS_SECRET_ACCESS_KEY=decoy_not_a_real_secret
AWS_DEFAULT_REGION=eu-west-1
AWS_BUCKET=decoy-not-a-real-bucket
"""

FAKE_API_DOTENV = """NODE_ENV=production
PORT=3000
DATABASE_URL=postgres://api:decoy_not_a_real_secret@127.0.0.1:5432/api
JWT_SECRET=decoy_not_a_real_secret
STRIPE_KEY=decoy_not_a_real_payment_key
SENDGRID_API_KEY=decoy_not_a_real_api_key
"""

FAKE_GIT_CONFIG = """[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
[remote "origin"]
\turl = https://git.example.invalid/internal/webapp.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
"""

FAKE_GIT_HEAD = "ref: refs/heads/main\n"

FAKE_CONFIG_JSON = """{
  "app": "webapp",
  "environment": "production",
  "database": {
    "host": "127.0.0.1",
    "port": 3306,
    "user": "webapp",
    "password": "decoy_not_a_real_secret"
  },
  "api": {
    "base_url": "https://api.example.invalid/v1",
    "token": "decoy_not_a_real_token"
  },
  "debug": false
}
"""

# No <script> anywhere: responses must never contain active content.
_WP_LOGIN_TEMPLATE = """<!DOCTYPE html>
<html lang="en-US">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Log In &lsaquo; My Blog &#8212; WordPress</title>
<meta name="robots" content="max-image-preview:large, noindex, noarchive" />
<style>
body { background: #f0f0f1; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
#login { width: 320px; margin: auto; padding: 8% 0 0; }
#login h1 a { display: block; text-align: center; font-size: 20px; color: #3c434a; text-decoration: none; }
.login form { margin-top: 20px; padding: 26px 24px; background: #fff; border: 1px solid #c3c4c7; }
.login label { font-size: 14px; }
.login input[type=text], .login input[type=password] { width: 100%; font-size: 24px; margin: 2px 6px 16px 0; padding: 3px 5px; }
#login_error { border-left: 4px solid #d63638; background: #fff; padding: 12px; margin-top: 20px; }
.button-primary { background: #2271b1; border-color: #2271b1; color: #fff; padding: 0 12px; min-height: 32px; }
</style>
</head>
<body class="login js login-action-login wp-core-ui locale-en-us">
<div id="login">
<h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
{error}
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
<p>
<label for="user_login">Username or Email Address</label>
<input type="text" name="log" id="user_login" class="input" value="" size="20" autocapitalize="off" autocomplete="username" />
</p>
<div class="user-pass-wrap">
<label for="user_pass">Password</label>
<input type="password" name="pwd" id="user_pass" class="input password-input" value="" size="20" autocomplete="current-password" />
</div>
<p class="forgetmenot"><input name="rememberme" type="checkbox" id="rememberme" value="forever" /> <label for="rememberme">Remember Me</label></p>
<p class="submit">
<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In" />
<input type="hidden" name="redirect_to" value="/wp-admin/" />
<input type="hidden" name="testcookie" value="1" />
</p>
</form>
<p id="nav"><a href="/wp-login.php?action=lostpassword">Lost your password?</a></p>
</div>
</body>
</html>
"""

# The error never echoes the submitted username (no reflection of input).
WP_LOGIN_PAGE = _WP_LOGIN_TEMPLATE.replace("{error}", "")
WP_LOGIN_FAILED_PAGE = _WP_LOGIN_TEMPLATE.replace(
    "{error}",
    '<div id="login_error"><strong>Error:</strong> The username or password '
    "you entered is incorrect. "
    '<a href="/wp-login.php?action=lostpassword">Lost your password?</a></div>',
)

PHPMYADMIN_PAGE = """<!DOCTYPE HTML>
<html lang="en" dir="ltr">
<head>
<meta charset="utf-8">
<meta name="robots" content="noindex,nofollow">
<title>phpMyAdmin</title>
<style>
body { font-family: sans-serif; background: #fff; }
.container { width: 400px; margin: 60px auto; }
fieldset { border: 1px solid #aaa; padding: 1em; }
label { display: inline-block; width: 120px; }
</style>
</head>
<body id="loginform">
<div class="container">
<h1>Welcome to <bdo dir="ltr" lang="en">phpMyAdmin</bdo></h1>
<form method="post" action="/phpmyadmin/index.php" name="login_form" class="disableAjax login hide js-show">
<fieldset>
<legend>Log in</legend>
<div class="item"><label for="input_username">Username:</label>
<input type="text" name="pma_username" id="input_username" value="" size="24" autocomplete="username"></div>
<div class="item"><label for="input_password">Password:</label>
<input type="password" name="pma_password" id="input_password" value="" size="24" autocomplete="current-password"></div>
<input type="hidden" name="server" value="1">
</fieldset>
<fieldset class="tblFooters">
<input value="Go" type="submit" id="input_go">
</fieldset>
</form>
</div>
</body>
</html>
"""

ADMIN_PAGE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Admin Login</title>
<style>
body { font-family: Arial, sans-serif; background: #eef1f5; }
.box { width: 300px; margin: 120px auto; background: #fff; padding: 24px; border: 1px solid #ccd; }
input { width: 100%; margin: 6px 0 14px; padding: 6px; }
</style>
</head>
<body>
<div class="box">
<h2>Administration</h2>
<form method="post" action="/admin">
<label>User</label><input type="text" name="username">
<label>Password</label><input type="password" name="password">
<input type="submit" value="Sign in">
</form>
</div>
</body>
</html>
"""

SERVER_STATUS_PAGE = f"""<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html><head>
<title>Apache Status</title>
</head><body>
<h1>Apache Server Status for {SERVER_NAME} (via 127.0.0.1)</h1>

<dl><dt>Server Version: {SERVER_HEADER} OpenSSL/3.0.2</dt>
<dt>Server MPM: prefork</dt>
<dt>Server Built: 2023-10-26T13:44:44</dt>
</dl><hr /><dl>
<dt>Current Time: Monday, 06-Nov-2023 10:12:01 UTC</dt>
<dt>Restart Time: Monday, 30-Oct-2023 08:00:13 UTC</dt>
<dt>Parent Server Config. Generation: 8</dt>
<dt>Server uptime:  7 days 2 hours 11 minutes 48 seconds</dt>
<dt>Server load: 0.08 0.05 0.01</dt>
<dt>Total accesses: 48211 - Total Traffic: 391.2 MB</dt>
<dt>1 requests currently being processed, 7 idle workers</dt>
</dl>
<pre>_W______.......................................................
................................................................</pre>
<p>Scoreboard Key:<br />
"<b><code>_</code></b>" Waiting for Connection,
"<b><code>W</code></b>" Sending Reply,
"<b><code>.</code></b>" Open slot with no current process<br />
</p>
</body></html>
"""

ROBOTS_TXT = """User-agent: *
Disallow: /admin
Disallow: /phpmyadmin/
Disallow: /server-status
Disallow: /config.json
Disallow: /wp-login.php
"""

NOT_FOUND_PAGE = f"""<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>{SERVER_HEADER} Server at {SERVER_NAME} Port {SERVER_PORT_LABEL}</address>
</body></html>
"""

_TEXT = "text/plain; charset=UTF-8"

# --------------------------------------------------------------------------
# Endpoints: exact path -> static response (served for GET / HEAD / POST)
# --------------------------------------------------------------------------

ENDPOINTS: dict[str, FakeResponse] = {
    "/": FakeResponse(200, APACHE_DEFAULT_PAGE),
    "/index.html": FakeResponse(200, APACHE_DEFAULT_PAGE),
    "/robots.txt": FakeResponse(200, ROBOTS_TXT, _TEXT),
    "/.env": FakeResponse(200, FAKE_DOTENV, _TEXT),
    "/api/.env": FakeResponse(200, FAKE_API_DOTENV, _TEXT),
    "/.git/config": FakeResponse(200, FAKE_GIT_CONFIG, _TEXT),
    "/.git/HEAD": FakeResponse(200, FAKE_GIT_HEAD, _TEXT),
    "/config.json": FakeResponse(200, FAKE_CONFIG_JSON, "application/json"),
    "/wp-login.php": FakeResponse(200, WP_LOGIN_PAGE, php=True),
    "/phpmyadmin/": FakeResponse(200, PHPMYADMIN_PAGE, php=True),
    "/phpmyadmin/index.php": FakeResponse(200, PHPMYADMIN_PAGE, php=True),
    "/phpmyadmin": FakeResponse(
        301, "", headers=(("Location", "/phpmyadmin/"),)
    ),
    "/admin": FakeResponse(200, ADMIN_PAGE, php=True),
    "/admin/": FakeResponse(200, ADMIN_PAGE, php=True),
    "/server-status": FakeResponse(200, SERVER_STATUS_PAGE),
}

# Responses for POST to specific paths (everything else: same as GET).
POST_OVERRIDES: dict[str, FakeResponse] = {
    # Login always fails, whatever was submitted.
    "/wp-login.php": FakeResponse(200, WP_LOGIN_FAILED_PAGE, php=True),
}

NOT_FOUND = FakeResponse(404, NOT_FOUND_PAGE, "text/html; charset=iso-8859-1")

# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------

LOG_FILE_NAME = "requests.jsonl"
LOG_MAX_BYTES = 20 * 1024 * 1024  # rotate at 20 MB...
LOG_BACKUP_COUNT = 9  # ...keeping 9 old files: at most 10 x 20 MB on disk
MAX_BODY_LOG_BYTES = 8 * 1024  # bodies are logged (never saved as files), truncated

# --------------------------------------------------------------------------
# Classification rules: (category, regex, parts of the request to search)
#
# Parts: "path" (raw + URL-decoded path), "query" (raw + decoded query),
# "body" (raw + decoded body), "headers" (header values).
# Matching is case-insensitive. A request can get several categories; if none
# matches it is "unknown". "proxy-attempt" is set by the server itself.
# --------------------------------------------------------------------------

_PARAMS = ("query", "body")
_ALL = ("path", "query", "body", "headers")

CATEGORY_RULES: list[tuple[str, str, tuple[str, ...]]] = [
    (
        "sensitive-file-probe",
        r"/\.(env|git|svn|hg|aws|ssh|docker|vscode|idea|ds_store|htpasswd|htaccess)"
        r"|/(config|settings|credentials|secrets?|database|parameters)\.(json|ya?ml|php|js|ini|xml|txt|bak)"
        r"|wp-config|\.(sql|bak|old|swp|tar\.gz|zip)$|/backup|/etc/(passwd|shadow)",
        ("path",),
    ),
    (
        "wordpress-probe",
        r"/(wp-(login|admin|content|includes|json|config|cron)|xmlrpc\.php|wordpress)",
        ("path",),
    ),
    (
        "phpmyadmin-probe",
        r"/(phpmyadmin|pma|myadmin|mysqladmin|dbadmin|sqladmin|phpmy)",
        ("path",),
    ),
    (
        "admin-discovery",
        r"/(admin|administrator|login|manager|cpanel|panel|dashboard|console"
        r"|server-status|server-info|actuator|jenkins|webadmin|adminer)(?:[/._?-]|$)",
        ("path",),
    ),
    (
        "path-traversal",
        r"\.\./|\.\.\\|%2e%2e|%252e|\.\.%2f|%c0%ae|/etc/passwd|win\.ini|boot\.ini",
        ("path", "query", "body"),
    ),
    (
        "sqli-attempt",
        r"union(\s|\+|/\*.*?\*/)+(all(\s|\+)+)?select|'\s*or\s*'?\d+'?\s*=\s*'?\d|\bor\s+1\s*=\s*1"
        r"|sleep\s*\(\s*\d|benchmark\s*\(|information_schema|waitfor\s+delay"
        r"|extractvalue\s*\(|updatexml\s*\(|'\s*(--|#)",
        _PARAMS,
    ),
    (
        "command-injection",
        r"(;|\||&&|\$\(|`)\s*(wget|curl|chmod|sh|bash|cat|id|uname|whoami|nc|busybox|rm|echo|ping|tftp|python|perl|cd)\b"
        r"|\b(wget|curl)\s+(-\S+\s+)*h[tx]{2}ps?://|chmod\s+(\+x|[0-7]{3})|/bin/(ba)?sh|\$\(",
        ("path", "query", "body"),
    ),
    ("log4shell", r"\$\{\s*jndi\s*:|\$\{[^}]{0,40}(lower|upper|::-)[^}]{0,40}\}", _ALL),
    ("shellshock", r"\(\s*\)\s*\{", _ALL),
    (
        "router-iot-exploit",
        r"/(boaform|goform|cgi-bin|hnap1|setup\.cgi|shell\b|gponform|tmunblock\.cgi"
        r"|login\.cgi|apply\.cgi|device\.rsp|onvif|picsdesc\.xml|soap\.cgi"
        r"|currentsetting\.htm|ctrlt|mgmt|dvr|diag\.cgi|stssys\.htm|wanipcn)",
        ("path",),
    ),
]
