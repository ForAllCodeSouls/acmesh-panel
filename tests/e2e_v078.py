#!/usr/bin/env python3
"""v0.1.78 端到端测试：真实进程，覆盖 ARI / 指标 / 导入 / 失败队列 / 筛选导出 / 委托参数。"""
import http.client
import json
import os
import shutil
import subprocess
import sys
import time

BASE_HOST = "127.0.0.1"
PORT = int(os.environ.get("E2E_PORT", "18083"))
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.environ.get("E2E_BIN", "/tmp/build/acmesh-panel")
ACME_BIN = os.environ.get("E2E_ACME_BIN", os.path.join(ROOT, "tests", "fake-acme.sh"))
WORK = os.environ.get("E2E_WORK", "/tmp/e2e-v078")
ACME_HOME = WORK + "/acme"
DATA = WORK + "/data"
SYNC_DIR = WORK + "/certs"
PASSWORD = "E2eV078Pass!2026"

passed = 0
failed = []


def check(name, cond, extra=""):
    global passed
    if cond:
        passed += 1
        print(f"  \033[32mPASS\033[0m {name}")
    else:
        failed.append(name)
        print(f"  \033[31mFAIL\033[0m {name} {extra}")


class Client:
    def __init__(self):
        self.cookies = {}
        self.csrf = None

    def req(self, method, path, body=None, headers=None, csrf=True):
        h = {"Host": f"{BASE_HOST}:{PORT}", "Accept": "application/json"}
        if body is not None:
            h["Content-Type"] = "application/json"
            body = json.dumps(body).encode()
        if self.cookies:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if csrf and self.csrf and method not in ("GET", "HEAD"):
            h["X-CSRF-Token"] = self.csrf
        if headers:
            h.update(headers)
        conn = http.client.HTTPConnection(BASE_HOST, PORT, timeout=30)
        conn.request(method, path, body=body, headers=h)
        r = conn.getresponse()
        data = r.read()
        for k, v in r.getheaders():
            if k.lower() == "set-cookie":
                first = v.split(";")[0]
                if "=" in first:
                    ck, cv = first.split("=", 1)
                    if cv == "":
                        self.cookies.pop(ck, None)
                    else:
                        self.cookies[ck] = cv
        status = r.status
        conn.close()
        return status, data

    def j(self, method, path, body=None, **kw):
        st, data = self.req(method, path, body, **kw)
        try:
            return st, json.loads(data)
        except Exception:
            return st, data


def main():
    shutil.rmtree(WORK, ignore_errors=True)
    for d in (ACME_HOME, DATA, SYNC_DIR):
        os.makedirs(d, exist_ok=True)

    env = dict(os.environ)
    env.update({
        "ACME_PANEL_LISTEN": f"{BASE_HOST}:{PORT}",
        "ACME_HOME": ACME_HOME,
        "ACME_BIN": ACME_BIN,
        "ACME_PANEL_DATA": DATA,
        "ACME_PANEL_USER": "admin",
        "ACME_PANEL_PASSWORD": PASSWORD,
        "ACME_PANEL_CRON": "0",
        "ACME_PANEL_SYNC_DIR": SYNC_DIR,
        "TZ": "Asia/Shanghai",
    })
    log = open(WORK + "/panel.log", "w+")
    proc = subprocess.Popen([BIN], env=env, stdout=log, stderr=subprocess.STDOUT)
    try:
        c = Client()
        ok = False
        for _ in range(80):
            try:
                st, _ = c.req("GET", "/api/health")
                if st == 200:
                    ok = True
                    break
            except Exception:
                pass
            time.sleep(0.15)
        check("服务启动", ok)
        if not ok:
            log.seek(0)
            print(log.read())
            return 1

        st, j = c.j("POST", "/api/login", {"username": "admin", "password": PASSWORD})
        check("登录成功", st == 200 and j.get("csrf"), (st, j))
        c.csrf = j["csrf"]

        # ---- ARI：无证书时返回空数组，不触发 CA 网络请求 ----
        st, j = c.j("GET", "/api/ari")
        check("ARI 接口可用且返回空列表", st == 200 and j.get("items") == [], (st, j))

        # ---- 指标端点：会话与两种令牌请求头 ----
        st, data = c.req("GET", "/api/metrics")
        text = data.decode("utf-8", "ignore")
        check("指标端点返回 Prometheus 文本", st == 200 and "acmesh_panel_up 1" in text
              and "acmesh_panel_certificates_total" in text, (st, text[:200]))
        check("指标不含域名标签", "example.com" not in text, text[:200])

        st, j = c.j("POST", "/api/tokens", {"name": "监控", "scopes": ["overview"]})
        token = j.get("plain", "") if isinstance(j, dict) else ""
        check("创建概览只读令牌", st == 201 and token.startswith("acmp_"), (st, j))
        st, data = c.req("GET", "/api/metrics", headers={"X-API-Token": token}, csrf=False)
        check("X-API-Token 可抓取指标", st == 200 and b"acmesh_panel_up 1" in data, st)
        st, data = c.req("GET", "/api/metrics", headers={"Authorization": "Bearer " + token}, csrf=False)
        check("Authorization Bearer 可抓取指标", st == 200 and b"acmesh_panel_up 1" in data, st)

        # ---- 证书导入：非法输入被拒绝且路径不可越界 ----
        st, j = c.j("POST", "/api/certs/import", {"cert_pem": "not a pem", "key_pem": "x"})
        check("导入非法 PEM 被拒绝", st == 400, (st, j))
        st, j = c.j("POST", "/api/certs/import", {
            "cert_pem": "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----",
            "key_pem": "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----",
            "name": "../escape",
        })
        check("导入拒绝越界目录名", st == 400, (st, j))

        # ---- 通知失败队列与 HMAC 渠道 ----
        st, j = c.j("GET", "/api/notify/failures")
        check("失败队列初始为空", st == 200 and j.get("failures") == [], (st, j))
        st, j = c.j("GET", "/api/notify/catalog")
        kinds = [x.get("code") for x in j.get("kinds", [])] if isinstance(j, dict) else []
        check("目录包含 HMAC 签名渠道", "generic_hmac" in kinds, kinds)
        st, j = c.j("POST", "/api/notify", {
            "name": "hmac-test", "kind": "generic_hmac", "target": "https://203.0.113.10/hook",
            "secret": "0123456789abcdef", "events": ["issue_failed"], "enabled": True,
        })
        check("HMAC 渠道可保存", st in (200, 201), (st, j))

        # ---- DNS 委托参数校验（不实际签发）----
        st, j = c.j("POST", "/api/issue", {"domains": ["demo1.example.net"], "code": "dns_ali",
                                          "env": {}, "challenge_alias": "bad host!"})
        check("非法 DNS 委托域名被拒绝", st == 400, (st, j))

        # ---- 审计导出应用筛选 ----
        st, data = c.req("GET", "/api/export.csv?kind=audit&action=login_ok")
        csv_text = data.decode("utf-8", "ignore")
        check("审计导出带筛选且含登录记录", st == 200 and "login_ok" in csv_text
              and "token_create" not in csv_text, (st, csv_text[:300]))
        st, data = c.req("GET", "/api/export.csv?kind=audit")
        check("审计导出全量含令牌创建记录", st == 200 and "token_create" in data.decode("utf-8", "ignore"), st)

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()

    total = passed + len(failed)
    print(f"\n结果: {passed}/{total} 通过")
    if failed:
        print("失败项:")
        for f in failed:
            print("  -", f)
        with open(WORK + "/panel.log") as fh:
            print("\n--- 服务日志 ---\n" + fh.read()[-4000:])
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
