#!/usr/bin/env python3
"""端到端测试：真实启动面板进程 + 假 acme.sh，覆盖认证、CSRF、限流、
签名流程、私钥访问控制、路径穿越与响应头。"""
import http.client
import datetime
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE_HOST = "127.0.0.1"
PORT = int(os.environ.get("E2E_PORT", "18080"))
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.environ.get("E2E_BIN", "/tmp/build/acmesh-panel")
ACME_BIN = os.environ.get("E2E_ACME_BIN", os.path.join(ROOT, "tests", "fake-acme.sh"))
WORK = os.environ.get("E2E_WORK", "/tmp/e2e")
ACME_HOME = WORK + "/acme"
DATA = WORK + "/data"
SYNC_DIR = WORK + "/certs"
SYNC_DIR2 = WORK + "/certs2"
PASSWORD = "E2eTestPass!2024"
NEW_PASSWORD = "E2eTestPass!2025"

passed = 0
failed = []

# 本地通知接收器：验证 Webhook 真正被送达，且不泄露凭证
notifications = []


class CaptureHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length).decode("utf-8", "ignore")
            notifications.append({"path": self.path, "headers": dict(self.headers), "body": body})
        except Exception:
            pass
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, fmt, *args):
        pass


def wait_notify(n, timeout=8):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if len(notifications) >= n:
            return True
        time.sleep(0.1)
    return False


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

    def req(self, method, path, body=None, headers=None, csrf=True, origin=None):
        h = {"Host": f"{BASE_HOST}:{PORT}", "Accept": "application/json"}
        if body is not None:
            h["Content-Type"] = "application/json"
            body = json.dumps(body).encode()
        if self.cookies:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if csrf and self.csrf and method not in ("GET", "HEAD"):
            h["X-CSRF-Token"] = self.csrf
        if origin:
            h["Origin"] = origin
        if headers:
            h.update(headers)
        conn = http.client.HTTPConnection(BASE_HOST, PORT, timeout=30)
        conn.request(method, path, body=body, headers=h)
        r = conn.getresponse()
        data = r.read()
        raw_headers = r.getheaders()
        for k, v in raw_headers:
            if k.lower() == "set-cookie":
                first = v.split(";")[0]
                if "=" in first:
                    ck, cv = first.split("=", 1)
                    if cv == "":
                        self.cookies.pop(ck, None)
                    else:
                        self.cookies[ck] = cv
        conn.close()
        out = {}
        for k, v in raw_headers:
            out.setdefault(k.lower(), []).append(v)
        return r.status, out, data

    def j(self, method, path, body=None, **kw):
        st, hd, data = self.req(method, path, body, **kw)
        try:
            return st, hd, json.loads(data)
        except Exception:
            return st, hd, data


def wait_job(c, job_id, timeout=40):
    t0 = time.time()
    while time.time() - t0 < timeout:
        st, _, j = c.j("GET", f"/api/jobs/{job_id}")
        if st == 200 and j["job"]["status"] in ("success", "failed", "canceled", "skipped"):
            return j
        time.sleep(0.3)
    return None


def main():
    # 从 zip 解压或在部分 CI 环境里脚本可能丢可执行位，测试启动前补上
    os.chmod(os.path.join(ROOT, "tests", "fake-acme.sh"), 0o755)

    shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(ACME_HOME, exist_ok=True)
    os.makedirs(DATA, exist_ok=True)
    os.makedirs(SYNC_DIR, exist_ok=True)
    os.makedirs(SYNC_DIR2, exist_ok=True)

    notifications.clear()
    notify_server = ThreadingHTTPServer(("127.0.0.1", 0), CaptureHandler)
    notify_port = notify_server.server_address[1]
    threading.Thread(target=notify_server.serve_forever, daemon=True).start()

    env = dict(os.environ)
    env.update({
        "ACME_PANEL_LISTEN": f"{BASE_HOST}:{PORT}",
        "ACME_HOME": ACME_HOME,
        "ACME_BIN": ACME_BIN,
        "ACME_PANEL_DATA": DATA,
        "ACME_PANEL_USER": "admin",
        "ACME_PANEL_PASSWORD": PASSWORD,
        "ACME_PANEL_ALLOW_LOCAL_WEBHOOK": "1",
        "ACME_PANEL_CRON": "0",
        "ACME_PANEL_CA": "letsencrypt",
        "ACME_PANEL_SYNC_DIR": SYNC_DIR + "," + SYNC_DIR2,
        "TZ": "Asia/Shanghai",
    })
    log = open(WORK + "/panel.log", "w+")
    proc = subprocess.Popen([BIN], env=env, stdout=log, stderr=subprocess.STDOUT)
    try:
        ok = False
        for _ in range(80):
            try:
                c = Client()
                st, _, _ = c.req("GET", "/api/health")
                if st == 200:
                    ok = True
                    break
            except Exception:
                pass
            time.sleep(0.15)
        check("服务启动 /api/health", ok)
        if not ok:
            log.seek(0)
            print(log.read())
            return 1

        anon = Client()

        # ---- 基础安全头 ----
        st, hd, body = anon.req("GET", "/")
        check("首页 200", st == 200)
        csp = " ".join(hd.get("content-security-policy", []))
        check("CSP 存在且禁止内联脚本", "script-src 'self'" in csp and "frame-ancestors 'none'" in csp, csp)
        check("X-Frame-Options=DENY", hd.get("x-frame-options") == ["DENY"])
        check("X-Content-Type-Options=nosniff", hd.get("x-content-type-options") == ["nosniff"])
        html = body.decode("utf-8", "ignore")
        check("页面无内联事件处理器", "onclick=" not in html and "<script>" not in html)
        check("页面无内联 style（严格 CSP 兼容）", 'style="' not in html)
        check("赞赏码支持点击放大", 'qr-zoom' in html and 'class="support-qr"' in html)
        check("维护者替换图片说明已删除", "维护者替换图片" not in html)
        st, hd2, js = anon.req("GET", "/app.js")
        check("静态资源可访问", st == 200 and b"api(" in js)
        st, hd_img, img = anon.req("GET", "/assets/wechat-pay.png")
        check("赞赏码图片已内嵌到二进制", st == 200 and len(img) > 1000, st)

        # ---- 未登录 ----
        st, hd, _ = anon.req("GET", "/api/certs")
        check("未登录访问证书接口 → 401", st == 401, st)
        check("API 响应 no-store", hd.get("cache-control") == ["no-store"])
        check("面板不下发 HSTS（由反代负责）", "strict-transport-security" not in hd, hd.get("strict-transport-security"))
        st, hd_xfp, _ = anon.req("GET", "/api/certs", headers={"X-Forwarded-Proto": "https"})
        check("收到 X-Forwarded-Proto 也不下发 HSTS", "strict-transport-security" not in hd_xfp, hd_xfp.get("strict-transport-security"))

        # ---- 同源校验（反代端口差异）----
        # nginx 反代常把 Host 设为不带端口的主机名，浏览器 Origin 带端口；
        # 按主机名比较才不会把合法登录误判为跨站（登录登不进的根因）。
        origin_port = f"http://{BASE_HOST}:{PORT}"
        rp = Client()
        st, _, j = rp.j("POST", "/api/login", {"username": "admin", "password": PASSWORD},
                        headers={"Host": BASE_HOST, "Origin": origin_port})
        check("反代 Host 无端口+Origin 带端口仍可登录", st == 200, (st, j))

        # HTTPS 反代：浏览器 Origin 为 https，后端仍收到 HTTP 请求
        https_rp = Client()
        st, _, j = https_rp.j("POST", "/api/login", {"username": "admin", "password": PASSWORD},
                              headers={"Host": BASE_HOST, "Origin": f"https://{BASE_HOST}"})
        check("HTTPS 反代 Origin 仍可登录", st == 200, (st, j))

        # nginx 未透传 Host 时，X-Forwarded-Host 是公网域名
        xfh = Client()
        st, _, j = xfh.j("POST", "/api/login", {"username": "admin", "password": PASSWORD},
                         headers={"Host": "127.0.0.1:8080", "X-Forwarded-Host": BASE_HOST,
                                  "Origin": f"https://{BASE_HOST}"})
        check("内网 Host + X-Forwarded-Host 仍可登录", st == 200, (st, j))

        cross = Client()
        st, _, j = cross.j("POST", "/api/login", {"username": "admin", "password": PASSWORD},
                           headers={"Host": BASE_HOST, "Origin": "http://evil.example.net"})
        check("跨站 Origin 登录被拒", st == 403, (st, j))

        # ---- 登录失败 ----
        st, _, j = anon.j("POST", "/api/login", {"username": "admin", "password": "wrong-pass"})
        check("错误密码 → 401", st == 401, st)

        # ---- 登录成功 ----
        c = Client()
        st, hd, j = c.j("POST", "/api/login", {"username": "admin", "password": PASSWORD})
        check("正确密码登录成功", st == 200 and j.get("user") == "admin", (st, j))
        c.csrf = j.get("csrf")
        sc = " ".join(hd.get("set-cookie", []))
        check("Cookie HttpOnly", "HttpOnly" in sc, sc)
        check("Cookie 为普通 Cookie（不带 SameSite）", "SameSite" not in sc and "samesite" not in sc, sc)
        check("Cookie 不带 Secure（HTTP/HTTPS 反代通用）", "; Secure" not in sc and "; secure" not in sc, sc)
        check("登录返回 CSRF token", bool(c.csrf))

        # 每日检测时间可配置
        st, _, j = c.j("GET", "/api/session")
        check("会话返回每日检测时间", j.get("cron_hour") == 3, j.get("cron_hour"))
        check("会话返回上次检测日期字段", "cron_last_day" in j, j.get("cron_last_day"))
        check("会话显示密码来源", j.get("password_source") == "env", j.get("password_source"))
        check("会话显示凭据来源 env", j.get("cred_source") == "env", j.get("cred_source"))
        st, _, j = c.j("GET", "/api/storage")
        check("存储信息接口可用", st == 200 and str(j.get("path", "")).endswith("panel.db"), (st, j))
        check("SQLite 记录数可见", all(k in j for k in ("jobs", "audit", "sync_events", "sync_seen")), j)
        st, _, j = c.j("POST", "/api/cron/schedule", {"hour": 5})
        check("每日检测时间可保存", st == 200, (st, j))
        st, _, j = c.j("GET", "/api/session")
        check("检测时间保存后可读回", j.get("cron_hour") == 5, j.get("cron_hour"))
        st, _, j = c.j("POST", "/api/cron/schedule", {"hour": 25})
        check("非法小时被拒绝", st == 400, st)
        c.j("POST", "/api/cron/schedule", {"hour": 3})

        st, _, j = c.j("GET", "/api/update/check")
        check("更新检测接口可用", st == 200 and "current" in j, (st, j))
        check("更新检测返回频次字段", "interval" in j and "auto_check" in j, j)
        check("默认每天自动检测", j.get("interval") == "daily" and j.get("auto_check") is True, j)
        check("默认未检测时无新版本", j.get("need_update") in (False, None), j)

        # 自动更新配置：频次校验、持久化与会话回读
        st, _, j = c.j("POST", "/api/update/settings", {"auto_check": False, "interval": "weekly"})
        check("更新检测设置可保存", st == 200 and j.get("interval") == "weekly" and j.get("auto_check") is False, (st, j))
        st, _, j = c.j("GET", "/api/session")
        check("会话返回更新检测配置", j.get("update", {}).get("interval") == "weekly", j.get("update"))
        st, _, _ = c.j("POST", "/api/update/settings", {"interval": "bogus"})
        check("非法检测频次被拒绝", st == 400, st)
        st, _, _ = c.j("POST", "/api/update/settings", {"auto_check": True, "interval": "daily"})
        check("恢复默认检测设置", st == 200, st)

        # 强制检测走实时刷新（GitHub 不可达时也应返回结构完整的响应，不影响面板）
        st, _, j = c.j("GET", "/api/update/check?force=1")
        check("强制检测返回完整字段", st == 200 and all(k in j for k in ("current", "ok", "last_check")), (st, j))

        # ---- 本地/远程同步记录拆分、独立强制推送 ----
        st, _, j = c.j("GET", "/api/sync/rules")
        check("本地与远程记录分开返回", "events" in j and "remote_events" in j, list(j)[:6])
        check("远程记录初始为空", not j.get("remote_events"), j.get("remote_events"))
        st, _, j = c.j("POST", "/api/remote/push", {})
        check("普通远程推送接口可用", st == 200 and j.get("ok") is True, (st, j))
        check("远程推送默认普通模式", j.get("force") is False, j.get("force"))
        check("远程推送返回跳过数量", isinstance(j.get("skipped"), int), j.get("skipped"))
        pushed = (j.get("remote_events") or []) + (j.get("events") or [])
        check("远程推送结果仅含远程记录", all(x.get("scope") == "remote" for x in pushed), pushed)
        st, _, j = c.j("POST", "/api/remote/push", {"force": True})
        check("强制远程推送接口可用", st == 200 and j.get("ok") is True and j.get("force") is True, (st, j))
        pushed = (j.get("remote_events") or []) + (j.get("events") or [])
        check("强制推送结果仅含远程记录", all(x.get("scope") == "remote" for x in pushed), pushed)
        st, _, j = c.j("GET", "/api/sync/rules")
        check("远程记录区不混入本地写入结果",
              all(x.get("scope") == "remote" for x in j.get("remote_events") or []),
              j.get("remote_events"))

        # ---- SQLite 数据保留与手动清理 ----
        st, _, j = c.j("GET", "/api/session")
        check("会话返回数据保留天数", j.get("retention_days") == 30, j.get("retention_days"))
        st, _, j = c.j("POST", "/api/retention", {"days": 7})
        check("保留天数可保存", st == 200, (st, j))
        st, _, j = c.j("GET", "/api/session")
        check("保留天数可读回", j.get("retention_days") == 7, j.get("retention_days"))
        st, _, j = c.j("POST", "/api/retention", {"days": -1})
        check("非法保留天数被拒绝", st == 400, st)
        tz8 = datetime.timezone(datetime.timedelta(hours=8))
        old_ts = (datetime.datetime.now(tz8) - datetime.timedelta(days=40)).isoformat(timespec="seconds")
        con = sqlite3.connect(os.path.join(DATA, "panel.db"))
        con.execute("INSERT INTO audit(ts,user,ip,action,detail) VALUES(?,?,?,?,?)",
                    (old_ts, "test", "127.0.0.1", "old_event", "old"))
        con.commit()
        con.close()
        st, _, j = c.j("POST", "/api/cleanup", {})
        check("手动清理可用", st == 200, (st, j))
        con = sqlite3.connect(os.path.join(DATA, "panel.db"))
        left = con.execute("SELECT COUNT(*) FROM audit WHERE action='old_event'").fetchone()[0]
        con.close()
        check("过期审计记录被清理", left == 0, left)
        c.j("POST", "/api/retention", {"days": 30})

        # 保持登录：cookie MaxAge 应为 90 天
        remember = Client()
        st, hd, j = remember.j("POST", "/api/login", {"username": "admin", "password": PASSWORD, "remember": True})
        sc2 = " ".join(hd.get("set-cookie", []))
        check("保持登录可用", st == 200, st)
        check("保持登录 Cookie 有效期 90 天", "Max-Age=7776000" in sc2, sc2)

        # ---- CSRF ----
        st, _, _ = c.req("POST", "/api/renew-all", {}, csrf=False)
        check("缺少 CSRF → 403", st == 403, st)
        st, _, _ = c.req("POST", "/api/renew-all", {}, origin="http://evil.example")
        check("跨站 Origin → 403", st == 403, st)

        # ---- 参数校验 ----
        st, _, j = c.j("POST", "/api/issue", {"domains": ["not_a_domain"], "code": "dns_ali", "env": {"Ali_Key": "a", "Ali_Secret": "b"}})
        check("非法域名 → 400", st == 400, (st, j))
        st, _, j = c.j("POST", "/api/issue", {"domains": ["example.com"], "code": "dns_evil", "env": {}})
        check("非白名单 provider → 400", st == 400, (st, j))
        st, _, j = c.j("POST", "/api/issue", {"domains": ["example.com"], "code": "dns_ali", "env": {"Ali_Key": "a"}})
        check("缺少必填凭证 → 400", st == 400, (st, j))
        st, _, j = c.j("POST", "/api/issue", {"domains": ["example.com"], "code": "dns_ali",
                                             "env": {"Ali_Key": "k", "Ali_Secret": "s", "PATH": "/evil"}})
        check("未知环境变量字段被拒绝", st == 400, (st, j))
        st, _, j = c.j("POST", "/api/issue", {"domains": ["example.com"], "code": "dns_ali",
                                             "env": {"Ali_Key": "a", "Ali_Secret": "b"}, "dns_sleep": 601})
        check("dns_sleep 超上限 → 400", st == 400, (st, j))
        st, _, j = c.j("POST", "/api/issue", {"domains": ["example.com"], "code": "dns_ali",
                                             "env": {"Ali_Key": "a", "Ali_Secret": "b"}, "dns_sleep": -1})
        check("dns_sleep 负数 → 400", st == 400, (st, j))

        # ---- 默认邮箱与通知渠道 ----
        st, _, _ = c.j("POST", "/api/notify/default-email", {"email": "default@example.com"})
        check("保存默认邮箱", st == 200, st)
        st, _, j = c.j("GET", "/api/session")
        check("会话返回默认邮箱", j.get("default_email") == "default@example.com", j.get("default_email"))

        target = "http://127.0.0.1:%d/hook" % notify_port
        st, _, j = c.j("POST", "/api/notify", {
            "name": "test-hook", "kind": "generic", "target": target,
            "secret": "notify-token-test",
            "events": ["cert_issued", "issue_failed", "cert_expiring", "security_alert"],
            "enabled": True,
        })
        check("创建通知渠道", st == 200, (st, j))
        nid = j.get("id") if st == 200 else ""

        # 新增的同步事件必须能保存（用户反馈的 bug）
        st, _, j = c.j("POST", "/api/notify", {
            "name": "sync-events", "kind": "generic", "target": target,
            "secret": "", "events": ["cert_synced", "sync_failed"], "enabled": True})
        check("同步成功/失败事件可保存", st == 200, (st, j))
        if st == 200:
            sync_nid = j.get("id")
            st, _, j = c.j("GET", "/api/notify")
            nv = next((x for x in j.get("notifiers", []) if x.get("id") == sync_nid), {})
            check("同步事件保存后可读回", set(nv.get("events", [])) == {"cert_synced", "sync_failed"}, nv.get("events"))
            c.j("DELETE", "/api/notify/" + sync_nid)

        st, _, j = c.j("GET", "/api/notify")
        nview = next((x for x in j.get("notifiers", []) if x.get("name") == "test-hook"), {})
        masked_dump = json.dumps(nview, ensure_ascii=False)
        check("渠道只回掩码（token）", "notify-token-test" not in masked_dump and "••" in masked_dump, masked_dump)
        check("渠道只回掩码（URL）", target not in masked_dump, masked_dump)
        db_path = os.path.join(DATA, "panel.db")
        check("持久化已迁移到 SQLite", os.path.exists(db_path), "缺少 panel.db")
        con = sqlite3.connect(db_path)
        state_raw = con.execute("SELECT value FROM state WHERE key='main'").fetchone()[0]
        con.close()
        check("渠道凭证加密落盘（SQLite）", "notify-token-test" not in state_raw and target not in state_raw)

        notifications.clear()
        if nid:
            st, _, _ = c.j("POST", "/api/notify/" + nid + "/test", {})
            check("测试通知成功", st == 200, st)
            check("收到测试通知", wait_notify(1) and "acmesh-panel 通知测试" in notifications[0]["body"], notifications[:1])
            check("Bearer token 随通知传递",
                  "notify-token-test" in notifications[0]["headers"].get("Authorization", ""),
                  notifications[0]["headers"].get("Authorization"))
        else:
            check("测试通知成功", False, "未拿到渠道 id")

        # ---- 签发 ----
        st, _, j = c.j("POST", "/api/issue", {
            "domains": ["example.com", "*.example.com"],
            "code": "dns_ali",
            "env": {"Ali_Key": "test-key", "Ali_Secret": "test-secret"},
            "keylength": "ec-256",
            "ca": "letsencrypt",
            "save_as": "ali-test",
            "email": "domain@example.com",
            "dns_sleep": 30,
        })
        check("签发请求被接受", st == 202, (st, j))
        notifications.clear()
        job = wait_job(c, j["job"]["id"])
        check("签发任务成功", job and job["job"]["status"] == "success", job and job["job"]["status"])
        check("签发成功通知已推送",
              wait_notify(1) and any("签发成功" in x["body"] for x in notifications),
              [x["body"][:80] for x in notifications])
        args_file = os.path.join(ACME_HOME, "last-issue.args")
        if os.path.exists(args_file):
            with open(args_file) as fh:
                issue_args = fh.read()
            check("签发使用域名专属邮箱",
                  "--accountemail" in issue_args and "domain@example.com" in issue_args,
                  issue_args.splitlines())
            check("签发传递 dnssleep 跳过公共 DNS 轮询",
                  "--dnssleep" in issue_args and "30" in issue_args,
                  issue_args.splitlines())
        else:
            # 签发失败时给出任务日志，避免只看到 FileNotFoundError 无从定位
            check("签发使用域名专属邮箱", False,
                  ("任务日志: " + "\n".join(job.get("logs", []))) if job else "无任务日志")
        logs = "\n".join(job["logs"]) if job else ""
        check("日志不含凭证明文", "test-secret" not in logs and "test-key" not in logs)

        st, _, j = c.j("GET", "/api/certs")
        certs = {x["domain"]: x for x in j.get("certs", [])}
        check("证书出现在列表", "example.com" in certs, list(certs))
        ci = certs.get("example.com", {})
        check("ECC 证书被识别", ci.get("is_ecc") is True and ci.get("key_type") == "ECDSA",
              (ci.get("is_ecc"), ci.get("key_type")))
        check("解析出 SAN", "*.example.com" in ci.get("sans", []), ci.get("sans"))
        check("私钥存在标记", ci.get("has_key") is True)
        check("证书带域名专属邮箱", ci.get("email") == "domain@example.com", ci.get("email"))

        st, _, _ = c.j("POST", "/api/certs/example.com_ecc/email", {"email": ""})
        st, _, j = c.j("GET", "/api/certs")
        ci2 = next((x for x in j.get("certs", []) if x["name"] == "example.com_ecc"), {})
        check("清空域名邮箱后恢复默认", not ci2.get("email"), ci2.get("email"))

        # ---- PEM 读取 ----
        st, hd, body = c.req("GET", "/api/certs/example.com_ecc/pem/fullchain")
        check("读取 fullchain", st == 200 and b"BEGIN CERTIFICATE" in body, st)
        check("PEM 下载为 pem 类型", "x-pem-file" in " ".join(hd.get("content-type", [])))

        # ---- 私钥访问控制 ----
        notifications.clear()
        st, _, _ = c.j("POST", "/api/certs/example.com_ecc/key", {"confirm": "nope"})
        check("私钥未确认 → 403", st == 403, st)
        st, _, _ = c.req("POST", "/api/certs/example.com_ecc/key", {"confirm": "I-UNDERSTAND"}, csrf=False)
        check("私钥无 CSRF → 403", st == 403, st)
        st, _, j = c.j("POST", "/api/certs/example.com_ecc/key", {"confirm": "I-UNDERSTAND"})
        check("确认后返回私钥", st == 200 and "PRIVATE KEY" in j.get("pem", ""), st)
        keyfile = os.path.join(ACME_HOME, "example.com_ecc", "example.com.key")
        mode = oct(os.stat(keyfile).st_mode & 0o777)
        check("私钥文件权限 600（Windows 跳过 POSIX 断言）", os.name == "nt" or mode == "0o600", mode)

        st, _, j = c.j("GET", "/api/audit")
        actions = [e.get("action") for e in j.get("entries", [])]
        check("私钥访问写入审计", "private_key_view" in actions, actions[:8])
        check("审计接口返回总数与下拉数据", all(k in j for k in ("total", "actions", "users")), list(j))
        check("动作下拉包含私钥查看", "private_key_view" in j.get("actions", []), j.get("actions"))
        check("用户下拉包含 admin", "admin" in j.get("users", []), j.get("users"))
        check("私钥查看触发安全告警",
              wait_notify(1) and any("私钥被查看" in x["body"] for x in notifications),
              [x["body"][:70] for x in notifications])

        # ---- 审计筛选与分页 ----
        st, _, j = c.j("GET", "/api/audit?action=private_key_view")
        check("按动作筛选命中私钥记录", st == 200 and j.get("total", 0) >= 1
              and all(e["action"] == "private_key_view" for e in j.get("entries", [])), (st, j.get("total")))
        st, _, j = c.j("GET", "/api/audit?q=admin")
        check("关键词筛选命中", st == 200 and j.get("total", 0) >= 1, (st, j.get("total")))
        st, _, j = c.j("GET", "/api/audit?q=%E4%B8%8D%E5%AD%98%E5%9C%A8%E7%9A%84%E5%85%B3%E9%94%AE%E8%AF%8Dxyz")
        check("无匹配关键词返回 0 条", st == 200 and j.get("total") == 0 and not j.get("entries"), (st, j))
        st, _, j = c.j("GET", "/api/audit?user=admin&limit=2&offset=0")
        check("分页返回 limit 条", st == 200 and len(j.get("entries", [])) <= 2, (st, len(j.get("entries", []))))
        check("分页返回总数", j.get("total", -1) >= 0, j.get("total"))
        st, _, j = c.j("GET", "/api/audit?from=2099-01-01")
        check("日期范围筛选生效", st == 200 and j.get("total") == 0, (st, j.get("total")))

        # ---- 路径穿越 ----
        for p in ["/api/certs/..%2F..%2Fetc/pem/cert",
                  "/api/certs/%2e%2e%2fetc/pem/cert",
                  "/api/certs/....%2F%2Fetc%2Fpasswd/pem/cert"]:
            st, _, body = c.req("GET", p)
            check(f"路径穿越被拦截 {urllib.parse.unquote(p)}", st != 200 and b"PRIVATE KEY" not in body, st)

        # ---- 静态资源路径穿越 ----
        st, _, body = c.req("GET", "/../etc/passwd")
        check("静态目录穿越被拦截", st != 200 and b"root:" not in body, st)

        # ---- 引用凭证签发（已保存凭证） ----
        st, _, j = c.j("POST", "/api/issue", {"domains": ["demo.org"], "credential": "ali-test", "keylength": "2048"})
        check("使用已保存凭证签发", st == 202, (st, j))
        job = wait_job(c, j["job"]["id"])
        check("已保存凭证签发成功", job and job["job"]["status"] == "success")

        # ---- 凭证列表掩码 ----
        st, _, j = c.j("GET", "/api/providers")
        saved = {s["name"]: s for s in j.get("saved", [])}
        check("凭证已保存", "ali-test" in saved)
        masked_vals = " ".join(saved.get("ali-test", {}).get("masked", {}).values())
        check("凭证只返回掩码", "test-secret" not in masked_vals and "••" in masked_vals, masked_vals)
        dynu = next((p for p in j.get("catalog", []) if p.get("code") == "dns_dynu"), None)
        check("Dynu DNS 服务商可用", dynu is not None, j.get("catalog"))
        check("Dynu 凭证字段正确", dynu is not None and
              {f["name"] for f in dynu.get("fields", [])} == {"Dynu_ClientId", "Dynu_Secret"}, dynu)
        st, _, j = c.j("POST", "/api/providers", {"name": "dynu-test", "code": "dns_dynu",
                                                   "env": {"Dynu_ClientId": "client-id",
                                                           "Dynu_Secret": "dynu-secret"}})
        check("Dynu 凭证可保存", st == 200, (st, j))
        st, _, j = c.j("GET", "/api/providers")
        check("DNS 服务商数量充足", len(j.get("catalog", [])) >= 43, len(j.get("catalog", [])))
        porkbun = next((p for p in j.get("catalog", []) if p.get("code") == "dns_porkbun"), None)
        check("Porkbun 凭证字段正确", porkbun is not None and
              {f["name"] for f in porkbun.get("fields", [])} ==
              {"PORKBUN_API_KEY", "PORKBUN_SECRET_API_KEY"}, porkbun)
        duckdns = next((p for p in j.get("catalog", []) if p.get("code") == "dns_duckdns"), None)
        check("DuckDNS 服务商可用", duckdns is not None, j.get("catalog"))
        check("DuckDNS 凭证字段正确", duckdns is not None and
              {f["name"] for f in duckdns.get("fields", [])} == {"DuckDNS_Token"}, duckdns)
        st, _, j = c.j("POST", "/api/providers", {"name": "duckdns-test", "code": "dns_duckdns",
                                                   "env": {"DuckDNS_Token": "duckdns-token-test"}})
        check("DuckDNS 凭证可保存", st == 200, (st, j))
        st, _, j = c.j("GET", "/api/providers")
        check("所有服务商均带官网链接", st == 200 and
              all(p.get("website", "").startswith("https://") for p in j.get("catalog", [])) and
              len(j.get("catalog", [])) >= 43, j.get("catalog"))
        check("DuckDNS 官网正确", next((p for p in j.get("catalog", []) if p.get("code") == "dns_duckdns"), {}).get("website") == "https://www.duckdns.org/")
        codes = {p.get("code") for p in j.get("catalog", [])}
        check("失效的 acme.sh code 已移除", not ({"dns_do", "dns_gandi", "dns_linode"} & codes), codes)
        check("修正后的 acme.sh code 已就位", {"dns_dgon", "dns_gandi_livedns", "dns_linode_v4"} <= codes, codes)
        check("新增服务商已内置", {"dns_pdns", "dns_nsupdate", "dns_jd", "dns_baidu", "dns_dpi"} <= codes, codes)
        ordered = [p.get("code") for p in j.get("catalog", [])]
        check("服务商目录按 code 字母序返回", ordered == sorted(ordered), ordered[:6])
        st, _, j = c.j("POST", "/api/providers", {"name": "legacy-do-test", "code": "dns_do",
                                                   "env": {"DO_API_KEY": "legacy-token-test"}})
        check("旧 code 保存时自动归一", st == 200, (st, j))
        st, _, j = c.j("GET", "/api/providers")
        saved = next((p for p in j.get("saved", []) if p.get("name") == "legacy-do-test"), None)
        check("旧 code 归一后为 dns_dgon", saved is not None and saved.get("code") == "dns_dgon", saved)

        # ---- 续期 ----
        st, _, j = c.j("POST", "/api/certs/example.com_ecc/renew", {"force": True})
        check("续期请求被接受", st == 202, st)
        job = wait_job(c, j["job"]["id"])
        check("续期成功", job and job["job"]["status"] == "success")

        # ---- 部署 ----
        st, _, j = c.j("POST", "/api/certs/example.com_ecc/install", {})
        check("部署请求被接受", st == 202, st)
        job = wait_job(c, j["job"]["id"])
        out = os.path.join(DATA, "output", "example.com_ecc")
        check("部署成功", job and job["job"]["status"] == "success")
        check("产出 key.pem / fullchain.pem",
              os.path.exists(os.path.join(out, "key.pem")) and os.path.exists(os.path.join(out, "fullchain.pem")))

        con = sqlite3.connect(os.path.join(DATA, "panel.db"))
        jobs_saved = [json.loads(r[0]) for r in con.execute("SELECT data FROM jobs")]
        con.close()
        check("任务记录写入 SQLite", len(jobs_saved) >= 1, len(jobs_saved))
        check("落盘任务含历史签发记录", any(x.get("kind") == "issue" for x in jobs_saved), jobs_saved[:2])

        # ---- 证书同步：子域名匹配 + 原子覆盖 ----
        st, _, j = c.j("GET", "/api/sync/catalog")
        check("同步目录已启用", st == 200 and j.get("enabled") is True, j)
        check("同步支持多个目录", len(j.get("dirs", [])) == 2, j.get("dirs"))
        check("目录状态可查询", len(j.get("dir_status", [])) == 2, j.get("dir_status"))
        check("目录读写权限正常", all(x.get("readable") and x.get("writable") for x in j.get("dir_status", [])), j.get("dir_status"))
        files = j.get("files", [])
        check("目录文件列表可读", isinstance(files, list), type(files))
        modes = j.get("modes", [])
        check("匹配模式带通俗说明",
              all(len(x.get("hint", "")) > 10 for x in modes), modes)
        check("同步匹配模式齐全",
              {x["code"] for x in j.get("modes", [])} ==
              {"exact", "subdomain", "wildcard", "filename", "san"}, j.get("modes"))
        check("同步预设规则存在", len(j.get("presets", [])) >= 4, j.get("presets"))

        # 造一个 sub.example.com 的目标证书文件，初始内容故意写假值
        target_cert = os.path.join(SYNC_DIR, "sub.example.com_cert.pem")
        target_key = os.path.join(SYNC_DIR, "sub.example.com_key.pem")
        target2_cert = os.path.join(SYNC_DIR2, "sub.example.com_cert.pem")
        for p in (target_cert, target2_cert):
            with open(p, "w") as f:
                f.write("OLD-CERT-CONTENT")
        with open(target_key, "w") as f:
            f.write("OLD-KEY-CONTENT")

        st, _, j = c.j("GET", "/api/sync/catalog")
        check("目录列表包含刚放进去的目标文件",
              any(x["name"] == "sub.example.com_cert.pem" for x in j.get("files", [])), j.get("files"))
        st, _, j = c.j("POST", "/api/sync/preview", {
            "name": "预览", "enabled": True, "mode": "subdomain",
            "source": "example.com_ecc", "pattern": "",
            "cert_tmpl": "{domain}_cert.pem", "key_tmpl": "{domain}_key.pem"})
        check("规则预览接口可用", st == 200 and isinstance(j.get("matched"), list), (st, j))
        check("预览命中两个目录的目标",
              {os.path.normpath(x["dir"]) for x in j.get("matched", [])} ==
              {os.path.normpath(SYNC_DIR), os.path.normpath(SYNC_DIR2)},
              j.get("matched"))
        check("预览按文件类型区分 key 与证书",
              {x["kind"] for x in j.get("matched", [])} == {"key", "cert"},
              [(x["file"], x["kind"]) for x in j.get("matched", [])])
        with open(os.path.join(ROOT, "README.md")) as f:
            readme_text = f.read()
        check("文档权限修复命令用容器内路径",
              "docker exec -u root acmesh-panel chown -R 10001:10001" in readme_text)
        check("预览不修改目标文件", "OLD-CERT-CONTENT" in open(target_cert).read(), "预览有副作用")

        st, _, j = c.j("POST", "/api/sync/rules", {
            "name": "子域同步", "enabled": True, "mode": "subdomain",
            "source": "example.com_ecc", "pattern": "", "remote_hosts": [],
            "cert_tmpl": "{domain}_cert.pem", "key_tmpl": "{domain}_key.pem"})
        check("保存同步规则", st == 200, (st, j))
        st, _, j = c.j("GET", "/api/sync/rules")
        check("同步规则回显远程主机栏", all("remote_hosts" in x for x in j.get("rules", [])), j.get("rules"))
        st, _, j = c.j("POST", "/api/remote/push", {})
        check("规则未选远程主机时不推送", st == 200 and not j.get("events") and j.get("matched_rules") == 0,
              (st, j.get("events"), j.get("matched_rules")))
        check("未选主机时给出明确提示", bool(j.get("message")), j.get("message"))
        st, _, j = c.j("POST", "/api/sync/run", {})
        check("手动同步被接受", st == 200, (st, j))
        synced = [x for x in j.get("events", []) if x["result"] == "ok"]
        check("同步事件报告成功", len(synced) >= 1, j.get("events"))
        with open(target_cert) as f:
            new_cert = f.read()
        check("目标证书内容已被替换", "OLD-CERT" not in new_cert and "BEGIN CERTIFICATE" in new_cert,
              new_cert[:80])
        with open(target_key) as f:
            new_key = f.read()
        check("目标私钥内容已被替换", "OLD-KEY" not in new_key and "PRIVATE KEY" in new_key,
              new_key[:80])
        with open(target2_cert) as f:
            new_cert2 = f.read()
        check("第二个目录目标也被替换", "OLD-CERT" not in new_cert2 and "BEGIN CERTIFICATE" in new_cert2,
              new_cert2[:80])
        check("私钥文件权限为 600（Windows 跳过 POSIX 断言）",
              os.name == "nt" or (os.stat(target_key).st_mode & 0o777) == 0o600,
              oct(os.stat(target_key).st_mode & 0o777))
        st, _, j = c.j("GET", "/api/sync/events")
        check("同步记录可查询", st == 200 and len(j.get("events") or []) >= 1, j)
        check("同步记录时间为本地时区（非 UTC Z）",
              all(not x["time"].endswith("Z") and "+08:00" in x["time"] for x in j.get("events") or []),
              [x["time"] for x in j.get("events") or []][:3])
        # ---- 同步记录：本地 + 远程合并、筛选、分页 ----
        st, _, j = c.j("GET", "/api/sync/events")
        check("合并记录返回 entries 与 total", st == 200 and isinstance(j.get("entries"), list)
              and isinstance(j.get("total"), int), list(j)[:8])
        check("合并记录数不超过总数", len(j.get("entries") or []) <= j.get("total", 0), j.get("total"))
        check("筛选下拉元数据存在", "results" in j and "scopes" in j, list(j))
        st, _, j2 = c.j("GET", "/api/sync/events?scope=local")
        check("按范围筛选只返回本地记录", st == 200
              and all(x.get("scope") != "remote" for x in j2.get("entries") or []), j2.get("entries"))
        st, _, j3 = c.j("GET", "/api/sync/events?result=ok")
        check("按结果筛选只返回成功记录", st == 200
              and all(x.get("result") == "ok" for x in j3.get("entries") or []), j3.get("entries"))
        st, _, j4 = c.j("GET", "/api/sync/events?from=2099-01-01")
        check("未来日期筛选无匹配", st == 200 and j4.get("total") == 0 and not j4.get("entries"), j4)
        st, _, j5 = c.j("GET", "/api/sync/events?limit=1")
        check("分页 limit 生效", st == 200 and len(j5.get("entries") or []) <= 1, j5.get("entries"))
        st, _, j6 = c.j("GET", "/api/sync/events?q=example.com")
        check("关键词筛选可用", st == 200 and isinstance(j6.get("total"), int), j6.get("total"))
        # 远程目录固定用主机配置：即便请求里带 dir 也不会报错，且不会被采纳
        st, _, j7 = c.j("POST", "/api/remote/files", {"host_id": "no-such-host", "dir": "/etc"})
        check("远程文件接口不接受自定义目录", st == 400 and "远程主机不存在" in str(j7.get("error", "")), (st, j7))

        st, _, j = c.j("DELETE", "/api/sync/events")
        check("同步记录可清空", st == 200, (st, j))
        st, _, j = c.j("GET", "/api/sync/events")
        check("清空后记录为空", not j.get("events"), j.get("events"))

        # ---- 同步去重：证书内容未变化时跳过，强制同步才重写 ----
        st, _, j = c.j("GET", "/api/sync/rules")
        check("证书指纹记录已建立", j.get("seen_count", 0) > 0, j.get("seen_count"))
        with open(target_cert, "w") as f:
            f.write("UNCHANGED-MARKER")
        st, _, j = c.j("POST", "/api/sync/run", {})
        check("内容未变化时跳过", st == 200 and (j.get("skipped") or 0) > 0, j)
        check("跳过时不写同步记录", not [x for x in j.get("events", []) if x["result"] == "ok"],
              j.get("events"))
        check("跳过后目标文件未被覆盖", open(target_cert).read() == "UNCHANGED-MARKER", "被意外重写")
        st, _, j = c.j("POST", "/api/sync/run", {"force": True})
        check("强制同步被接受", st == 200 and j.get("force") is True, (st, j))
        check("强制同步产生成功记录", any(x["result"] == "ok" for x in j.get("events", [])),
              j.get("events"))
        check("强制同步后目标已重写", "BEGIN CERTIFICATE" in open(target_cert).read(), "未重写")
        # 模拟续签：源证书内容变化后，普通同步也应自动重写一次
        src_fullchain = os.path.join(ACME_HOME, "example.com_ecc", "fullchain.cer")
        with open(src_fullchain, "a") as f:
            f.write("\n")
        with open(target_cert, "w") as f:
            f.write("STALE-CERT")
        st, _, j = c.j("POST", "/api/sync/run", {})
        check("证书续签后自动重新同步", "BEGIN CERTIFICATE" in open(target_cert).read(),
              (st, j.get("skipped")))

        # ---- 远程主机：加密存储、掩码回显、keep_key、删除 ----
        FAKE_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEKEYDATA\n-----END OPENSSH PRIVATE KEY-----"
        st, _, j = c.j("POST", "/api/remote/hosts", {"host": {
            "name": "测试主机", "host": "192.0.2.10", "port": 22, "user": "deploy",
            "remote_dir": "/etc/ssl/certs", "key": FAKE_KEY, "enabled": True}})
        check("保存远程主机成功", st == 200, (st, j))
        rid = None
        st, _, j = c.j("GET", "/api/remote/hosts")
        hosts = j.get("hosts") or []
        check("远程主机列表可查询", st == 200 and len(hosts) == 1, j)
        check("私钥不明文回显", st == 200 and "FAKEKEYDATA" not in json.dumps(j), j)
        check("私钥掩码展示", st == 200 and bool(hosts[0].get("key_masked")), hosts)
        rid = hosts[0]["id"]
        # 编辑但不改私钥
        st, _, j = c.j("POST", "/api/remote/hosts", {"host": {
            "id": rid, "name": "测试主机2", "host": "192.0.2.10", "port": 2222,
            "user": "deploy", "remote_dir": "/etc/ssl/certs", "key": "", "enabled": False},
            "keep_key": True})
        check("编辑远程主机保留私钥", st == 200, (st, j))
        st, _, j = c.j("GET", "/api/remote/hosts")
        check("编辑后端口已更新", j["hosts"][0]["port"] == 2222, j)
        con = sqlite3.connect(os.path.join(DATA, "panel.db"))
        state_raw = con.execute("SELECT value FROM state WHERE key='main'").fetchone()[0]
        audit_cnt = con.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
        con.close()
        check("审计日志写入 SQLite", audit_cnt > 0, audit_cnt)
        check("私钥加密落盘（state 无明文）", "FAKEKEYDATA" not in state_raw,
              "state 含明文私钥!" if "FAKEKEYDATA" in state_raw else "")
        # 非法配置被拒绝
        st, _, j = c.j("POST", "/api/remote/hosts", {"host": {
            "name": "bad", "host": "192.0.2.10; rm -rf /", "port": 22, "user": "u",
            "remote_dir": "/tmp", "key": FAKE_KEY, "enabled": True}})
        check("远程主机非法主机名被拒绝", st == 400, (st, j))
        st, _, j = c.j("DELETE", "/api/remote/hosts/" + rid)
        check("删除远程主机成功", st == 200, (st, j))
        st, _, j = c.j("GET", "/api/remote/hosts")
        check("删除后列表为空", not j.get("hosts"), j)

        # ---- 远程主机密码认证：加密落盘、掩码回显、切换认证 ----
        PW_SECRET = "RemotePassw0rd!2026"
        st, _, j = c.j("POST", "/api/remote/hosts", {"host": {
            "name": "密码主机", "host": "192.0.2.11", "port": 22, "user": "deploy",
            "remote_dir": "/etc/ssl/certs", "password": PW_SECRET, "enabled": False}})
        check("密码认证主机可保存", st == 200, (st, j))
        st, _, j = c.j("GET", "/api/remote/hosts")
        pw_host = next((h for h in j.get("hosts", []) if h.get("name") == "密码主机"), {})
        check("认证方式识别为密码", pw_host.get("auth_mode") == "password", pw_host)
        check("密码不明文回显", PW_SECRET not in json.dumps(j), j)
        check("密码掩码展示", bool(pw_host.get("password_masked")), pw_host)
        con = sqlite3.connect(os.path.join(DATA, "panel.db"))
        state_raw = con.execute("SELECT value FROM state WHERE key='main'").fetchone()[0]
        con.close()
        check("密码加密落盘", PW_SECRET not in state_raw, "数据库含明文密码")
        st, _, j = c.j("POST", "/api/remote/hosts", {"host": {
            "name": "双凭证", "host": "192.0.2.12", "port": 22, "user": "u",
            "remote_dir": "/tmp", "key": FAKE_KEY, "password": PW_SECRET, "enabled": False}})
        check("私钥与密码不能同时配置", st == 400, (st, j))
        c.j("DELETE", "/api/remote/hosts/" + pw_host["id"])

        # 文件名模式：另造一个文件，验证 glob 也能命中
        fn_cert = os.path.join(SYNC_DIR, "wildcard-target.pem")
        with open(fn_cert, "w") as f:
            f.write("OLD-FN-CONTENT")
        st, _, j = c.j("POST", "/api/sync/rules", {
            "name": "文件名模式", "enabled": True, "mode": "filename",
            "source": "example.com_ecc", "pattern": "wildcard-*.pem",
            "cert_tmpl": "wildcard-target.pem", "key_tmpl": "{domain}_key.pem"})
        check("保存文件名模式规则", st == 200, (st, j))
        st, _, j = c.j("POST", "/api/sync/run", {})
        check("文件名模式同步成功",
              st == 200 and any(x["result"] == "ok" for x in j.get("events", [])), j)
        with open(fn_cert) as f:
            fn_content = f.read()
        check("文件名模式目标已替换", "OLD-FN" not in fn_content and "BEGIN CERTIFICATE" in fn_content,
              fn_content[:80])

        # ---- 未到续期时间：手动优雅提示、不报错、不通知 ----
        st, _, j = c.j("POST", "/api/issue", {
            "domains": ["skip.example.org"], "credential": "ali-test", "keylength": "ec-256"})
        check("skip 域名签发被接受", st == 202, st)
        if st == 202:
            job = wait_job(c, j["job"]["id"])
            check("skip 域名签发成功", job and job["job"]["status"] == "success",
                  job and job["job"]["status"])

        notifications.clear()
        st, _, j = c.j("POST", "/api/certs/skip.example.org_ecc/renew", {})
        check("手动续期请求被接受（未到期）", st == 202, st)
        if st == 202:
            job = wait_job(c, j["job"]["id"])
            check("未到期续期状态为 skipped 而非 failed",
                  job and job["job"]["status"] == "skipped",
                  job and job["job"]["status"])
            logs = "\n".join(job.get("logs", [])) if job else ""
            check("未到期有优雅提示", "尚未到续期时间" in logs and "下次可续签" in logs, logs[:300])
            check("提示含距过期与可续签时间", "还有" in logs and "2027-02-09" in logs, logs[:300])
            check("未到期不推送失败通知",
                  not any("续期失败" in x["body"] for x in notifications),
                  [x["body"][:60] for x in notifications])
            check("未到期不推送任何续期通知",
                  not any("续期" in x["body"] for x in notifications),
                  [x["body"][:60] for x in notifications])

        # 强制续期应成功
        st, _, j = c.j("POST", "/api/certs/skip.example.org_ecc/renew", {"force": True})
        check("强制续期请求被接受", st == 202, st)
        if st == 202:
            job = wait_job(c, j["job"]["id"])
            check("强制续期成功", job and job["job"]["status"] == "success",
                  job and job["job"]["status"])

        # ---- 签发失败事件 ----
        notifications.clear()
        st, _, j = c.j("POST", "/api/issue", {
            "domains": ["fail.example.org"], "credential": "ali-test", "keylength": "2048"})
        check("失败签发请求被接受", st == 202, st)
        if st == 202:
            job = wait_job(c, j["job"]["id"])
            check("签发失败状态正确", job and job["job"]["status"] == "failed",
                  job and job["job"]["status"])
            check("签发失败通知已推送",
                  wait_notify(1) and any("签发失败" in x["body"] for x in notifications),
                  [x["body"][:80] for x in notifications])

        # ---- 失败任务重试：首次失败的任务可重新执行 ----
        st, _, j = c.j("POST", "/api/issue", {
            "domains": ["flaky.example.org"], "credential": "ali-test", "keylength": "2048"})
        check("可重试签发请求被接受", st == 202, st)
        if st == 202:
            first = wait_job(c, j["job"]["id"])
            check("首次签发失败", first and first["job"]["status"] == "failed",
                  first and first["job"]["status"])
            st2, _, j2 = c.j("POST", "/api/jobs/" + j["job"]["id"] + "/retry", {})
            check("失败任务可重试", st2 == 202, (st2, j2))
            if st2 == 202:
                check("重试生成新任务 ID", j2["job"]["id"] != j["job"]["id"],
                      (j["job"]["id"], j2["job"]["id"]))
                retried = wait_job(c, j2["job"]["id"])
                check("重试后签发成功", retried and retried["job"]["status"] == "success",
                      retried and retried["job"]["status"])
        # 成功任务不可重试
        st, _, j = c.j("GET", "/api/jobs")
        ok_jobs = [x for x in j.get("jobs", []) if x.get("status") == "success"]
        if ok_jobs:
            st3, _, j3 = c.j("POST", "/api/jobs/" + ok_jobs[0]["id"] + "/retry", {})
            check("成功任务不允许重试", st3 == 400, (st3, j3))
        # 不存在的任务不可重试
        st4, _, _ = c.j("POST", "/api/jobs/no-such-job/retry", {})
        check("不存在任务重试被拒绝", st4 == 400, st4)

        # ---- 临期提醒（造一张 20 天后到期的证书）----
        exp_dir = os.path.join(ACME_HOME, "expiring.example.org")
        os.makedirs(exp_dir, exist_ok=True)
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "20",
            "-keyout", os.path.join(exp_dir, "expiring.example.org.key"),
            "-out", os.path.join(exp_dir, "expiring.example.org.cer"),
            "-subj", "/CN=expiring.example.org",
            "-addext", "subjectAltName=DNS:expiring.example.org",
        ], capture_output=True, check=True)
        shutil.copy(os.path.join(exp_dir, "expiring.example.org.cer"), os.path.join(exp_dir, "fullchain.cer"))
        shutil.copy(os.path.join(exp_dir, "expiring.example.org.cer"), os.path.join(exp_dir, "ca.cer"))
        notifications.clear()
        st, _, j = c.j("POST", "/api/renew-all", {})
        check("手动检查全部被接受", st == 202, st)
        job = wait_job(c, j["job"]["id"])
        check("临期提醒已推送",
              wait_notify(1) and any("临期" in x["body"] for x in notifications),
              [x["body"][:80] for x in notifications])

        # ---- 删除通知渠道 ----
        if nid:
            st, _, _ = c.j("DELETE", "/api/notify/" + nid)
            check("删除通知渠道", st == 200, st)

        # ---- 登录限流（独立用户名，不影响 admin）----
        rl = Client()
        last = 0
        for _ in range(6):
            last, _, _ = rl.j("POST", "/api/login", {"username": "nobody", "password": "x"})
        check("连续失败触发 429 锁定", last == 429, last)

        # ---- 修改密码 ----
        st, _, _ = c.j("POST", "/api/password", {"old": "wrong", "new": NEW_PASSWORD})
        check("旧密码错误 → 403", st == 403, st)
        st, _, j = c.j("POST", "/api/password", {"old": PASSWORD, "new": NEW_PASSWORD})
        check("修改密码成功", st == 200, (st, j))
        st, _, j = c.j("GET", "/api/session")
        check("Web 改密码后凭据来源为 web", j.get("cred_source") == "web", j.get("cred_source"))

        c2 = Client()
        st, _, _ = c2.j("POST", "/api/login", {"username": "admin", "password": PASSWORD})
        check("旧密码已失效", st == 401, st)
        st, _, j = c2.j("POST", "/api/login", {"username": "admin", "password": NEW_PASSWORD})
        check("新密码可登录", st == 200, st)
        c2.csrf = j.get("csrf")

        # ---- 退出 ----
        st, _, _ = c2.j("POST", "/api/logout", {})
        check("退出成功", st == 200)
        st, _, _ = c2.req("GET", "/api/certs")
        check("退出后会话失效", st == 401, st)

        # ---- 删除（purge）----
        c3 = Client()
        st, _, j = c3.j("POST", "/api/login", {"username": "admin", "password": NEW_PASSWORD})
        c3.csrf = j.get("csrf")
        st, _, j = c3.j("POST", "/api/certs/example.com_ecc/remove", {"purge": True})
        check("删除请求被接受", st == 202, st)
        job = wait_job(c3, j["job"]["id"])
        time.sleep(0.8)
        check("证书目录已删除", not os.path.exists(os.path.join(ACME_HOME, "example.com_ecc")))
        st, _, j = c3.j("GET", "/api/certs")
        check("列表不再包含该证书", all(x["domain"] != "example.com" for x in j.get("certs", [])))

        # ---- 配置备份 / 恢复 ----
        st, hd, body = c3.req("GET", "/api/backup")
        check("备份导出返回下载头", st == 200 and "attachment" in str(hd.get("content-disposition", "")), (st, hd))
        try:
            bf = json.loads(body)
        except Exception:
            bf = {}
        check("备份文件格式与版本正确",
              bf.get("format") == "acmesh-panel-backup" and bf.get("version") == 1, bf.get("format"))
        bst = bf.get("state") or {}
        check("备份不含登录账号与密码哈希",
              not bst.get("username") and not bst.get("salt") and not bst.get("hash")
              and bst.get("iter") in (0, None), {k: bst.get(k) for k in ("username", "salt", "hash", "iter")})
        check("备份含同步规则与系统设置", "sync_rules" in bst and "retention_days" in bst, list(bst)[:8])
        st, _, _ = c3.j("POST", "/api/retention", {"days": 3})
        check("恢复前先改动保留天数", st == 200, st)
        st, _, j = c3.j("POST", "/api/backup", bf)
        check("备份恢复成功", st == 200 and j.get("ok") is True, (st, j))
        st, _, j = c3.j("GET", "/api/session")
        check("恢复后会话仍有效（凭据不覆盖）", st == 200, st)
        check("恢复不覆盖凭据来源标记", j.get("cred_source") == "web", j.get("cred_source"))
        check("恢复后配置回到备份时的值", j.get("retention_days") == bst.get("retention_days"),
              (j.get("retention_days"), bst.get("retention_days")))
        st, _, _ = c3.j("POST", "/api/backup", {"format": "not-a-backup"})
        check("非法备份文件被拒绝", st == 400, st)

        # ---- 修改账号（放最后：成功后所有会话失效）----
        st, _, _ = c3.j("POST", "/api/username", {"password": "wrong", "username": "newadmin"})
        check("改账号密码错误 → 403", st == 403, st)
        st, _, _ = c3.j("POST", "/api/username", {"password": NEW_PASSWORD, "username": "1bad"})
        check("非法账号被拒绝", st == 400, st)
        st, _, _ = c3.j("POST", "/api/username", {"password": NEW_PASSWORD, "username": "admin"})
        check("相同账号被拒绝", st == 400, st)
        st, _, j = c3.j("POST", "/api/username", {"password": NEW_PASSWORD, "username": "newadmin"})
        check("修改账号成功", st == 200, (st, j))
        st, _, _ = c3.j("GET", "/api/session")
        check("改账号后旧会话失效", st == 401, st)
        st, _, j = c.j("POST", "/api/login", {"username": "newadmin", "password": NEW_PASSWORD})
        check("新账号可登录", st == 200 and bool(j.get("csrf")), (st, j))
        st, _, _ = c.j("POST", "/api/login", {"username": "admin", "password": NEW_PASSWORD})
        check("旧账号已失效", st == 401, st)
        st, _, j = c.j("GET", "/api/session")
        check("会话返回凭据来源 web（持久生效）", j.get("cred_source") == "web", j.get("cred_source"))
        check("兼容字段同步为 web", j.get("username_source") == "web" and j.get("password_source") == "web",
              (j.get("username_source"), j.get("password_source")))

    finally:
        notify_server.shutdown()
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()

    print()
    total = passed + len(failed)
    print(f"结果: {passed}/{total} 通过")
    if failed:
        print("失败项:")
        for f in failed:
            print("  -", f)
        print("\n--- 服务日志 ---")
        with open(WORK + "/panel.log") as fh:
            print(fh.read()[-4000:])
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
