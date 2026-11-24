#!/usr/bin/env python3
"""端到端测试：真实启动面板进程 + 假 acme.sh，覆盖认证、CSRF、限流、
签名流程、私钥访问控制、路径穿越与响应头。"""
import http.client
import json
import os
import shutil
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
WORK = "/tmp/e2e"
ACME_HOME = os.path.join(WORK, "acme")
DATA = os.path.join(WORK, "data")
SYNC_DIR = os.path.join(WORK, "certs")
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
        if st == 200 and j["job"]["status"] in ("success", "failed", "canceled"):
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

    notifications.clear()
    notify_server = ThreadingHTTPServer(("127.0.0.1", 0), CaptureHandler)
    notify_port = notify_server.server_address[1]
    threading.Thread(target=notify_server.serve_forever, daemon=True).start()

    env = dict(os.environ)
    env.update({
        "ACME_PANEL_LISTEN": f"{BASE_HOST}:{PORT}",
        "ACME_HOME": ACME_HOME,
        "ACME_BIN": os.path.join(ROOT, "tests", "fake-acme.sh"),
        "ACME_PANEL_DATA": DATA,
        "ACME_PANEL_USER": "admin",
        "ACME_PANEL_PASSWORD": PASSWORD,
        "ACME_PANEL_CRON": "0",
        "ACME_PANEL_CA": "letsencrypt",
        "ACME_PANEL_SYNC_DIR": SYNC_DIR,
    })
    log = open(os.path.join(WORK, "panel.log"), "w+")
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
        st, hd2, js = anon.req("GET", "/app.js")
        check("静态资源可访问", st == 200 and b"api(" in js)
        st, hd_img, img = anon.req("GET", "/assets/wechat-pay.png")
        check("赞赏码图片已内嵌到二进制", st == 200 and len(img) > 1000, st)

        # ---- 未登录 ----
        st, hd, _ = anon.req("GET", "/api/certs")
        check("未登录访问证书接口 → 401", st == 401, st)
        check("API 响应 no-store", hd.get("cache-control") == ["no-store"])

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
        check("Cookie SameSite=Strict", "SameSite=Strict" in sc, sc)
        check("登录返回 CSRF token", bool(c.csrf))

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

        st, _, j = c.j("GET", "/api/notify")
        nview = next((x for x in j.get("notifiers", []) if x.get("name") == "test-hook"), {})
        masked_dump = json.dumps(nview, ensure_ascii=False)
        check("渠道只回掩码（token）", "notify-token-test" not in masked_dump and "••" in masked_dump, masked_dump)
        check("渠道只回掩码（URL）", target not in masked_dump, masked_dump)
        with open(os.path.join(DATA, "state.json")) as fh:
            state_raw = fh.read()
        check("渠道凭证加密落盘", "notify-token-test" not in state_raw and target not in state_raw)

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
        check("私钥文件权限 600", mode == "0o600", mode)

        st, _, j = c.j("GET", "/api/audit")
        actions = [e.get("action") for e in j.get("entries", [])]
        check("私钥访问写入审计", "private_key_view" in actions, actions[:8])
        check("私钥查看触发安全告警",
              wait_notify(1) and any("私钥被查看" in x["body"] for x in notifications),
              [x["body"][:70] for x in notifications])

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

        # ---- 证书同步：子域名匹配 + 原子覆盖 ----
        st, _, j = c.j("GET", "/api/sync/catalog")
        check("同步目录已启用", st == 200 and j.get("enabled") is True, j)
        check("同步匹配模式齐全",
              {x["code"] for x in j.get("modes", [])} ==
              {"exact", "subdomain", "wildcard", "filename", "san"}, j.get("modes"))
        check("同步预设规则存在", len(j.get("presets", [])) >= 4, j.get("presets"))

        # 造一个 baihu.example.com 的目标证书文件，初始内容故意写假值
        target_cert = os.path.join(SYNC_DIR, "baihu.example.com_cert.pem")
        target_key = os.path.join(SYNC_DIR, "baihu.example.com_key.pem")
        with open(target_cert, "w") as f:
            f.write("OLD-CERT-CONTENT")
        with open(target_key, "w") as f:
            f.write("OLD-KEY-CONTENT")

        st, _, j = c.j("POST", "/api/sync/rules", {
            "name": "子域同步", "enabled": True, "mode": "subdomain",
            "source": "example.com_ecc", "pattern": "",
            "cert_tmpl": "{domain}_cert.pem", "key_tmpl": "{domain}_key.pem"})
        check("保存同步规则", st == 200, (st, j))
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
        check("私钥文件权限为 600", (os.stat(target_key).st_mode & 0o777) == 0o600,
              oct(os.stat(target_key).st_mode & 0o777))
        st, _, j = c.j("GET", "/api/sync/events")
        check("同步记录可查询", st == 200 and len(j.get("events", [])) >= 1, j)

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
        with open(os.path.join(WORK, "panel.log")) as fh:
            print(fh.read()[-4000:])
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
