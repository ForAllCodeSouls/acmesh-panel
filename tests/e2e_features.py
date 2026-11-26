#!/usr/bin/env python3
"""v0.1.70 新功能端到端测试：真实进程 + 假 acme.sh。

运行方式与 tests/e2e.py 相同，通过环境变量指定可执行文件与工作目录：
  E2E_BIN, E2E_WORK, E2E_ACME_BIN
"""
import http.client
import json
import os
import shutil
import subprocess
import sys
import time

BASE_HOST = "127.0.0.1"
PORT = int(os.environ.get("E2E_PORT", "18082"))
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.environ.get("E2E_BIN", "/tmp/build/acmesh-panel")
ACME_BIN = os.environ.get("E2E_ACME_BIN", os.path.join(ROOT, "tests", "fake-acme.sh"))
WORK = os.environ.get("E2E_WORK", "/tmp/e2e-features")
ACME_HOME = WORK + "/acme"
DATA = WORK + "/data"
SYNC_DIR = WORK + "/certs"
PASSWORD = "E2eFeaturePass!2026"

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
        raw = r.getheaders()
        for k, v in raw:
            if k.lower() == "set-cookie":
                first = v.split(";")[0]
                if "=" in first:
                    ck, cv = first.split("=", 1)
                    if cv == "":
                        self.cookies.pop(ck, None)
                    else:
                        self.cookies[ck] = cv
        conn.close()
        return r.status, data

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

        # ---- 会话管理 ----
        st, j = c.j("GET", "/api/sessions")
        check("会话列表返回当前会话", st == 200 and j.get("total") == 1
              and j["sessions"][0]["current"] is True, (st, j))
        other = Client()
        st, j = other.j("POST", "/api/login", {"username": "admin", "password": PASSWORD})
        check("第二个会话可登录", st == 200, st)
        st, j = c.j("GET", "/api/sessions")
        check("会话列表包含两个会话", j.get("total") == 2, j)
        victim = [s["id"] for s in j["sessions"] if not s["current"]][0]
        st, j = c.j("DELETE", "/api/sessions/" + victim)
        check("强制下线其它会话", st == 200 and j.get("ok") is True, (st, j))
        st, j = c.j("GET", "/api/sessions")
        check("下线后只剩当前会话", j.get("total") == 1, j.get("total"))

        # ---- IP 白名单（本地回环豁免）----
        st, j = c.j("GET", "/api/ip-allowlist")
        check("IP 白名单初始未限制", st == 200 and j.get("configured") is False, (st, j))
        st, j = c.j("POST", "/api/ip-allowlist", {"entries": ["203.0.113.0/24"], "allow_local": True})
        check("保存 CIDR 白名单", st == 200, (st, j))
        st, j = c.j("GET", "/api/session")
        check("回环豁免后仍可访问", st == 200, st)
        st, j = c.j("POST", "/api/ip-allowlist/test", {"ip": "203.0.113.7"})
        check("白名单内 IP 被允许", st == 200 and j.get("allowed") is True, (st, j))
        st, j = c.j("POST", "/api/ip-allowlist/test", {"ip": "198.51.100.7"})
        check("白名单外 IP 被拒绝", st == 200 and j.get("allowed") is False, (st, j))
        st, j = c.j("POST", "/api/ip-allowlist", {"entries": [], "allow_local": True})
        check("清空白名单恢复不限制", st == 200, (st, j))

        # ---- 只读 API Token ----
        st, j = c.j("POST", "/api/tokens", {"name": "e2e-readonly", "scopes": ["certs", "overview"]})
        check("创建只读令牌", st == 201 and j.get("plain", "").startswith("acmp_"), (st, j))
        plain = j.get("plain")
        anon = Client()  # 不带会话 Cookie，只携带令牌
        st, data = anon.req("GET", "/api/certs", headers={"X-API-Token": plain})
        check("令牌可读取授权端点", st == 200, st)
        st, data = anon.req("GET", "/api/tokens", headers={"X-API-Token": plain})
        check("令牌不能访问未授权端点", st == 401, st)
        st, data = anon.req("POST", "/api/tokens", {"name": "x"}, headers={"X-API-Token": plain}, csrf=False)
        check("令牌不能执行写操作", st in (401, 403), st)
        st, j = c.j("GET", "/api/tokens")
        tid = j["tokens"][0]["id"]
        st, j = c.j("DELETE", "/api/tokens/" + tid)
        check("删除令牌", st == 200, (st, j))
        st, data = anon.req("GET", "/api/certs", headers={"X-API-Token": plain})
        check("删除后令牌立即失效", st == 401, st)

        # ---- 健康自检 / 到期看板 / 计划任务 ----
        st, j = c.j("POST", "/api/health/check", {})
        check("健康自检返回结论", st == 200 and j.get("overall") in ("ok", "warn", "fail")
              and len(j.get("checks", [])) >= 5, (st, j))
        st, j = c.j("GET", "/api/health/report")
        check("健康自检历史可查询", st == 200 and len(j.get("history", [])) >= 1, st)
        st, j = c.j("GET", "/api/expiry")
        check("到期看板返回四档", st == 200 and all(k in j.get("counts", {})
              for k in ("expired", "critical", "warning", "valid")), (st, j))
        st, j = c.j("GET", "/api/schedules")
        check("计划任务聚合五类", st == 200 and len(j.get("items", [])) >= 5, st)

        # ---- 自动备份 ----
        st, j = c.j("POST", "/api/backups/config", {"enabled": True, "interval": "daily",
              "hour": 3, "keep": 3, "include_certs": False})
        check("保存自动备份策略", st == 200 and j.get("keep") == 3, (st, j))
        st, j = c.j("POST", "/api/backups/run", {})
        check("手动备份成功", st == 200 and j.get("status") == "ok", (st, j))
        bid = j.get("id")
        st, j = c.j("GET", "/api/backups")
        check("备份列表可读取", st == 200 and len(j.get("records", [])) >= 1, st)
        st, j = c.j("GET", f"/api/backups/{bid}/content")
        check("备份摘要可读取", st == 200 and j.get("format") == "acmesh-panel-backup", (st, j))
        st, j = c.j("DELETE", f"/api/backups/{bid}")
        check("删除备份", st == 200, (st, j))

        # ---- 重试策略 / 配置 Diff ----
        st, j = c.j("POST", "/api/retry/policy", {"enabled": True, "max_attempts": 4,
              "base_delay": 5, "max_delay": 60})
        check("保存退避重试策略", st == 200 and j.get("max_attempts") == 4, (st, j))
        st, j = c.j("GET", "/api/config-diffs")
        check("配置变更 Diff 有记录", st == 200 and j.get("total", 0) >= 4, (st, j.get("total")))
        actions = j.get("actions", [])
        check("Diff 记录包含令牌与白名单动作", "token_create" in actions
              and "ip_allowlist_save" in actions, actions)
        st, data = c.req("GET", "/api/export.csv?kind=diff")
        check("配置变更可导出 CSV", st == 200 and b"\xef\xbb\xbf" in data, st)

        # ---- 通知渠道扩展 ----
        st, j = c.j("GET", "/api/notify/catalog")
        kinds = [k.get("code") for k in j.get("kinds", [])] if isinstance(j.get("kinds"), list) else []
        check("通知目录含 Telegram 与企业微信", "telegram" in kinds and "wecom" in kinds, kinds)

        # ---- ACME 账户 / 批量签发 ----
        st, j = c.j("GET", "/api/acme/accounts")
        check("ACME 账户接口可用", st == 200 and "accounts" in j, (st, j))
        st, j = c.j("POST", "/api/issue/batch", {
            "domains": ["batch1.example.net", "batch2.example.net"],
            "code": "dns_ali", "env": {"Ali_Key": "test-key", "Ali_Secret": "test-secret"},
            "keylength": "ec-256", "ca": "letsencrypt", "dns_sleep": 0, "force": False,
        })
        check("批量签发返回两个任务", st == 202 and j.get("count") == 2, (st, j))
        check("批量任务域名正确", [x["domain"] for x in j.get("jobs", [])] ==
              ["batch1.example.net", "batch2.example.net"], j.get("jobs"))

        # ---- 证书链校验（签发完成后）----
        for _ in range(80):
            st, j = c.j("GET", "/api/jobs")
            jobs = j.get("jobs", [])
            batch = [x for x in jobs if x.get("domain", "").startswith("batch")]
            if len(batch) >= 2 and all(x["status"] in ("success", "failed", "skipped") for x in batch):
                break
            time.sleep(0.25)
        st, j = c.j("GET", "/api/certs")
        certs = j.get("certs", [])
        if certs:
            name = certs[0]["name"]
            st, j = c.j("POST", f"/api/certs/{name}/verify", {})
            check("证书链与私钥校验返回结果", st == 200 and "checks" in j, (st, j))
        else:
            check("证书链与私钥校验返回结果", False, "fake-acme.sh 未生成证书")

        # ---- 语言切换 ----
        st, j = c.j("POST", "/api/locale", {"locale": "ja"})
        check("切换界面语言为日语", st == 200 and j.get("locale") == "ja", (st, j))
        st, j = c.j("GET", "/api/session")
        check("会话接口返回语言设置", j.get("locale") == "ja", j.get("locale"))

        # ---- v0.1.71：静默窗口 ----
        st, j = c.j("GET", "/api/notify/quiet")
        check("静默窗口接口返回配置与状态", st == 200 and "quiet_hours" in j and "active" in j, (st, j))
        st, j = c.j("POST", "/api/notify/quiet", {
            "enabled": True, "start_hour": 0, "end_hour": 23, "days": [], "allow_critical": True,
        })
        check("保存静默窗口", st == 200 and j.get("quiet_hours", {}).get("enabled") is True, (st, j))
        st, j = c.j("GET", "/api/notify/quiet")
        check("静默窗口生效中", j.get("active") is True, j)
        st, j = c.j("POST", "/api/notify/quiet", {
            "enabled": False, "start_hour": 22, "end_hour": 7, "days": [], "allow_critical": True,
        })
        check("关闭静默窗口", st == 200 and j.get("quiet_hours", {}).get("enabled") is False, (st, j))
        st, j = c.j("GET", "/api/config-diffs")
        check("静默配置变更写入 Diff", st == 200 and any(
            d.get("action") == "quiet_hours_save" for d in j.get("items", [])), st)

        # ---- v0.1.71：默认 CA 切换与锁定 ----
        st, j = c.j("GET", "/api/catalog")
        check("目录返回 CA 选项与锁定状态", st == 200 and len(j.get("ca_options", [])) >= 5
              and "ca_locked" in j, (st, j))
        st, j = c.j("POST", "/api/acme/accounts/default", {"ca": "zerossl"})
        check("切换默认 CA 成功", st == 200 and j.get("default_ca") == "zerossl", (st, j))
        st, j = c.j("GET", "/api/catalog")
        check("切换后目录反映新 CA", j.get("default_ca") == "zerossl", j.get("default_ca"))
        st, j = c.j("POST", "/api/acme/accounts/default", {"ca": "not-a-ca"})
        check("非法 CA 被拒绝", st == 400, st)

        # ---- v0.1.71：账户私钥导出需密码 ----
        st, j = c.j("POST", "/api/acme/accounts/key", {"id": "account.conf", "password": "wrong"})
        check("错误密码拒绝导出账户私钥", st == 403, st)
        st, data = c.req("POST", "/api/acme/accounts/key", {"id": "../account.conf", "password": PASSWORD})
        check("越界账户 ID 被拒绝", st == 400, st)
        st, j = c.j("GET", "/api/acme/accounts")
        check("账户摘要不回显私钥内容", st == 200 and all(
            "private_key" not in a for a in j.get("accounts", [])), st)

        # ---- v0.1.71：到期看板批量续期 ----
        st, j = c.j("GET", "/api/expiry")
        check("到期看板返回证书分组", st == 200 and "groups" in j and "counts" in j, (st, j))
        names = []
        for group in j.get("groups", {}).values():
            names.extend(x.get("name") for x in group if x.get("name"))
        if names:
            st, data = c.req("POST", "/api/expiry/renew", {
                "names": names[:2] + ["nonexistent.example.com"], "force": False,
            })
            try:
                rj = json.loads(data)
            except Exception:
                rj = {}
            check("批量续期排队成功并跳过不存在证书", st == 202 and rj.get("queued") == 2
                  and "nonexistent.example.com" in rj.get("skipped", []), (st, rj))
        else:
            check("批量续期排队成功并跳过不存在证书", False, "无证书可用")
        st, data = c.req("POST", "/api/expiry/renew", {"names": []})
        check("批量续期空列表被拒绝", st == 400, st)
        st, data = c.req("POST", "/api/expiry/renew", {"names": ["../etc/passwd"]})
        check("批量续期非法证书名被拒绝", st == 400, st)

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
