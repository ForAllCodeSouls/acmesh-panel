#!/usr/bin/env python3
"""账号来源专项测试：注册入口已移除；env 只在首次启动时初始化账号密码；
Web 修改的账号密码持久生效、重启不被 env 覆盖；显式重置开关可应急找回。"""
import http.client
import json
import os
import re
import shutil
import subprocess
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.environ.get("E2E_BIN", "/tmp/build/acmesh-panel")
WORK = os.environ.get("E2E_WORK", "/tmp/setup-check")
PORT = int(os.environ.get("E2E_PORT", "18081"))
PASSWORD = "SetupPassw0rd!2026"

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


def req(method, path, body=None, port=PORT):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    headers = {"Content-Type": "application/json"} if body is not None else {}
    conn.request(method, path, json.dumps(body).encode() if body is not None else None, headers)
    res = conn.getresponse()
    raw = res.read().decode("utf-8", "ignore")
    conn.close()
    try:
        data = json.loads(raw)
    except Exception:
        data = {}
    return res.status, data


class Session:
    """带 Cookie + CSRF 的轻量客户端，用于调用需要登录的账号/密码接口。"""

    def __init__(self, port=PORT):
        self.port = port
        self.cookies = {}
        self.csrf = None

    def req(self, method, path, body=None):
        headers = {}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode()
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if self.csrf and method not in ("GET", "HEAD"):
            headers["X-CSRF-Token"] = self.csrf
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request(method, path, body=data, headers=headers)
        res = conn.getresponse()
        raw = res.read().decode("utf-8", "ignore")
        for k, v in res.getheaders():
            if k.lower() == "set-cookie":
                first = v.split(";")[0]
                if "=" in first:
                    ck, cv = first.split("=", 1)
                    if cv == "":
                        self.cookies.pop(ck, None)
                    else:
                        self.cookies[ck] = cv
        conn.close()
        try:
            out = json.loads(raw)
        except Exception:
            out = {}
        if isinstance(out, dict) and out.get("csrf"):
            self.csrf = out["csrf"]
        return res.status, out


def wait_alive(port=PORT):
    for _ in range(100):
        try:
            if req("GET", "/api/health", port=port)[0] == 200:
                return True
        except Exception:
            pass
        time.sleep(0.1)
    return False


def base_env(data_dir, acme_dir, password=None, user=None):
    env = os.environ.copy()
    env.update({
        "ACME_PANEL_LISTEN": f"127.0.0.1:{PORT}",
        "ACME_PANEL_DATA": data_dir,
        "ACME_HOME": acme_dir,
        "ACME_BIN": os.path.join(ROOT, "tests", "fake-acme.sh"),
        "ACME_PANEL_CRON": "0",
        "TZ": "Asia/Shanghai",
    })
    for key in ("ACME_PANEL_PASSWORD", "ACME_PANEL_USER", "ACME_PANEL_RESET_CREDENTIALS"):
        env.pop(key, None)
    if password is not None:
        env["ACME_PANEL_PASSWORD"] = password
    if user is not None:
        env["ACME_PANEL_USER"] = user
    return env


def start(env, logpath):
    os.makedirs(os.path.dirname(logpath), exist_ok=True)
    log = open(logpath, "wb")
    proc = subprocess.Popen([BIN], env=env, stdout=log, stderr=subprocess.STDOUT)
    return proc, log


def stop(proc, log):
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    log.close()


def read_log(path):
    with open(path, encoding="utf-8", errors="ignore") as fh:
        return fh.read()


def main():
    shutil.rmtree(WORK, ignore_errors=True)
    data = os.path.join(WORK, "data")
    acme = os.path.join(WORK, "acme")
    os.makedirs(data)
    os.makedirs(acme)

    # ---- 场景 1：无 env 密码 → 生成随机密码打印日志，可登录 ----
    proc, log = start(base_env(data, acme), os.path.join(WORK, "gen.log"))
    try:
        check("无 env 密码时服务启动", wait_alive())
        st, j = req("GET", "/api/setup/status")
        check("注册状态接口已移除", st == 404, (st, j))
        st, j = req("POST", "/api/setup", {"username": "hack", "password": PASSWORD})
        check("注册接口已移除", st == 404, (st, j))
    finally:
        stop(proc, log)
    content = read_log(os.path.join(WORK, "gen.log"))
    check("启动日志打印初始随机密码", "初始密码" in content, content[:400])
    m = re.search(r"初始密码\s*:\s*(\S+)", content)
    check("日志含可解析的随机密码", bool(m), content[:400])
    if m:
        # 随机密码已写入库，重启（仍无 env）应保留、不重新生成
        proc, log = start(base_env(data, acme), os.path.join(WORK, "gen2.log"))
        try:
            check("随机密码服务再次启动", wait_alive())
            st, j = req("POST", "/api/login", {"username": "admin", "password": m.group(1)})
            check("随机密码可登录", st == 200 and bool(j.get("csrf")), (st, j))
        finally:
            stop(proc, log)

    # ---- 场景 2：全新库由 env 初始化，Web 修改后来源变为 web ----
    data2 = os.path.join(WORK, "data2")
    acme2 = os.path.join(WORK, "acme2")
    os.makedirs(data2)
    os.makedirs(acme2)
    env_user, env_pwd = "adminA", PASSWORD
    proc, log = start(base_env(data2, acme2, password=env_pwd, user=env_user), os.path.join(WORK, "envA.log"))
    try:
        check("env 首次初始化服务启动", wait_alive())
        s = Session()
        st, j = s.req("POST", "/api/login", {"username": env_user, "password": env_pwd})
        check("env 初始化凭据可登录", st == 200 and bool(j.get("csrf")), (st, j))
        st, j = s.req("GET", "/api/session")
        check("会话凭据来源为 env", j.get("cred_source") == "env", j.get("cred_source"))
        check("兼容字段同为 env", j.get("username_source") == "env" and j.get("password_source") == "env",
              (j.get("username_source"), j.get("password_source")))

        web_pwd = "WebChangedPass!2029"
        st, j = s.req("POST", "/api/password", {"old": env_pwd, "new": web_pwd})
        check("Web 修改密码成功", st == 200, (st, j))
        st, j = s.req("GET", "/api/session")
        check("改密码后凭据来源为 web", j.get("cred_source") == "web", j.get("cred_source"))

        web_user = "webadmin"
        st, j = s.req("POST", "/api/username", {"password": web_pwd, "username": web_user})
        check("Web 修改账号成功", st == 200, (st, j))
        s2 = Session()
        st, j = s2.req("POST", "/api/login", {"username": web_user, "password": web_pwd})
        check("Web 新凭据可登录", st == 200 and bool(j.get("csrf")), (st, j))
        st, j = s2.req("GET", "/api/session")
        check("改账号后凭据来源仍为 web", j.get("cred_source") == "web", j.get("cred_source"))
    finally:
        stop(proc, log)

    # ---- 场景 3：换成完全不同的 env 重启，不得覆盖 Web 修改 ----
    proc, log = start(base_env(data2, acme2, password="EnvBPassword!2030", user="envBuser"),
                      os.path.join(WORK, "envB.log"))
    try:
        check("换 env 后服务再次启动", wait_alive())
        st, j = req("POST", "/api/login", {"username": web_user, "password": web_pwd})
        check("Web 修改的账号密码重启后仍生效", st == 200 and bool(j.get("csrf")), (st, j))
        st, _ = req("POST", "/api/login", {"username": "envBuser", "password": "EnvBPassword!2030"})
        check("新 env 值未覆盖数据库凭据", st == 401, st)
        st, _ = req("POST", "/api/login", {"username": env_user, "password": env_pwd})
        check("旧 env 初始化凭据已失效", st == 401, st)
        s3 = Session()
        s3.req("POST", "/api/login", {"username": web_user, "password": web_pwd})
        st, j = s3.req("GET", "/api/session")
        check("重启后凭据来源仍为 web", j.get("cred_source") == "web", j.get("cred_source"))
    finally:
        stop(proc, log)
    check("启动日志未出现覆盖提示", "同步登录" not in read_log(os.path.join(WORK, "envB.log")))

    # ---- 场景 4：显式重置开关可应急找回 ----
    reset_env = base_env(data2, acme2, password="ResetPass!2031", user="resetadmin")
    reset_env["ACME_PANEL_RESET_CREDENTIALS"] = "1"
    proc, log = start(reset_env, os.path.join(WORK, "reset.log"))
    try:
        check("重置开关启动", wait_alive())
        st, j = req("POST", "/api/login", {"username": "resetadmin", "password": "ResetPass!2031"})
        check("重置后 env 凭据可登录", st == 200 and bool(j.get("csrf")), (st, j))
        st, _ = req("POST", "/api/login", {"username": web_user, "password": web_pwd})
        check("重置后原 Web 凭据失效", st == 401, st)
        s4 = Session()
        s4.req("POST", "/api/login", {"username": "resetadmin", "password": "ResetPass!2031"})
        st, j = s4.req("GET", "/api/session")
        check("重置后凭据来源回到 env", j.get("cred_source") == "env", j.get("cred_source"))
    finally:
        stop(proc, log)
    check("重置写入启动日志", "重置登录凭据" in read_log(os.path.join(WORK, "reset.log")))

    # ---- 场景 5：重置开关未配密码时忽略，不破坏现有凭据 ----
    no_pwd_env = base_env(data2, acme2, user="admin")
    no_pwd_env["ACME_PANEL_RESET_CREDENTIALS"] = "1"
    proc, log = start(no_pwd_env, os.path.join(WORK, "reset-nopwd.log"))
    try:
        check("无密码重置开关启动", wait_alive())
        st, j = req("POST", "/api/login", {"username": "resetadmin", "password": "ResetPass!2031"})
        check("未配密码时现有凭据保持可用", st == 200 and bool(j.get("csrf")), (st, j))
    finally:
        stop(proc, log)
    check("未配密码时打印忽略警告", "忽略本次重置" in read_log(os.path.join(WORK, "reset-nopwd.log")))

    print(f"结果: {passed}/{passed + len(failed)} 通过")
    if failed:
        print("失败项:")
        for name in failed:
            print("  - " + name)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
