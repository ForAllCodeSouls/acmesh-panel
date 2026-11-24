#!/usr/bin/env python3
"""首次注册专项测试：无密码时开放，注册后永久关闭，且可正常登录。"""
import http.client
import json
import os
import shutil
import subprocess
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.environ.get("E2E_BIN", "/tmp/build/acmesh-panel")
WORK = "/tmp/setup-check"
PORT = 18081
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


def req(method, path, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=5)
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


def main():
    shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(os.path.join(WORK, "data"))
    os.makedirs(os.path.join(WORK, "acme"))
    env = os.environ.copy()
    env.update({
        "ACME_PANEL_LISTEN": f"127.0.0.1:{PORT}",
        "ACME_PANEL_DATA": os.path.join(WORK, "data"),
        "ACME_HOME": os.path.join(WORK, "acme"),
        "ACME_BIN": os.path.join(ROOT, "tests", "fake-acme.sh"),
        "ACME_PANEL_CRON": "0",
        "TZ": "Asia/Shanghai",
    })
    env.pop("ACME_PANEL_PASSWORD", None)
    log = open(os.path.join(WORK, "server.log"), "wb")
    proc = subprocess.Popen([BIN], env=env, stdout=log, stderr=subprocess.STDOUT)
    try:
        ok = False
        for _ in range(100):
            try:
                if req("GET", "/api/health")[0] == 200:
                    ok = True
                    break
            except Exception:
                pass
            time.sleep(0.1)
        check("服务启动", ok)
        st, j = req("GET", "/api/setup/status")
        check("未设置密码时开放注册", st == 200 and j.get("needed") is True, (st, j))
        st, j = req("POST", "/api/setup", {
            "username": "admin2", "password": "short", "confirm": "short"})
        check("弱密码被拒绝", st == 400, (st, j))
        st, j = req("POST", "/api/setup", {
            "username": "1bad", "password": PASSWORD, "confirm": PASSWORD})
        check("非法用户名被拒绝", st == 400, (st, j))
        st, j = req("POST", "/api/setup", {
            "username": "admin2", "password": PASSWORD, "confirm": "different"})
        check("两次密码不一致被拒绝", st == 400, (st, j))
        st, j = req("POST", "/api/setup", {
            "username": "admin2", "password": PASSWORD, "confirm": PASSWORD})
        check("首次注册成功", st == 200, (st, j))
        st, j = req("GET", "/api/setup/status")
        check("注册后入口关闭", st == 200 and j.get("needed") is False, (st, j))
        st, j = req("POST", "/api/setup", {
            "username": "other", "password": PASSWORD, "confirm": PASSWORD})
        check("二次注册被拒绝", st == 409, (st, j))
        st, j = req("POST", "/api/login", {"username": "admin2", "password": "wrong-pass"})
        check("错误密码无法登录", st == 401, st)
        st, j = req("POST", "/api/login", {"username": "admin2", "password": PASSWORD})
        check("新账号可以登录", st == 200 and bool(j.get("csrf")), (st, j))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()
    print(f"结果: {passed}/{passed + len(failed)} 通过")
    if failed:
        print("失败项:")
        for name in failed:
            print("  - " + name)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
