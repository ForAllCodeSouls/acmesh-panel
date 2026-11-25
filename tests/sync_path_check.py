"""Linux 目标环境的路径/读取逻辑验证（无需 Docker，不改本机环境）。"""
import os
import posixpath
import re
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
passed = 0


def check(name, ok, extra=""):
    global passed
    if not ok:
        raise AssertionError(f"FAIL {name}: {extra}")
    passed += 1
    print(f"  ok - {name}")


def resolve(local_dir, name):
    """与 remote.go resolveSyncLocalPath 等价的 POSIX 实现。"""
    name = name.strip()
    if not name or not posixpath.isabs(local_dir):
        raise ValueError("非法输入")
    base = posixpath.normpath(local_dir)
    full = posixpath.normpath(name if posixpath.isabs(name) else posixpath.join(base, name))
    if not posixpath.isabs(full) or ".." in full.split("/"):
        raise ValueError("路径穿越")
    rel = posixpath.relpath(full, base)
    if rel == ".." or rel.startswith("../"):
        raise ValueError("不在同步目录内")
    return full


with tempfile.TemporaryDirectory() as tmp:
    # 物理文件放在临时目录，逻辑路径按 Linux 容器的 /certs 计算
    vdir = "/certs"
    cert_name = "baihu.loveli.de5.net_cert.pem"
    cert = Path(tmp) / cert_name
    cert.write_text("-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n", encoding="utf-8")
    (Path(tmp) / "baihu.loveli.de5.net_key.pem").write_text("PRIVATE KEY", encoding="utf-8")
    (Path(tmp) / "notes.txt").write_text("ignore", encoding="utf-8")
    vcert = posixpath.join(vdir, cert_name)

    # Go filepath.Join 不会因第二段绝对而重置："/certs" + "/certs/x" => "/certs/certs/x"
    old = posixpath.normpath(vdir.rstrip("/") + "/" + vcert.lstrip("/"))
    check("旧逻辑确实产生双 certs 路径", old == "/certs/certs/" + cert_name, old)

    resolved = resolve(vdir, vcert)
    physical = Path(tmp) / posixpath.relpath(resolved, vdir)
    check("绝对路径解析不再重复目录", resolved == vcert, resolved)
    check("相对文件名解析正确", resolve(vdir, cert_name) == vcert)
    check("证书内容可读", "BEGIN CERTIFICATE" in physical.read_text(encoding="utf-8"))
    for bad in ("/etc/passwd", "../etc/passwd", "  "):
        try:
            resolve(vdir, bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"非法路径未被拒绝: {bad}")
    check("越界/空路径被拒绝", True)

    candidates = [p.name for p in Path(tmp).iterdir()
                  if p.is_file() and p.suffix.lower() in (".pem", ".cer", ".crt", ".key")]
    check("证书候选文件识别", set(candidates) == {cert.name, "baihu.loveli.de5.net_key.pem"}, candidates)

remote_src = (ROOT / "remote.go").read_text(encoding="utf-8")
api_src = (ROOT / "api.go").read_text(encoding="utf-8")
check("后端存在统一路径解析", "func resolveSyncLocalPath" in remote_src)
check("不再直接 filepath.Join(localDir, f)", "filepath.Join(localDir, f)" not in remote_src)
check("强制推送只传文件名", "pushAllRemotes(s.store, dir, names, true" in api_src)
check("记录按 scope 分流", "func splitSyncEvents" in api_src)
check("远程推送响应含 remote_events", '"remote_events": events' in api_src)

print(f"sync path checks: {passed} passed")
