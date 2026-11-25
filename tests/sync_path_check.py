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
    cert_name = "demo1.example.net_cert.pem"
    cert = Path(tmp) / cert_name
    cert.write_text("-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n", encoding="utf-8")
    (Path(tmp) / "demo1.example.net_key.pem").write_text("PRIVATE KEY", encoding="utf-8")
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
    check("证书候选文件识别", set(candidates) == {cert.name, "demo1.example.net_key.pem"}, candidates)

remote_src = (ROOT / "remote.go").read_text(encoding="utf-8")
api_src = (ROOT / "api.go").read_text(encoding="utf-8")
go_sync_src = (ROOT / "sync.go").read_text(encoding="utf-8")
check("后端存在统一路径解析", "func resolveSyncLocalPath" in remote_src)
check("不再直接 filepath.Join(localDir, f)", "filepath.Join(localDir, f)" not in remote_src)
check("手动远程推送只传文件名", "pushAllRemotesOnce(s.store, dir, names, req.Force" in api_src)
check("远程普通同步按主机去重", "func selectRemoteFiles" in remote_src and "remoteSeenKey(hostID" in remote_src)
check("远程同步按规则匹配文件", "RuleMatchedFiles(rule)" in api_src and "rule.RemoteHosts" in api_src)
check("规则未选主机不远程推送", "len(rule.RemoteHosts) == 0" in api_src)
check("远程目录列表接口存在", '"POST /api/remote/files"' in (ROOT / "main.go").read_text(encoding="utf-8"))
check("记录按 scope 分流", "func splitSyncEvents" in api_src)
check("远程推送响应含 remote_events", '"remote_events": events' in api_src)

main_src = (ROOT / "main.go").read_text(encoding="utf-8")
backup_src = (ROOT / "backup.go").read_text(encoding="utf-8")
store_src = (ROOT / "store.go").read_text(encoding="utf-8")
html_src = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
readme_src = (ROOT / "README.md").read_text(encoding="utf-8")

check("远程目录固定取主机配置、忽略请求值",
      "listRemoteFiles(s.store, h, h.RemoteDir)" in api_src and "_ = req.Dir" in api_src)
check("远程文件返回规则命中类型与内容匹配结果",
      '"matched_kinds": kinds' in api_src
      and '"content_matches": contentMatches' in api_src
      and "func (s *Server) remoteMatchedKinds(remoteNames []string)" in api_src
      and "readRemoteCertFiles(s.store, h, names)" in api_src)
check("远程文件类型来自现有证书的规则预览与文件名匹配",
      "s.sync.Preview(rule)" in api_src and "s.sync.MatchNames(rule, remoteNames)" in api_src
      and "func (e *SyncEngine) MatchNames" in go_sync_src)
check("合并记录筛选函数存在", "func filterSyncEvents(" in api_src and "AllSyncEvents()" in api_src)
check("同步记录接口返回合并结果与总数", '"entries":' in api_src and '"total":' in api_src)
check("备份接口已注册", '"GET /api/backup"' in main_src and '"POST /api/backup"' in main_src)
check("备份导出剔除登录凭据", 'st.Hash = ""' in backup_src and 'st.Salt = ""' in backup_src and 'st.Iter = 0' in backup_src)
check("恢复保留当前 env 凭据", "st.Username = cur.Username" in store_src and "st.Hash = cur.Hash" in store_src)
check("界面不再出现远程推送", "远程推送" not in html_src and "远程推送" not in (ROOT / "web" / "app.js").read_text(encoding="utf-8"))
check("同步记录合并为单一列表", 'id="remote-event-list"' not in html_src and 'id="sync-scope"' in html_src)
check("部署文档废话已删除", "不管用哪种系统，都需要两个文件" not in readme_src)

print(f"sync path checks: {passed} passed")
