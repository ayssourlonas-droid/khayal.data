"""اختبار شامل: python test_server.py  (يشغّل GitHub مزيّفاً محلياً، ولا يحتاج إنترنت ولا توكن)"""
import base64, hashlib, json, os, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer

os.environ.update(STATS_TOKEN="tok123", HASH_KEY="k" * 32, FLUSH_SECONDS="3600",
                  GH_REPO="me/khayal.data", GH_TOKEN="x", GH_BRANCH="main", GH_PATH="stats/stats.json")

# ── GitHub مزيّف (Contents API مع sha)
FILES = {}
class FakeGH(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _path(self): return self.path.split("?")[0].split("/contents/", 1)[1]
    def _send(self, code, body, ctype="application/json"):
        b = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        p = self._path()
        if p not in FILES: return self._send(404, {"message": "Not Found"})
        raw, sha = FILES[p]
        if "raw" in self.headers.get("Accept", ""): return self._send(200, raw, "application/octet-stream")
        self._send(200, {"sha": sha, "encoding": "base64", "content": base64.b64encode(raw).decode()})
    def do_PUT(self):
        p = self._path(); j = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        cur = FILES.get(p)
        if cur and j.get("sha") != cur[1]: return self._send(409, {"message": "sha mismatch"})
        if not cur and j.get("sha"): return self._send(422, {"message": "bad sha"})
        raw = base64.b64decode(j["content"]); sha = hashlib.sha1(raw).hexdigest()
        FILES[p] = (raw, sha); self._send(201 if not cur else 200, {"content": {"sha": sha}})
srv = HTTPServer(("127.0.0.1", 0), FakeGH); threading.Thread(target=srv.serve_forever, daemon=True).start()
os.environ["GH_API"] = f"http://127.0.0.1:{srv.server_port}"

from fastapi.testclient import TestClient
import main

A = {"Authorization": "Bearer tok123"}
def check(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond: raise SystemExit(1)

dev1, dev2 = "a" * 32, "b" * 32
with TestClient(main.app) as c:
    # ── فتح الألعاب
    check("hit 204", c.post("/hit", json={"slug": "tetris", "id": "1" * 16}).status_code == 204)
    c.post("/hit", json={"slug": "tetris", "id": "1" * 16})               # مكرر: يُتجاهل
    c.post("/hit", json={"slug": "tetris", "id": "2" * 16})
    c.post("/hit", json={"slug": "snake", "id": "3" * 16})
    check("hit رفض slug سيئ", c.post("/hit", json={"slug": "../x", "id": "1" * 16}).status_code == 400)
    check("hit رفض id سيئ", c.post("/hit", json={"slug": "a", "id": "zz"}).status_code == 400)
    # ── الأجهزة
    check("dev 204", c.post("/dev", json={"id": dev1, "v": "2.1.204"}).status_code == 204)
    c.post("/dev", json={"id": dev1, "v": "2.1.204"})                     # نفس اليوم: يُتجاهل
    c.post("/dev", json={"id": dev2, "v": "2.1.203"})
    check("dev رفض id سيئ", c.post("/dev", json={"id": "short", "v": "1"}).status_code == 400)
    # ── الأخطاء
    e = {"app": "games", "v": "2.1.204", "type": "_TypeError", "msg": "null check at https://x.com/a?token=1 mail a@b.com",
         "stack": "#0 foo (a.dart:1)\n#1 bar (b.dart:2)", "ctx": "7", "android": "14 (SDK 34)", "model": "Samsung A16", "fatal": False, "id": dev1}
    check("err 204", c.post("/err", json=e).status_code == 204)
    c.post("/err", json=e); c.post("/err", json={**e, "id": dev2, "model": "Xiaomi 13", "fatal": True})
    check("err رفض بلا id", c.post("/err", json={**e, "id": "bad"}).status_code == 400)
    c.post("/err", json={"app": "games", "v": "1", "type": "Log.warning", "msg": "تحذير", "stack": "", "ctx": "", "android": "", "model": "", "fatal": False, "id": dev1})
    # ── الصلاحيات
    check("stats بلا رمز 401", c.get("/stats").status_code == 401)
    check("stats رمز خاطئ 401", c.get("/stats", headers={"Authorization": "Bearer no"}).status_code == 401)
    check("errors بلا رمز 401", c.get("/errors").status_code == 401)
    # ── /stats
    s = c.get("/stats?days=7", headers=A).json()
    check("stats ألعاب", s["games"] == [{"slug": "tetris", "plays": 2}, {"slug": "snake", "plays": 1}])
    d = s["devices"]
    check("stats أجهزة", (d["total"], d["active"], d["new"]) == (2, 2, 2))
    check("stats daily 7 أيام وآخرها اليوم", len(d["daily"]) == 7 and d["daily"][-1]["active"] == 2 and d["daily"][-1]["new"] == 2 and d["daily"][0]["active"] == 0)
    check("stats إصدارات", {v["ver"]: v["n"] for v in d["versions"]} == {"2.1.204": 1, "2.1.203": 1})
    # ── /errors
    r = c.get("/errors?days=30&all=0", headers=A).json()
    check("errors open=2", r["open"] == 2 and len(r["errors"]) == 2)
    te = [x for x in r["errors"] if x["type"] == "_TypeError"][0]
    check("errors تجميع", te["n"] == 3 and te["devices"] == 2 and te["fatal"] == 1 and te["resolved"] == 0)
    check("errors تنظيف الرابط والبريد", "https" not in te["msg"] and "a@b.com" not in te["msg"] and "<email>" in te["msg"])
    check("errors طُرز الأجهزة", {m["model"]: m["n"] for m in te["models"]} == {"Samsung A16": 2, "Xiaomi 13": 1})
    fp = te["fp"]
    check("resolve", c.post("/errors", headers=A, json={"fp": fp, "action": "resolve"}).status_code == 200)
    check("المحلول يختفي", len(c.get("/errors?days=30&all=0", headers=A).json()["errors"]) == 1)
    check("all=1 يُظهره", len(c.get("/errors?days=30&all=1", headers=A).json()["errors"]) == 2)
    c.post("/err", json=e)
    check("تكرار الخطأ يعيد فتحه", c.get("/errors?all=0", headers=A).json()["open"] == 2)
    check("reopen/delete", c.post("/errors", headers=A, json={"fp": fp, "action": "delete"}).status_code == 200 and c.post("/errors", headers=A, json={"fp": fp, "action": "delete"}).status_code == 404)
    check("action سيئ 400", c.post("/errors", headers=A, json={"fp": "x", "action": "boom"}).status_code == 400)
    check("health GET/HEAD", c.get("/health").status_code == 200 and c.head("/health").status_code == 200)
    check("حد الحجم", c.post("/hit", content=b"{" + b"a" * 9000).status_code == 400)
    # ── الحفظ في GitHub (مزيّف)
    check("flush 1", c.app.state.store.flush(force=True))
    raw, sha1 = FILES["stats/stats.json"]
    snap = json.loads(raw)
    check("اللقطة لا تحوي المعرّف الخام", dev1 not in raw.decode() and dev2 not in raw.decode())
    check("اللقطة تحوي بصمات HMAC من 12 خانة", all(len(k) == 12 for k in snap["dev"]))
    c.post("/hit", json={"slug": "snake", "id": "4" * 16})
    check("flush 2 يحدّث الملف (sha صحيح)", c.app.state.store.flush() and FILES["stats/stats.json"][1] != sha1)
    check("لا تغيير ⇒ لا commit", c.app.state.store.flush() is False)
    # تعارض sha (كأن أحداً غيّر الملف): يتعافى
    FILES["stats/stats.json"] = (FILES["stats/stats.json"][0], "deadbeef")
    c.post("/hit", json={"slug": "snake", "id": "5" * 16})
    check("تعافٍ من تعارض sha", c.app.state.store.flush() and FILES["stats/stats.json"][1] != "deadbeef")

# ── إعادة تشغيل: يجب أن تعود الأرقام من GitHub
with TestClient(main.app) as c2:
    s = c2.get("/stats?days=7", headers=A).json()
    check("بعد إعادة التشغيل: الألعاب", {g["slug"]: g["plays"] for g in s["games"]} == {"tetris": 2, "snake": 3})
    check("بعد إعادة التشغيل: الأجهزة", s["devices"]["total"] == 2)
    c2.post("/dev", json={"id": dev1, "v": "2.1.204"})
    check("جهاز معروف لا يُحسب جديداً بعد إعادة التشغيل", c2.get("/stats", headers=A).json()["devices"]["total"] == 2)
    # حد المعدل
    ok = [c2.post("/hit", json={"slug": "x", "id": f"{i:016x}"}).status_code for i in range(130)]
    check("حد المعدل 429", 429 in ok)

# ── فشل التحميل لا يمسح البيانات
main.time.sleep = lambda s: None
srv.shutdown()
try:
    with TestClient(main.app):
        check("كان يجب أن يفشل التشغيل", False)
except Exception:
    check("فشل تحميل اللقطة يوقف التشغيل (لا كتابة فوق البيانات)", True)
print("\nكل الاختبارات نجحت")
