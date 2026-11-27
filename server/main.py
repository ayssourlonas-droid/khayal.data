"""
سيرفر إحصاءات خيال وأخطائه (بديل Worker على Cloudflare).

الواجهات (نفسها التي يستعملها التطبيقان، فلا يتغير كودهما):
  POST /hit     {slug, id}                        ← فتح لعبة         (من خيال)
  POST /dev     {id, v}                           ← عدّاد الأجهزة    (من خيال)
  POST /err     {app,v,type,msg,stack,ctx,
                 android,model,fatal,id}          ← بلاغ خطأ         (من خيال)
  GET  /stats?days=N                              ← للمتحكم (Bearer STATS_TOKEN)
  GET  /errors?days=N&all=0|1                     ← للمتحكم (Bearer STATS_TOKEN)
  POST /errors  {fp, action: resolve|reopen|delete} ← للمتحكم (Bearer STATS_TOKEN)
  GET  /health                                    ← للمنبّه (cron-job.org)

التخزين: الحالة في الذاكرة، وتُحفظ كل FLUSH_SECONDS (إن تغيّرت) وعند الإيقاف في ملف JSON واحد
داخل مستودع GitHub (GH_REPO/GH_PATH)، وتُقرأ منه عند التشغيل. بلا قاعدة بيانات.

الخصوصية: المعرّفات العشوائية للأجهزة لا تُخزَّن خاماً أبداً، بل بصمة HMAC مقتطعة بمفتاح سري (HASH_KEY).
الملف يحوي أرقاماً مجمَّعة فقط.
"""
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import threading
import time
from collections import OrderedDict, defaultdict, deque
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta, timezone
from urllib.parse import quote

import requests
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse

log = logging.getLogger("khayal-stats")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

SCHEMA = 1
MAX_BODY = 8192
MAX_SLUGS = 1000
MAX_ERRORS = 500
MAX_DEVS_PER_ERROR = 300
MAX_MODELS_PER_ERROR = 30
MAX_DEVICES = 500_000
PLAYS_KEEP_DAYS = 400
DAILY_KEEP_DAYS = 800
ERRORS_KEEP_DAYS = 120
RATE_LIMIT = 120          # طلب لكل دقيقة لكل عنوان IP (مشترك بين /hit و/dev و/err)

_HEX16 = re.compile(r"^[0-9a-f]{16}$")
_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_SLUG = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
_APP = re.compile(r"^[a-z0-9_-]{1,20}$")
_VER = re.compile(r"^[\w.+-]{1,20}$")
_URL = re.compile(r"https?://([^/\s]+)\S*")
_MAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_EPOCH = date(1970, 1, 1)


# ───────────────────────── أدوات ─────────────────────────
def utc_today() -> date:
    return datetime.now(timezone.utc).date()


def eday(d: date) -> int:
    return (d - _EPOCH).days


def now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")


def clean(s, n: int) -> str:
    s = "" if s is None else str(s)
    s = _URL.sub(r"\1", s)
    s = _MAIL.sub("<email>", s)
    s = _CTRL.sub("", s)
    return s[:n]


def fingerprint(app: str, typ: str, msg: str, stack: str) -> str:
    lines = [l for l in stack.split("\n") if l.strip()][:3]
    base = f"{app}|{typ}|{'|'.join(lines)}|{'' if stack else msg}"
    return hashlib.sha1(base.encode("utf-8")).hexdigest()[:12]


class Settings:
    def __init__(self):
        e = os.environ.get
        self.stats_token = e("STATS_TOKEN", "")
        self.hash_key = e("HASH_KEY", "")
        self.flush_seconds = int(e("FLUSH_SECONDS", "600"))
        self.gh_token = e("GH_TOKEN", "")
        self.gh_repo = e("GH_REPO", "")
        self.gh_branch = e("GH_BRANCH", "main")
        self.gh_path = e("GH_PATH", "stats/stats.json")
        self.gh_api = e("GH_API", "https://api.github.com")
        self.local_file = e("DATA_FILE", "stats.json")


# ───────────────────────── التخزين ─────────────────────────
class LocalBackend:
    def __init__(self, path):
        self.path = path

    def load(self):
        if not os.path.exists(self.path):
            return None
        with open(self.path, "rb") as f:
            return json.loads(f.read().decode("utf-8"))

    def save(self, data):
        tmp = self.path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
        os.replace(tmp, self.path)


class GitHubBackend:
    def __init__(self, token, repo, branch, path, api="https://api.github.com"):
        self.token, self.repo, self.branch, self.path, self.api = token, repo, branch, path, api.rstrip("/")
        self.sha = None
        self.url = f"{self.api}/repos/{repo}/contents/{quote(path)}"

    def _h(self, accept="application/vnd.github+json"):
        return {"Authorization": f"Bearer {self.token}", "Accept": accept,
                "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "khayal-stats"}

    def _meta(self):
        r = requests.get(self.url, params={"ref": self.branch}, headers=self._h(), timeout=30)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        j = r.json()
        if isinstance(j, list):
            raise RuntimeError("GH_PATH مجلد وليس ملفاً")
        return j

    def load(self):
        j = self._meta()
        if j is None:
            self.sha = None
            return None
        self.sha = j["sha"]
        if j.get("content") and j.get("encoding") == "base64":
            raw = base64.b64decode(j["content"])
        else:  # الملفات الأكبر من 1MB لا تأتي محتواها في JSON
            r = requests.get(self.url, params={"ref": self.branch},
                             headers=self._h("application/vnd.github.raw+json"), timeout=60)
            r.raise_for_status()
            raw = r.content
        return json.loads(raw.decode("utf-8"))

    def save(self, data):
        body = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        payload = {"message": "stats snapshot", "content": base64.b64encode(body).decode("ascii"),
                   "branch": self.branch}
        for _ in range(3):
            if self.sha:
                payload["sha"] = self.sha
            else:
                payload.pop("sha", None)
            r = requests.put(self.url, json=payload, headers=self._h(), timeout=60)
            if r.status_code in (200, 201):
                self.sha = r.json()["content"]["sha"]
                return
            if r.status_code in (409, 422):  # sha قديم: نجلب الأحدث ونعيد
                j = self._meta()
                self.sha = j["sha"] if j else None
                continue
            r.raise_for_status()
        raise RuntimeError("تعذّر حفظ اللقطة بعد 3 محاولات")


# ───────────────────────── الحالة ─────────────────────────
class Store:
    def __init__(self, settings: Settings, backend):
        self.s = settings
        self.backend = backend
        self.lock = threading.Lock()
        self.dirty = False
        self.plays = {}      # "YYYY-MM-DD" → {slug: n}
        self.daily = {}      # "YYYY-MM-DD" → {"active": n, "new": n}
        self.dev = {}        # بصمة → [أول يوم, آخر يوم, إصدار]  (الأيام أرقام: أيام منذ 1970-01-01)
        self.errors = {}     # fp → سجل الخطأ المجمَّع
        self.slugs = set()
        self.hit_ids = OrderedDict()   # لا يُحفظ: لتجاهل تكرار نفس الفتح
        self.last_saved = None

    # ── تحميل وحفظ
    def load(self):
        data = self.backend.load()
        if not data:
            log.info("لا توجد لقطة سابقة: بداية نظيفة")
            return
        if data.get("v", 1) > SCHEMA:
            raise RuntimeError("لقطة بإصدار أحدث من هذا السيرفر")
        self.plays = data.get("plays", {})
        self.daily = data.get("daily", {})
        self.dev = {k: list(v) for k, v in data.get("dev", {}).items()}
        self.errors = data.get("errors", {})
        for day in self.plays.values():
            self.slugs.update(day.keys())
        log.info("حُمّلت اللقطة: %d جهاز، %d خطأ", len(self.dev), len(self.errors))

    def snapshot(self):
        self._prune()
        return {"v": SCHEMA, "saved": now_str(), "plays": self.plays, "daily": self.daily,
                "dev": self.dev, "errors": self.errors}

    def flush(self, force=False):
        with self.lock:
            if not (self.dirty or force):
                return False
            data = json.loads(json.dumps(self.snapshot()))  # نسخة معزولة
            self.dirty = False
        try:
            self.backend.save(data)
            self.last_saved = now_str()
            log.info("حُفظت اللقطة")
            return True
        except Exception as ex:  # نعيد التعليم ليُعاد المحاولة في الدورة التالية
            with self.lock:
                self.dirty = True
            log.error("فشل الحفظ: %s", ex)
            return False

    def _prune(self):
        t = utc_today()
        for d in [d for d in self.plays if d < (t - timedelta(days=PLAYS_KEEP_DAYS)).isoformat()]:
            del self.plays[d]
        for d in [d for d in self.daily if d < (t - timedelta(days=DAILY_KEEP_DAYS)).isoformat()]:
            del self.daily[d]
        cut = (datetime.now(timezone.utc) - timedelta(days=ERRORS_KEEP_DAYS)).strftime("%Y-%m-%d %H:%M")
        for fp in [fp for fp, e in self.errors.items() if e.get("resolved") and e.get("last", "") < cut]:
            del self.errors[fp]
        if len(self.dev) > MAX_DEVICES:
            for h, _ in sorted(self.dev.items(), key=lambda kv: kv[1][1])[: len(self.dev) - MAX_DEVICES]:
                del self.dev[h]

    # ── التسجيل
    def hid(self, raw_id: str) -> str:
        return hmac.new(self.s.hash_key.encode(), raw_id.encode(), hashlib.sha256).hexdigest()[:12]

    def add_hit(self, slug: str, open_id: str):
        with self.lock:
            if open_id in self.hit_ids:
                return
            self.hit_ids[open_id] = 1
            while len(self.hit_ids) > 50_000:
                self.hit_ids.popitem(last=False)
            if slug not in self.slugs:
                if len(self.slugs) >= MAX_SLUGS:
                    return
                self.slugs.add(slug)
            day = self.plays.setdefault(utc_today().isoformat(), {})
            day[slug] = day.get(slug, 0) + 1
            self.dirty = True

    def add_dev(self, raw_id: str, ver: str):
        h = self.hid(raw_id)
        today = utc_today()
        ed, key = eday(today), today.isoformat()
        with self.lock:
            rec = self.dev.get(h)
            d = self.daily.setdefault(key, {"active": 0, "new": 0})
            if rec is None:
                if len(self.dev) >= MAX_DEVICES * 1.1:
                    return
                self.dev[h] = [ed, ed, ver]
                d["active"] += 1
                d["new"] += 1
            elif rec[1] < ed:
                rec[1], rec[2] = ed, ver or rec[2]
                d["active"] += 1
            else:
                return
            self.dirty = True

    def add_err(self, raw_id, app, ver, typ, msg, stack, ctx, android, model, fatal):
        h = self.hid(raw_id)
        fp = fingerprint(app, typ, msg, stack)
        now = now_str()
        with self.lock:
            e = self.errors.get(fp)
            if e is None:
                if len(self.errors) >= MAX_ERRORS:
                    victims = sorted(self.errors.items(), key=lambda kv: (not kv[1].get("resolved"), kv[1].get("last", "")))
                    del self.errors[victims[0][0]]
                e = self.errors[fp] = {"app": app, "ver": ver, "type": typ, "msg": msg, "stack": stack,
                                       "ctx": ctx, "first": now, "last": now, "fatal": bool(fatal),
                                       "resolved": False, "n": 0, "devs": [], "models": []}
            e["n"] += 1
            e["last"] = now
            e["ver"] = ver or e["ver"]
            e["ctx"] = ctx or e["ctx"]
            e["fatal"] = bool(e["fatal"] or fatal)
            e["resolved"] = False
            if h not in e["devs"] and len(e["devs"]) < MAX_DEVS_PER_ERROR:
                e["devs"].append(h)
            for m in e["models"]:
                if m[0] == model and m[1] == android:
                    m[2] += 1
                    break
            else:
                if len(e["models"]) < MAX_MODELS_PER_ERROR:
                    e["models"].append([model, android, 1])
            self.dirty = True

    def act_err(self, fp: str, action: str) -> bool:
        with self.lock:
            e = self.errors.get(fp)
            if e is None:
                return False
            if action == "delete":
                del self.errors[fp]
            elif action == "resolve":
                e["resolved"] = True
            elif action == "reopen":
                e["resolved"] = False
            self.dirty = True
            return True

    # ── القراءة
    def stats(self, days: int):
        today = utc_today()
        start_ed = eday(today) - days + 1
        keys = [(today - timedelta(days=i)).isoformat() for i in range(days)]
        with self.lock:
            tot = defaultdict(int)
            for k in keys:
                for slug, n in self.plays.get(k, {}).items():
                    tot[slug] += n
            games = [{"slug": s, "plays": n} for s, n in sorted(tot.items(), key=lambda kv: -kv[1])]
            active = sum(1 for r in self.dev.values() if r[1] >= start_ed)
            fresh = sum(1 for r in self.dev.values() if r[0] >= start_ed)
            vers = defaultdict(int)
            for r in self.dev.values():
                if r[1] >= start_ed:
                    vers[r[2] or "unknown"] += 1
            daily = []
            for k in reversed(keys):
                d = self.daily.get(k, {})
                daily.append({"day": k, "active": d.get("active", 0), "new": d.get("new", 0)})
            return {"games": games,
                    "devices": {"total": len(self.dev), "active": active, "new": fresh, "daily": daily,
                                "versions": [{"ver": v, "n": n} for v, n in sorted(vers.items(), key=lambda kv: -kv[1])]}}

    def errors_list(self, days: int, show_all: bool):
        cut = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d %H:%M")
        with self.lock:
            opened = sum(1 for e in self.errors.values() if not e.get("resolved"))
            out = []
            for fp, e in self.errors.items():
                if e["last"] < cut or (e["resolved"] and not show_all):
                    continue
                out.append({"fp": fp, "app": e["app"], "ver": e["ver"], "type": e["type"], "msg": e["msg"],
                            "stack": e["stack"], "ctx": e["ctx"], "first": e["first"], "last": e["last"],
                            "fatal": 1 if e["fatal"] else 0, "resolved": 1 if e["resolved"] else 0,
                            "n": e["n"], "devices": len(e["devs"]),
                            "models": [{"model": m[0], "android": m[1], "n": m[2]}
                                       for m in sorted(e["models"], key=lambda m: -m[2])[:10]]})
            out.sort(key=lambda e: e["last"], reverse=True)
            return {"open": opened, "errors": out}


class RateLimiter:
    def __init__(self, limit, window=60):
        self.limit, self.window = limit, window
        self.hits = defaultdict(deque)

    def allow(self, key) -> bool:
        now = time.time()
        q = self.hits[key]
        while q and q[0] < now - self.window:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        if len(self.hits) > 20_000:
            for k in [k for k, v in self.hits.items() if not v or v[-1] < now - self.window]:
                del self.hits[k]
        return True


# ───────────────────────── التطبيق ─────────────────────────
def make_backend(s: Settings):
    if s.gh_repo and s.gh_token:
        log.info("التخزين: GitHub %s:%s", s.gh_repo, s.gh_path)
        return GitHubBackend(s.gh_token, s.gh_repo, s.gh_branch, s.gh_path, s.gh_api)
    log.warning("GH_REPO/GH_TOKEN غير مضبوطين: التخزين في ملف محلي (يضيع عند إعادة تشغيل Render)")
    return LocalBackend(s.local_file)


@asynccontextmanager
async def lifespan(app: FastAPI):
    s = Settings()
    if not s.hash_key:
        raise RuntimeError("HASH_KEY مطلوب (سر طويل ثابت، لا يُغيَّر بعد الآن)")
    store = Store(s, make_backend(s))
    last = None
    for i in range(6):   # لا نبدأ بحالة فارغة بسبب خطأ شبكة عابر: كي لا نكتب فوق بيانات حقيقية
        try:
            store.load()
            last = None
            break
        except Exception as ex:
            last = ex
            log.error("تعذّر تحميل اللقطة (محاولة %d): %s", i + 1, ex)
            time.sleep(min(5 * (i + 1), 20))
    if last is not None:
        raise RuntimeError(f"فشل تحميل اللقطة، أوقفتُ التشغيل كي لا أكتب فوقها: {last}")
    app.state.s, app.state.store, app.state.rl = s, store, RateLimiter(RATE_LIMIT)
    stop = threading.Event()

    def loop():
        while not stop.wait(s.flush_seconds):
            store.flush()

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    try:
        yield
    finally:
        stop.set()
        store.flush()


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


def bad(msg="bad request", code=400):
    return JSONResponse({"error": msg}, status_code=code)


def client_ip(req: Request) -> str:
    xff = req.headers.get("x-forwarded-for", "")
    return (xff.split(",")[0].strip() if xff else (req.client.host if req.client else "?")) or "?"


async def read_json(req: Request):
    raw = await req.body()
    if len(raw) > MAX_BODY:
        return None
    try:
        j = json.loads(raw.decode("utf-8"))
    except Exception:
        return None
    return j if isinstance(j, dict) else None


def authed(req: Request) -> bool:
    tok = req.app.state.s.stats_token
    h = req.headers.get("authorization", "")
    return bool(tok) and h.startswith("Bearer ") and hmac.compare_digest(h[7:].strip(), tok)


def guard(req: Request):
    if not req.app.state.rl.allow(client_ip(req)):
        return bad("rate limited", 429)
    return None


@app.api_route("/health", methods=["GET", "HEAD"])
async def health():
    return PlainTextResponse("ok")


@app.get("/")
async def root():
    return PlainTextResponse("khayal-stats")


@app.post("/hit")
async def hit(req: Request):
    if (g := guard(req)):
        return g
    b = await read_json(req)
    slug, oid = (b or {}).get("slug"), (b or {}).get("id")
    if not isinstance(slug, str) or not _SLUG.match(slug) or not isinstance(oid, str) or not _HEX16.match(oid):
        return bad()
    req.app.state.store.add_hit(slug, oid)
    return Response(status_code=204)


@app.post("/dev")
async def dev(req: Request):
    if (g := guard(req)):
        return g
    b = await read_json(req)
    did, ver = (b or {}).get("id"), (b or {}).get("v", "")
    if not isinstance(did, str) or not _HEX32.match(did):
        return bad()
    ver = ver if isinstance(ver, str) and _VER.match(ver) else ""
    req.app.state.store.add_dev(did, ver)
    return Response(status_code=204)


@app.post("/err")
async def err(req: Request):
    if (g := guard(req)):
        return g
    b = await read_json(req)
    if b is None:
        return bad()
    did = b.get("id")
    if not isinstance(did, str) or not _HEX32.match(did):
        return bad()
    app_name = b.get("app", "games")
    if not isinstance(app_name, str) or not _APP.match(app_name):
        return bad()
    typ = re.sub(r"[^\w.:<>,\[\]() \-]", "?", clean(b.get("type"), 80)).strip()
    if not typ:
        return bad()
    ver = b.get("v", "")
    ver = ver if isinstance(ver, str) and _VER.match(ver) else ""
    req.app.state.store.add_err(did, app_name, ver, typ, clean(b.get("msg"), 300), clean(b.get("stack"), 1500),
                                clean(b.get("ctx"), 80), clean(b.get("android"), 40), clean(b.get("model"), 60),
                                bool(b.get("fatal")))
    return Response(status_code=204)


def _days(req: Request, default: int) -> int:
    try:
        return max(1, min(365, int(req.query_params.get("days", default))))
    except ValueError:
        return default


@app.get("/stats")
async def stats(req: Request):
    if not req.app.state.s.stats_token:
        return bad("STATS_TOKEN غير مضبوط", 501)
    if not authed(req):
        return bad("unauthorized", 401)
    return JSONResponse(req.app.state.store.stats(_days(req, 30)))


@app.get("/errors")
async def errors(req: Request):
    if not req.app.state.s.stats_token:
        return bad("STATS_TOKEN غير مضبوط", 501)
    if not authed(req):
        return bad("unauthorized", 401)
    return JSONResponse(req.app.state.store.errors_list(_days(req, 30), req.query_params.get("all") == "1"))


@app.post("/errors")
async def errors_act(req: Request):
    if not req.app.state.s.stats_token:
        return bad("STATS_TOKEN غير مضبوط", 501)
    if not authed(req):
        return bad("unauthorized", 401)
    b = await read_json(req)
    fp, action = (b or {}).get("fp"), (b or {}).get("action")
    if not isinstance(fp, str) or action not in ("resolve", "reopen", "delete"):
        return bad()
    if not req.app.state.store.act_err(fp, action):
        return bad("not found", 404)
    return JSONResponse({"ok": True})
