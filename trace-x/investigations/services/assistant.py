"""Sentinel — the TRACE-X in-app assistant.

A local, deterministic-yet-variadic chat engine. It understands how the
platform works (cases, evidence, analysis, integrity, access rules, API)
and answers in a natural, conversational voice — never a fixed script.
Every intent has several phrasings and replies pull in the caller's real
data (their case counts, latest case, findings) so no two answers are
cookie-cutter.
"""

import random
import re

from ..models import Evidence, Finding, Investigation


# ---------------------------------------------------------------- helpers

def _profile(user):
    """Live snapshot of the caller's own work — used to personalise replies."""
    cases = Investigation.objects.filter(created_by=user)
    latest = cases.order_by("-created_at").first()
    return {
        "name": user.username,
        "cases": cases.count(),
        "latest": latest,
        "evidence": Evidence.objects.filter(investigation__created_by=user).count(),
        "findings": Finding.objects.filter(investigation__created_by=user).count(),
    }


def _case_line(ctx):
    latest = ctx["latest"]
    if not latest:
        return "you haven't opened a case yet"
    return f"your latest is {latest.case_number} — {latest.title} ({latest.status})"


def _pick(lines, ctx=None, **extra):
    text = random.choice(lines)
    if ctx is not None:
        text = text.format(**ctx, **extra)
    return text


# --------------------------------------------------------------- intents

def _greeting(user, ctx, msg):
    who = ctx["name"]
    return (
        _pick([
            "Hey {name} — good to see you. What are we digging into today?",
            "Hi {name}. Sentinel here, ready when you are. Got a case that needs eyes, or just exploring?",
            "Hello {name}. All quiet on the evidence chain. What can I help you with?",
            "Morning {name} — hashes verified, coffee optional. What's on the investigation board?",
        ], ctx),
        ["How do I create a case?", "Run AI analysis", "What is the integrity chain?"],
    )


def _who_are_you(user, ctx, msg):
    return (
        _pick([
            "I'm Sentinel — the TRACE-X assistant. I live in the corner of your screen, I know how this platform works, and I answer in plain human instead of manual-speak. Ask me about cases, evidence, analysis, access rules… I'm surprisingly good company.",
            "Sentinel, at your service. Think of me as the colleague who has actually read the docs — cases, uploads, the hash chain, who's allowed to see what. What do you want to know?",
            "I'm your in-app guide, Sentinel. I watch the investigation workflow so you don't have to guess: create a case, fingerprint evidence, run analysis, verify the chain. What should we start with?",
        ], ctx),
        ["What can you do?", "How do I create a case?", "What is TRACE-X?"],
    )


def _what_is_tracex(user, ctx, msg):
    return (
        _pick([
            "TRACE-X is a cyber investigation platform. You drop in raw evidence — logs, emails, alerts, captures — and it fingerprints every file with SHA-256, rebuilds an attack timeline, and turns it into findings that point straight back to the exact line of evidence. Nothing is a black box here.",
            "Short version: TRACE-X takes messy forensic evidence and gives you traceable conclusions. Every upload gets a SHA-256 fingerprint, everything sits in a tamper-evident hash chain, and each finding shows its work — the evidence, the excerpt, the reasoning.",
            "It's your investigation command center. Evidence in, timeline and findings out, with a cryptographic chain of custody holding it all together. The part people love: any conclusion can be walked back to the raw evidence that produced it.",
        ], ctx),
        ["How do I create a case?", "Run AI analysis", "What is the integrity chain?"],
    )


def _capabilities(user, ctx, msg):
    return (
        _pick([
            "Quite a lot, honestly:\n— Open cases and upload evidence (every file gets a SHA-256 fingerprint on arrival)\n— Run analysis to rebuild the attack timeline and surface findings\n— Verify the tamper-evident integrity chain\n— Read traceability trails from finding back to raw evidence\n— Peek at fellow investigators' profiles read-only\n— Use the JSON API if you're building something\nWhat sounds useful?",
            "Here's my wheelhouse: cases, evidence fingerprinting, AI analysis, integrity checks, traceability — plus the occasional honest opinion on your investigation habits. I can also point you to the right page instead of making you hunt. Pick a starting point:",
            "I can walk you through just about anything here: creating a case, uploading and hashing evidence, running analysis, reading findings, verifying the ledger, or the API. I also know who's allowed to touch what — access questions are kind of my thing.",
        ], ctx),
        ["Upload evidence", "Who can see my cases?", "What is the API?"],
    )


def _create_case(user, ctx, msg):
    return (
        _pick([
            "Super easy — click **New Case** in the top nav, give it a title and a description, and save. TRACE-X assigns the next TRX number automatically and stamps you as the owner. From there it's upload → analyze → findings. Want the upload part too?",
            "Two clicks: hit **New Case** up top, fill in the title and description, save. You'll get a fresh TRX number and the case opens straight away. One tip — write a real description now, your future self reading the timeline will thank you.",
            "Head to **New Case** in the navigation (or /investigations/new/), name the investigation, describe what you're chasing, and save. The case number is generated for you. After that, evidence uploads are waiting on the case page.",
        ], ctx),
        ["Upload evidence", "Run AI analysis", "How do I search cases?"],
    )


def _upload(user, ctx, msg):
    return (
        _pick([
            "Open your case and use the **Upload evidence** card — drop in logs, .eml files, pcaps, CSVs, JSON alerts, screenshots. On arrival each file is hashed with SHA-256, duplicates are skipped, and the hash lands in the integrity ledger. One heads-up: files over 25 MB get politely refused.",
            "Open the case, scroll to **Upload evidence**, attach your files, hit *Upload & fingerprint*. The bytes are hashed immediately — SHA-256, computed on arrival — and any file you've already uploaded (same bytes) is skipped as a duplicate. Supported: logs, email, network captures, JSON alerts, screenshots.",
            "Easy — on the case page, the upload card takes logs, emails, pcaps, CSV, JSON and images. Everything gets fingerprinted the second it lands, and the record goes into the append-only ledger. So if anyone edits the file later, the chain will know. That's kind of the whole point.",
        ], ctx),
        ["Run AI analysis", "What is the integrity chain?", "25 MB limit — why?"],
    )


def _analyze(user, ctx, msg):
    n = ctx["cases"]
    opener = _pick([
        "Open your case and hit **Run AI analysis** in the header.",
        "Sure — open the case and press **Run AI analysis** at the top.",
        "Go to the case page and click **Run AI analysis**.",
    ])
    tail = _pick([
        "The engine parses every piece of evidence, rebuilds the chronological timeline, and emits findings like brute force, compromise-after-failures, phishing, C2 beaconing, exfiltration and privilege escalation — each one linked to the evidence that proves it.",
        "It works through parsers and detection rules, reconstructs the attack timeline, and writes up findings with the supporting evidence attached. Nothing is hand-waved — every conclusion carries its excerpt and rationale.",
        "You'll get timeline events plus findings with confidence scores, and each finding keeps a full trail back to the raw evidence. It's deterministic — same evidence, same conclusions.",
    ])
    if n == 0:
        opener = "You don't have a case open yet — create one first from **New Case**, add at least one evidence file, then hit **Run AI analysis**."
        tail = "Analysis needs evidence to chew on, so the flow is: case → upload → analyze."
    return (f"{opener} {tail}", ["How do I create a case?", "Upload evidence", "What are findings?"])


def _findings(user, ctx, msg):
    return (
        _pick([
            "Findings are the conclusions the analysis engine stands behind. Each one has a category, severity, confidence and MITRE technique — and, more importantly, a traceability trail: the exact evidence, the raw excerpt and the reasoning that got it there. Open any finding to see the full chain, finding → evidence → excerpt.",
            "Think of a finding as a verdict with receipts. It says what happened (brute force, phishing, C2 beaconing…), how confident it is, and shows you the supporting evidence line by line. You can flip its status as you investigate — confirmed, false positive, and so on.",
            "They're the 'so what' of your investigation. The analysis produces them, each one links back to concrete evidence, and you can walk the trail yourself on the finding page. Nothing is asserted without the artifact behind it.",
        ], ctx),
        ["Run AI analysis", "Open a finding trail", "What is traceability?"])


def _integrity(user, ctx, msg):
    return (
        _pick([
            "The integrity chain is a blockchain-style hash chain over your investigation: each block is SHA-256(height | timestamp | previous hash | payload). Evidence, timeline events and findings all feed it. Change anything after the fact and verification fails loudly — that's the tamper evidence.",
            "Every action appends a new block to an append-only ledger, each one hashed with the block before it. Open **Integrity chain** on any case to verify it end to end — if a single byte was altered, the verification reports exactly where the chain broke.",
            "Short answer: it's tamper-evident storage. Blocks stack as SHA-256 hashes linking back through height, timestamp and the previous block. You can verify any case whenever you like — the page walks the whole chain and tells you if it's intact.",
        ], ctx),
        ["Verify a case now", "Upload evidence", "What is SHA-256?"])


def _sha256(user, ctx, msg):
    return (
        _pick([
            "SHA-256 is the fingerprinting hash TRACE-X applies to every upload. Same bytes always produce the same 64-character fingerprint; change one byte and it's completely different. We compute it on arrival, store it, and re-check it whenever you verify integrity.",
            "It's a cryptographic hash — a 256-bit fingerprint of your file's exact bytes. TRACE-X hashes evidence the moment it lands, keeps the digest in the ledger, and compares it later to prove nothing was edited. Fast, standard, and effectively impossible to fake.",
            "Think of it as a digital fingerprint for evidence. 64 hex characters, derived purely from the file's bytes. Re-upload the same file and you'll notice it's skipped as a duplicate — same fingerprint, same file.",
        ], ctx),
        ["What is the integrity chain?", "Upload evidence", "How do I create a case?"])


def _traceability(user, ctx, msg):
    return (
        _pick([
            "Traceability means every conclusion can be walked back to its source. A finding stores which evidence supports it, the exact excerpt, and why it matters — so on the finding page you go Finding → Evidence → raw line. No orphan claims, ever.",
            "That's the whole soul of this platform: evidence-to-conclusion, in both directions. From a finding you can jump to the evidence behind it; from evidence you can see every finding it feeds. If someone asks 'how do you know?', the answer is two clicks away.",
            "Every finding carries its receipts — the linked evidence, the excerpt taken from it, and the rationale. The chain of reasoning is visible, not implied. That's what makes the report defensible.",
        ], ctx),
        ["Open a finding trail", "Run AI analysis", "Download a report"])


def _report(user, ctx, msg):
    return (
        _pick([
            "Reports live on the case page — TRACE-X generates HTML, Markdown and PDF versions stamped with a timestamp, including findings, timeline and the integrity status. Look for the report action on your case and you'll have all three formats.",
            "Open the case and generate the report — you'll get HTML, Markdown and PDF copies with case number, timeline, findings and the chain status baked in. Nice for handing to people who don't live in the tool.",
            "On the case page you can export the full report: HTML for sharing, Markdown for repos, PDF for humans. It includes the findings, the timeline and whether the integrity chain verified clean.",
        ], ctx),
        ["Where is my evidence stored?", "What is traceability?", "Who can see my cases?"])


def _api(user, ctx, msg):
    return (
        _pick([
            "There's a JSON API if you want to script things:\n— GET /api/investigations/ — your case list\n— GET /api/investigations/<id>/ — full case with evidence, timeline and finding traceability\n— POST /api/investigations/<id>/analyze/ — trigger analysis\n— GET /api/investigations/<id>/integrity/ — chain verification\n— GET /api/health — heartbeat\nAll of it requires a logged-in session.",
            "Yes — clean and small. /api/investigations/ lists cases, the detail endpoint returns evidence plus findings with their traceability, analyze is a POST, and integrity gives you the chain report. /api/health is there for monitors. Everything sits behind login.",
            "API lives under /api/ — list cases, pull a full case with evidence and findings, run analysis, verify integrity, check health. It returns plain JSON, so curl or fetch both work. Just remember it needs an authenticated session like every other page here.",
        ], ctx),
        ["What is traceability?", "Run AI analysis", "Who can see my cases?"])


def _access(user, ctx, msg):
    return (
        _pick([
            "Good question — the rules are simple. Owners and staff can change a case; everyone signed in can *read* it. So your cases are safe from edits by teammates, but they can still open your profile from **Investigators** and review the attack in read-only mode. Uploads, analysis and status changes are blocked for non-owners — they get a READ-ONLY banner instead of the buttons.",
            "Short version: view yes, touch no. Any signed-in investigator can open another's case read-only — you'll see the READ-ONLY badge and the edit controls are gone. Only the owner or an admin can upload evidence, run analysis or change finding statuses. Lists and dashboards still only show your own cases.",
            "Two layers. Your dashboard and case list stay private to you (admins see everything). But case pages themselves are view-only for colleagues — useful for pair-investigating without risking someone rewriting your evidence. Anything that modifies data checks ownership first and refuses otherwise.",
        ], ctx),
        ["Who is an administrator?", "Show investigator profiles", "Where is my evidence stored?"])


def _admin(user, ctx, msg):
    return (
        _pick([
            "Administrators are staff accounts — they can open every case, see the **Users** dashboard with team-wide stats, and manage accounts. Regular investigators only see their own cases in lists, though colleagues' profiles stay readable by anyone signed in.",
            "Staff users get the extra layer: the Users page, all cases across the platform, and account oversight. Everyone else works within their own cases — with read-only visibility into other investigators' work if they need it.",
            "An admin is just a user with the staff flag. They see every case, get the Users dashboard, and can create accounts for the team. Regular investigators keep full control of their own cases and read-only eyes on everyone else's.",
        ], ctx),
        ["Who can see my cases?", "How do I sign up?", "Show investigator profiles"])


def _signup_login(user, ctx, msg):
    return (
        _pick([
            "New teammate? The login page has a **Create account** link — pick a username and a solid password and you're in. If that link is ever hidden, an admin has turned self-registration off and you'll need them to make the account.",
            "Sign-up is on the login screen — **New investigator? Create account**. Password rules are the usual suspects: eight characters or more, not your username, not something obvious. Already have an account? The login form is right there.",
            "Just hit **Create account** under the sign-in form. Once you're registered you land straight on the dashboard and can open your first case immediately.",
        ], ctx),
        ["How do I create a case?", "What can you do?", "Who can see my cases?"])


def _search(user, ctx, msg):
    return (
        _pick([
            "The **Investigations** page has a search box at the top — it matches case number, title and description as you type. Admins search everything; you'll search your own cases. Dashboard shows your ten most recent if you just want a quick glance.",
            "Go to **Investigations** and use the search bar — case number, title or description all work. Your dashboard is also a fast route: it lists your latest cases with evidence and finding counts right there.",
            "Search lives at the top of the **Investigations** list. Try the TRX number if you have it, or a keyword from the title. Admins get the whole platform's cases; investigators get their own.",
        ], ctx),
        ["How do I create a case?", "Show investigator profiles", "What can you do?"])


def _status(user, ctx, msg):
    return (
        _pick([
            "Case statuses are simple lifecycle flags: **open** means active work, and the pill on the case page always shows the current state — it flips back to open whenever new evidence lands. Finding statuses (open, in review, confirmed, false positive) are yours to set as you investigate.",
            "The pill next to the case title is the live status — it starts open and any new evidence resets it to open, since fresh artifacts mean fresh work. Findings have their own statuses you can update from the finding page.",
            "You'll see pills for case status (open by default, reset on new evidence) and for each finding (open, reviewing, confirmed, dismissed). They're there so your future self knows what's still hot.",
        ], ctx),
        ["Run AI analysis", "Open a finding trail", "What are findings?"])


def _security(user, ctx, msg):
    return (
        _pick([
            "Evidence never leaves this machine — everything runs locally. Uploads are treated as untrusted data (never executed), capped at 25 MB, stored with safe filenames, and every page except login requires an authenticated session. Media files are served through a login-protected route, not public static.",
            "Locally, through the whole pipeline. Files are fingerprinted on arrival and kept on disk; the app never phones home. Access is enforced server-side — pages, media and API all check who you are before returning anything.",
            "Short answer: your evidence stays put. No external calls, uploads are size-checked and hash-stamped, and sensitive routes sit behind login. The hash chain then keeps an eye on everything after the fact.",
        ], ctx),
        ["What is the integrity chain?", "Who can see my cases?", "How do I create a case?"])


def _limits(user, ctx, msg):
    return (
        _pick([
            "The upload limit is 25 MB per file — big enough for logs, pcaps and images, small enough that one accidental disk dump doesn't choke the server. Anything larger is rejected with a message and the rest of your batch still uploads.",
            "25 MB per evidence file, deliberately. Forensic artifacts are usually small; the cap just stops someone attaching a 4 GB image by mistake. Duplicate bytes are skipped too, so re-uploading the same file costs nothing.",
            "Files over 25 MB are refused at upload with a clear error. Beyond that, no real limits — upload as many files as your investigation needs, each one gets its own fingerprint.",
        ], ctx),
        ["Upload evidence", "Run AI analysis", "Where is my evidence stored?"])


def _storage(user, ctx, msg):
    return (
        _pick([
            "Two places, both local: uploaded files live under the app's media storage, and metadata (hashes, timeline, findings) lives in the database. Reports are written to the storage folder as HTML, Markdown and PDF. Nothing is uploaded anywhere else.",
            "On this machine, full stop. Evidence files go to the local media directory with safe generated names, the database keeps the hashes and records, and reports get written alongside. The app makes no outbound calls with your data.",
            "Everything stays local — evidence on disk, records in the database, reports in the storage folder. That's on purpose: forensic material shouldn't be anyone else's business.",
        ], ctx),
        ["What is the integrity chain?", "Where are reports stored?", "Who can see my cases?"])


def _profiles(user, ctx, msg):
    return (
        _pick([
            "Click **Investigators** in the top nav — you'll see the whole team with their case, evidence and finding counts. Open anyone's profile to browse the attacks they've worked on. It's strictly view-only: you can read their cases, but the edit controls stay hidden.",
            "The **Investigators** page is your team directory, and each profile lists their attack cases with counts. Great for 'who handled the ransomware one?' — click through and their cases open in read-only mode. In the profile dropdown there's a **See Investigators** shortcut too.",
            "Top nav, **Investigators**. Everyone signed in shows up with their activity stats; click a name to view their cases. Colleagues can review your work but never modify it — read-only is enforced server-side, not just hidden in the UI.",
        ], ctx),
        ["Who can see my cases?", "How do I create a case?", "What can you do?"])


def _thanks(user, ctx, msg):
    return (
        _pick([
            "Any time — that's what I'm here for. Go make that evidence count.",
            "Happy to help. You know where to find me if the hash chain starts getting philosophical.",
            "Of course. Ping me anytime — I don't sleep, I just verify chains.",
        ], ctx),
        ["What can you do?", "Run AI analysis", "What is the integrity chain?"],
    )


def _bye(user, ctx, msg):
    return (
        _pick([
            "Take care, {name}. I'll keep the ledger honest while you're gone.",
            "See you, {name}. Go find something interesting in those logs.",
            "Later {name}. Your cases will be right here, hashes and all.",
        ], ctx),
        ["What can you do?", "How do I create a case?", "Show investigator profiles"],
    )


def _how_are_you(user, ctx, msg):
    return (
        _pick([
            "Running smooth — every chain verified this morning. More importantly, how's the investigation going?",
            "All green on my side: no broken hashes, no tampered blocks, no existential dread. What's on your mind?",
            "Firing on all cylinders and slightly bored, honestly. Give me something to trace.",
        ], ctx),
        ["What can you do?", "Run AI analysis", "How do I create a case?"],
    )


def _joke(user, ctx, msg):
    return (
        _pick([
            "A hash walks into a bar. The bartender asks for ID — it says 'I don't know, I'm only a fingerprint of myself.'",
            "Why did the investigator bring a ladder to the server room? Heard the evidence had layers. ...I'll stick to forensics.",
            "I'd tell you a UDP joke, but you might not get it. Log jokes? I've got plenty — mostly failed logins. Ba dum tss.",
        ], ctx),
        ["What can you do?", "What is the integrity chain?", "How do I create a case?"],
    )


def _case_lookup(user, ctx, msg):
    m = re.search(r"TRX-?\s*([A-Za-z]?\s*)(\d{3,4})", msg, re.I)
    if not m:
        return None
    number = f"TRX-{m.group(1).strip()}{int(m.group(2)):04d}"
    case = Investigation.objects.filter(case_number__iexact=number).first()
    if not case:
        return (
            f"I can't find a case numbered {number}. Check the spelling — TRACE-X numbers look like TRX-0001 — or see your list on the Investigations page.",
            ["How do I search cases?", "How do I create a case?"],
        )
    ev = case.evidence.count()
    fi = case.findings.count()
    return (
        f"{case.case_number} — {case.title}. Status is {case.status}, {ev} evidence item{'s' if ev != 1 else ''}, "
        f"{fi} finding{'s' if fi != 1 else ''}, opened by {case.created_by.username if case.created_by else 'the system'}. "
        f"You can open it from the Investigations list" + ("." if _can_touch(user, case) else " — it'll be read-only for you."),
        ["Run AI analysis", "What is the integrity chain?", "Who can see my cases?"],
    )


def _can_touch(user, case):
    return bool(user.is_staff or (case.created_by_id and case.created_by_id == user.id))


def _fallback(user, ctx, msg):
    return (
        _pick([
            "Hmm — I didn't quite catch that one. I'm at my best around cases, evidence, analysis, the integrity chain and access rules. Could you rephrase, or tap a suggestion below?",
            "That one's outside my usual circuits. Ask me how to create a case, upload evidence, run analysis, verify the chain — or anything about who can see what. What sounds close?",
            "I want to get this right rather than guess. Try me on TRACE-X territory: workflows, findings, hashing, permissions, the API. Or just say 'what can you do' and I'll show my cards.",
            "Not sure I follow — but I'm keen. Give it another go, maybe with a few keywords like 'upload', 'analysis', 'integrity' or 'permissions'.",
        ], ctx),
        ["What can you do?", "How do I create a case?", "Who can see my cases?"],
    )


# ----------------------------------------------------------- dispatcher

_RULES = [
    ("greeting", _greeting, r"\b(hi|hello|hey|yo|good (morning|evening|afternoon)|namaste|hola)\b"),
    ("bye", _bye, r"\b(bye|goodbye|see you|later|gtg|good night)\b"),
    ("thanks", _thanks, r"\b(thanks|thank you|thx|cheers|appreciate)\b"),
    ("how_are_you", _how_are_you, r"how('?s| is| are) (it |you )?(going|doing|are you)|how are you"),
    ("joke", _joke, r"\b(joke|funny|make me laugh|entertain)\b"),
    ("who_are_you", _who_are_you, r"(who|what) are you|your name|about you|introduce"),
    ("what_is_tracex", _what_is_tracex, r"what('?s| is) (this|trace-?x|the platform)|about (this|trace-?x)|explain trace"),
    ("capabilities", _capabilities, r"what can you do|help me|features|commands|abilities|what do you know"),
    ("create_case", _create_case, r"(create|open|start|new) (a |an |new )?(case|investigation)|how do i begin"),
    ("limits", _limits, r"\blimit|too (big|large)|max(imum)? size|25 ?mb"),
    ("upload", _upload, r"(upload|add|submit|attach|import).*(evidence|file|log)|fingerprint|hash (a |the )?file"),
    ("analyze", _analyze, r"(run|start|do).*(analysis|analyse|analyze|scan|detect)|ai analysis|reconstruct|timeline again"),
    ("traceability", _traceability, r"traceab|evidence.to.conclusion|walk (it |them )?back|how do you know"),
    ("findings", _findings, r"finding|conclusion|confidence|mitre|false positive|receipts"),
    ("integrity", _integrity, r"integrity|hash chain|tamper|ledger|blockchain|verify|chain of custody"),
    ("sha256", _sha256, r"sha-?256|fingerprint|digest|checksum"),
    ("report", _report, r"report|export|pdf|download.*(report|pdf)|markdown"),
    ("api", _api, r"\bapi\b|endpoint|json|curl|fetch\("),
    ("access", _access, r"who can (see|view|edit|access)|permission|read.?only|colleague|friend|other investigator|see (other|someone|my friends)|private|own case"),
    ("admin", _admin, r"\badmin\b|staff|superuser|manage accounts|users dashboard"),
    ("signup_login", _signup_login, r"sign ?up|register|create account|log ?in|sign ?in|password|forgot"),
    ("search", _search, r"search|find (a |my )?case|filter|look up"),
    ("status", _status, r"status|pill|what does open mean|in review|confirmed"),
    ("security", _security, r"secure|privacy|leave (the )?machine|external|phone home|safe|encrypt"),
    ("storage", _storage, r"where.*(stored|kept|saved|live)|storage|database|disk|local"),
    ("profiles", _profiles, r"investigator (page|profile|directory)|see (the )?team|roster|colleague profile|friends"),
]


def respond(user, message):
    """Return {"reply": str, "suggestions": [str]} for one user message."""
    msg = (message or "").strip()
    ctx = _profile(user)

    if not msg:
        return {
            "reply": "You sent an empty one — I'm a chatbot, not a mind reader. What's on your mind?",
            "suggestions": ["What can you do?", "How do I create a case?", "Run AI analysis"],
        }

    result = _case_lookup(user, ctx, msg)
    if result:
        reply, suggestions = result
        return {"reply": reply, "suggestions": suggestions}

    for name, handler, pattern in _RULES:
        if re.search(pattern, msg, re.I):
            reply, suggestions = handler(user, ctx, msg)
            return {"reply": reply, "suggestions": suggestions}

    reply, suggestions = _fallback(user, ctx, msg)
    return {"reply": reply, "suggestions": suggestions}
