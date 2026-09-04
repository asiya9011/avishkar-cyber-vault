import os
import re
import sqlite3
import hashlib
import secrets

from datetime import datetime

from flask import (
    Flask,
    request,
    redirect,
    url_for,
    session,
    flash,
    render_template_string,
    send_from_directory
)

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression


# ============================================================
# CONFIGURATION
# ============================================================

APP_NAME = "CYBER CRIME EVIDENCE VAULT"

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

DATABASE = os.path.join(
    BASE_DIR,
    "cyber_vault.db"
)

EVIDENCE_DIR = os.path.join(
    BASE_DIR,
    "evidence_storage"
)

os.makedirs(
    EVIDENCE_DIR,
    exist_ok=True
)


app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))


# ============================================================
# DATABASE
# ============================================================

def db():

    connection = sqlite3.connect(
        DATABASE
    )

    connection.row_factory = sqlite3.Row

    return connection


def timestamp():

    return datetime.utcnow().strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )


def initialize_database():

    connection = db()

    connection.executescript("""

    CREATE TABLE IF NOT EXISTS users (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        username TEXT UNIQUE NOT NULL,

        password TEXT NOT NULL,

        role TEXT NOT NULL,

        created_at TEXT NOT NULL
    );


    CREATE TABLE IF NOT EXISTS cases (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        case_number TEXT UNIQUE NOT NULL,

        title TEXT NOT NULL,

        description TEXT,

        created_at TEXT NOT NULL,

        created_by INTEGER
    );


    CREATE TABLE IF NOT EXISTS evidence (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        evidence_id TEXT UNIQUE NOT NULL,

        case_id INTEGER NOT NULL,

        filename TEXT NOT NULL,

        stored_filename TEXT NOT NULL,

        sha256 TEXT NOT NULL,

        content TEXT,

        uploaded_by INTEGER,

        uploaded_at TEXT NOT NULL,

        FOREIGN KEY(case_id)
            REFERENCES cases(id)
    );


    CREATE TABLE IF NOT EXISTS custody (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        evidence_id INTEGER NOT NULL,

        action TEXT NOT NULL,

        notes TEXT,

        timestamp TEXT NOT NULL
    );


    CREATE TABLE IF NOT EXISTS ai_analysis (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        evidence_id INTEGER NOT NULL,

        prediction TEXT NOT NULL,

        risk_score INTEGER NOT NULL,

        confidence INTEGER NOT NULL,

        explanation TEXT,

        analyzed_at TEXT NOT NULL
    );

    """)

    admin = connection.execute(
        """
        SELECT id
        FROM users
        WHERE username=?
        """,
        ("admin",)
    ).fetchone()

    if admin is None:

        connection.execute(
            """
            INSERT INTO users
            (
                username,
                password,
                role,
                created_at
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                "admin",
                os.environ.get("ADMIN_PASSWORD", "Avishkar@2026!"),
                "admin",
                timestamp()
            )
        )

    connection.commit()

    connection.close()


initialize_database()


# ============================================================
# EXPLAINABLE AI
# ============================================================

PHISHING_DATA = [

    "URGENT verify your bank account immediately click login",

    "Your account will be suspended verify your password immediately",

    "Congratulations you won a prize click the link to claim",

    "Your payment has failed login and verify your credentials",

    "Security alert confirm your password immediately",

    "Your account will be closed unless you verify your identity",

    "Urgent payment required click the link and enter credentials",

    "Your email account has been compromised verify password",

    "Click immediately to avoid account suspension",

    "Verify your bank account and credit card immediately"

]


LEGITIMATE_DATA = [

    "The meeting is scheduled for tomorrow at 10 AM",

    "Please find the project report attached",

    "The monthly team meeting will be held on Friday",

    "Thank you for submitting the requested documents",

    "Your appointment is confirmed for Monday",

    "The invoice has been received by accounting",

    "Please review the project proposal",

    "The office will remain closed on the public holiday",

    "Your application has been successfully received",

    "We look forward to seeing you at the conference"

]


TRAINING_TEXT = (
    PHISHING_DATA
    +
    LEGITIMATE_DATA
)


TRAINING_LABELS = (
    [1] * len(PHISHING_DATA)
    +
    [0] * len(LEGITIMATE_DATA)
)


vectorizer = TfidfVectorizer(
    lowercase=True,
    ngram_range=(1, 2),
    max_features=3000
)


X = vectorizer.fit_transform(
    TRAINING_TEXT
)


classifier = LogisticRegression(
    max_iter=1000,
    random_state=42
)


classifier.fit(
    X,
    TRAINING_LABELS
)


FEATURE_RULES = {

    "Urgent language": [
        "urgent",
        "immediately",
        "right now",
        "action required",
        "as soon as possible"
    ],

    "Payment language": [
        "payment",
        "invoice",
        "bank",
        "credit card",
        "money",
        "transfer"
    ],

    "Credential request": [
        "password",
        "login",
        "username",
        "credentials",
        "verify your identity",
        "account verification"
    ],

    "Account threat": [
        "account will be closed",
        "account suspended",
        "account will be suspended",
        "account blocked",
        "avoid suspension"
    ],

    "Prize/scam language": [
        "winner",
        "won a prize",
        "congratulations",
        "claim your prize",
        "reward"
    ],

    "Suspicious attachment": [
        ".exe",
        ".scr",
        ".bat",
        ".zip",
        ".js",
        ".docm"
    ]
}


def extract_security_features(text):

    text_lower = text.lower()

    features = []

    for name, keywords in FEATURE_RULES.items():

        matches = []

        for keyword in keywords:

            if keyword in text_lower:

                matches.append(
                    keyword
                )

        if matches:

            features.append({
                "name": name,
                "matches": matches
            })


    urls = re.findall(
        r"https?://[^\s]+|www\.[^\s]+",
        text,
        flags=re.IGNORECASE
    )


    if urls:

        suspicious_terms = [
            "login",
            "verify",
            "account",
            "secure",
            "update",
            "payment",
            "confirm"
        ]

        suspicious = []

        for url in urls:

            if any(
                term in url.lower()
                for term in suspicious_terms
            ):

                suspicious.append(url)


        features.append({

            "name":
                "URL characteristics",

            "matches":
                suspicious or urls
        })


    return features


def explain_ai(text):

    if not text.strip():

        return {

            "label":
                "NO DATA",

            "risk":
                0,

            "confidence":
                0,

            "features":
                [],

            "reasons":
                [
                    "No evidence text was provided."
                ],

            "model_features":
                []
        }


    test_vector = vectorizer.transform(
        [text]
    )


    probability = classifier.predict_proba(
        test_vector
    )[0][1]


    risk = int(
        round(
            probability * 100
        )
    )


    prediction = (
        "PHISHING"
        if probability >= 0.5
        else "LIKELY LEGITIMATE"
    )


    # ========================================================
    # XAI MODEL CONTRIBUTIONS
    # ========================================================

    names = (
        vectorizer
        .get_feature_names_out()
    )


    coefficients = (
        classifier.coef_[0]
    )


    values = (
        test_vector
        .toarray()[0]
    )


    contributions = (
        values * coefficients
    )


    indexes = sorted(
        range(len(contributions)),
        key=lambda i:
            abs(contributions[i]),
        reverse=True
    )


    model_features = []


    for index in indexes:

        if values[index] == 0:

            continue


        model_features.append({

            "feature":
                names[index],

            "contribution":
                float(
                    contributions[index]
                )
        })


        if len(model_features) >= 10:

            break


    # ========================================================
    # HUMAN-READABLE SECURITY FEATURES
    # ========================================================

    security_features = (
        extract_security_features(text)
    )


    reasons = []


    for feature in security_features:

        name = feature["name"]


        if name == "Urgent language":

            reasons.append(
                "Urgent or pressure-based "
                "language detected"
            )


        elif name == "Payment language":

            reasons.append(
                "Payment or financial "
                "terminology detected"
            )


        elif name == "Credential request":

            reasons.append(
                "Credential or identity "
                "verification request detected"
            )


        elif name == "Account threat":

            reasons.append(
                "Account suspension or "
                "threat language detected"
            )


        elif name == "Prize/scam language":

            reasons.append(
                "Prize or reward-related "
                "scam language detected"
            )


        elif name == "Suspicious attachment":

            reasons.append(
                "Potentially risky attachment "
                "type detected"
            )


        elif name == "URL characteristics":

            reasons.append(
                "Suspicious URL characteristics "
                "detected"
            )


    if not reasons:

        reasons.append(
            "No strong phishing indicators "
            "were detected."
        )


    return {

        "label":
            prediction,

        "risk":
            risk,

        "confidence":
            max(
                risk,
                100 - risk
            ),

        "features":
            security_features,

        "reasons":
            reasons,

        "model_features":
            model_features
    }


# ============================================================
# SHA-256
# ============================================================

def calculate_sha256(filepath):

    sha = hashlib.sha256()


    with open(
        filepath,
        "rb"
    ) as file:

        while True:

            chunk = file.read(
                1024 * 1024
            )

            if not chunk:

                break

            sha.update(chunk)


    return sha.hexdigest()


# ============================================================
# CSS
# ============================================================

CSS = """

* {
    box-sizing: border-box;
}

body {

    margin: 0;

    font-family:
        Arial,
        Helvetica,
        sans-serif;

    background: #eef2f7;

    color: #172033;
}

nav {

    background: #111827;

    color: white;

    padding: 18px 30px;

    display: flex;

    justify-content: space-between;

    align-items: center;
}

.logo {

    font-size: 18px;

    font-weight: bold;
}

nav a {

    color: white;

    text-decoration: none;

    margin-left: 20px;
}

.container {

    max-width: 1200px;

    margin: 30px auto;

    padding: 0 20px;
}

.panel {

    background: white;

    padding: 25px;

    border-radius: 12px;

    margin-bottom: 25px;

    box-shadow:
        0 4px 15px
        rgba(0,0,0,.07);
}

.stats {

    display: grid;

    grid-template-columns:
        repeat(3,1fr);

    gap: 20px;

    margin-bottom: 25px;
}

.stat {

    background: white;

    padding: 25px;

    border-radius: 10px;
}

.stat strong {

    display: block;

    font-size: 35px;

    color: #2563eb;
}

input,
textarea {

    width: 100%;

    padding: 12px;

    margin: 8px 0 15px;

    border:
        1px solid #cbd5e1;

    border-radius: 7px;
}

button,
.btn {

    display: inline-block;

    padding: 11px 18px;

    border: none;

    border-radius: 7px;

    background: #2563eb;

    color: white;

    text-decoration: none;

    cursor: pointer;
}

.green {

    background: #16a34a;
}

.red {

    background: #dc2626;
}

table {

    width: 100%;

    border-collapse: collapse;
}

th,
td {

    padding: 13px;

    border-bottom:
        1px solid #e5e7eb;

    text-align: left;
}

.hash {

    max-width: 280px;

    word-break: break-all;

    font-family: monospace;

    font-size: 11px;
}

.ai-header {

    background: #111827;

    color: white;

    padding: 25px;

    border-radius: 12px;

    margin-bottom: 20px;
}

.prediction {

    font-size: 30px;

    font-weight: bold;

    margin: 20px 0;
}

.phishing {

    color: #dc2626;
}

.legitimate {

    color: #16a34a;
}

.risk {

    font-size: 26px;

    margin-bottom: 15px;
}

.progress {

    width: 100%;

    height: 25px;

    background: #e5e7eb;

    border-radius: 20px;

    overflow: hidden;
}

.progress-bar {

    height: 100%;

    background:
        linear-gradient(
            90deg,
            #facc15,
            #ef4444
        );
}

.feature {

    margin: 22px 0;
}

.feature-bar {

    height: 17px;

    background: #e5e7eb;

    border-radius: 20px;

    overflow: hidden;

    margin: 7px 0;
}

.feature-fill {

    height: 100%;

    background: #ef4444;
}

code {

    background: #fee2e2;

    color: #991b1b;

    padding: 3px 6px;

    margin-right: 5px;

    border-radius: 4px;
}

.reason {

    padding: 14px;

    background: #f8fafc;

    border-left:
        4px solid #ef4444;

    margin: 8px 0;
}

.model-feature {

    display: flex;

    justify-content: space-between;

    padding: 12px;

    background: #f8fafc;

    margin: 5px 0;

    font-family: monospace;
}

.positive {

    color: #dc2626;

    font-weight: bold;
}

.negative {

    color: #16a34a;

    font-weight: bold;
}

.alert {

    padding: 15px;

    margin-bottom: 20px;

    border-radius: 7px;
}

.success {

    background: #dcfce7;

    color: #166534;
}

.danger {

    background: #fee2e2;

    color: #991b1b;
}

.login {

    max-width: 450px;

    margin: 100px auto;

    background: white;

    padding: 35px;

    border-radius: 12px;

    box-shadow:
        0 5px 25px
        rgba(0,0,0,.08);
}

@media(max-width:800px) {

    .stats {

        grid-template-columns: 1fr;
    }

    nav {

        flex-direction: column;

        gap: 15px;
    }

    table {

        display: block;

        overflow-x: auto;
    }
}

"""


# ============================================================
# HTML TEMPLATES
# ============================================================

BASE = """

<!DOCTYPE html>

<html>

<head>

<title>
{{ title }}
</title>

<meta
    name="viewport"
    content="width=device-width,initial-scale=1"
>

<style>
{{ css }}
</style>

</head>

<body>

<nav>

<div class="logo">

🔐 CYBER CRIME EVIDENCE VAULT

</div>

<div>

{% if session.get("user_id") %}

<a href="/dashboard">
Dashboard
</a>

<a href="/cases">
Cases
</a>

<a href="/logout">
Logout
</a>

{% endif %}

</div>

</nav>

<div class="container">

{% with messages =
get_flashed_messages(
with_categories=true
) %}

{% for category, message in messages %}

<div class="alert {{ category }}">

{{ message }}

</div>

{% endfor %}

{% endwith %}

{{ content|safe }}

</div>

</body>

</html>

"""


def page(content, title=APP_NAME):

    return render_template_string(

        BASE,

        title=title,

        css=CSS,

        content=content
    )


# ============================================================
# LOGIN
# ============================================================

@app.route(
    "/",
    methods=["GET"]
)
def home():

    if session.get("user_id"):

        return redirect(
            "/dashboard"
        )

    return redirect(
        "/login"
    )


@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        )

        password = request.form.get(
            "password",
            ""
        )


        connection = db()


        user = connection.execute(
            """
            SELECT *
            FROM users
            WHERE username=?
            AND password=?
            """,
            (
                username,
                password
            )
        ).fetchone()


        connection.close()


        if user:

            session["user_id"] = user["id"]

            session["username"] = (
                user["username"]
            )

            return redirect(
                "/dashboard"
            )


        flash(
            "Invalid username or password",
            "danger"
        )


    content = """

    <div class="login">

    <h1>
    🔐 Evidence Vault
    </h1>

    <p>
    Explainable AI Cyber Crime
    Investigation System
    </p>

    <form method="POST">

    <input
        name="username"
        placeholder="Username"
        required
    >

    <input
        name="password"
        type="password"
        placeholder="Password"
        required
    >

    <button>
    Login
    </button>

    </form>

    </div>

    """

    return page(
        content,
        "Login"
    )


@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        "/login"
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
def dashboard():

    if not session.get("user_id"):

        return redirect(
            "/login"
        )


    connection = db()


    case_count = connection.execute(
        "SELECT COUNT(*) AS c FROM cases"
    ).fetchone()["c"]


    evidence_count = connection.execute(
        "SELECT COUNT(*) AS c FROM evidence"
    ).fetchone()["c"]


    ai_count = connection.execute(
        "SELECT COUNT(*) AS c FROM ai_analysis"
    ).fetchone()["c"]


    recent = connection.execute(
        """
        SELECT
            evidence.*,
            cases.case_number
        FROM evidence
        JOIN cases
        ON cases.id=evidence.case_id
        ORDER BY evidence.id DESC
        LIMIT 10
        """
    ).fetchall()


    connection.close()


    rows = ""


    for item in recent:

        rows += f"""

        <tr>

        <td>
        {item["evidence_id"]}
        </td>

        <td>
        {item["case_number"]}
        </td>

        <td>
        {item["filename"]}
        </td>

        <td>

        <a
        class="btn"
        href="/evidence/{item["id"]}/ai"
        >
        AI Analysis
        </a>

        </td>

        </tr>

        """


    content = f"""

    <h1>
    Cyber Crime Evidence Vault
    </h1>

    <p>
    Explainable AI Investigation Dashboard
    </p>


    <div class="stats">

    <div class="stat">

    <h3>
    Cases
    </h3>

    <strong>
    {case_count}
    </strong>

    </div>


    <div class="stat">

    <h3>
    Evidence
    </h3>

    <strong>
    {evidence_count}
    </strong>

    </div>


    <div class="stat">

    <h3>
    AI Analyses
    </h3>

    <strong>
    {ai_count}
    </strong>

    </div>

    </div>


    <div class="panel">

    <h2>
    Recent Evidence
    </h2>

    <table>

    <tr>

    <th>
    Evidence
    </th>

    <th>
    Case
    </th>

    <th>
    Filename
    </th>

    <th>
    Action
    </th>

    </tr>

    {rows}

    </table>

    </div>

    """

    return page(
        content,
        "Dashboard"
    )


# ============================================================
# CASES
# ============================================================

@app.route("/cases")
def cases():

    if not session.get("user_id"):

        return redirect(
            "/login"
        )


    connection = db()


    case_rows = connection.execute(
        """
        SELECT *
        FROM cases
        ORDER BY id DESC
        """
    ).fetchall()


    connection.close()


    rows = ""


    for case in case_rows:

        rows += f"""

        <tr>

        <td>
        {case["case_number"]}
        </td>

        <td>
        {case["title"]}
        </td>

        <td>
        {case["created_at"]}
        </td>

        <td>

        <a
        class="btn"
        href="/cases/{case["id"]}"
        >
        Open
        </a>

        </td>

        </tr>

        """


    content = f"""

    <h1>
    Investigation Cases
    </h1>


    <div class="panel">

    <h2>
    Create New Case
    </h2>

    <form
    method="POST"
    action="/cases/create"
    >

    <input
    name="title"
    placeholder="Case title"
    required
    >

    <textarea
    name="description"
    placeholder="Case description"
    ></textarea>

    <button>
    Create Case
    </button>

    </form>

    </div>


    <div class="panel">

    <table>

    <tr>

    <th>
    Case Number
    </th>

    <th>
    Title
    </th>

    <th>
    Created
    </th>

    <th>
    Action
    </th>

    </tr>

    {rows}

    </table>

    </div>

    """

    return page(
        content,
        "Cases"
    )


@app.route(
    "/cases/create",
    methods=["POST"]
)
def create_case():

    title = request.form.get(
        "title",
        ""
    )

    description = request.form.get(
        "description",
        ""
    )


    case_number = (
        "CASE-"
        +
        secrets.token_hex(4).upper()
    )


    connection = db()


    connection.execute(
        """
        INSERT INTO cases
        (
            case_number,
            title,
            description,
            created_at,
            created_by
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            case_number,
            title,
            description,
            timestamp(),
            session.get("user_id")
        )
    )


    connection.commit()

    connection.close()


    flash(
        "Case created successfully",
        "success"
    )


    return redirect(
        "/cases"
    )


# ============================================================
# CASE DETAILS
# ============================================================

@app.route(
    "/cases/<int:case_id>"
)
def case_details(case_id):

    connection = db()


    case = connection.execute(
        """
        SELECT *
        FROM cases
        WHERE id=?
        """,
        (case_id,)
    ).fetchone()


    evidence_rows = connection.execute(
        """
        SELECT *
        FROM evidence
        WHERE case_id=?
        ORDER BY id DESC
        """,
        (case_id,)
    ).fetchall()


    connection.close()


    if not case:

        return "Case not found", 404


    rows = ""


    for item in evidence_rows:

        rows += f"""

        <tr>

        <td>
        {item["evidence_id"]}
        </td>

        <td>
        {item["filename"]}
        </td>

        <td class="hash">
        {item["sha256"]}
        </td>

        <td>

        <a
        class="btn"
        href="/evidence/{item["id"]}/ai"
        >
        AI Analysis
        </a>

        <a
        class="btn green"
        href="/evidence/{item["id"]}/verify"
        >
        Verify SHA-256
        </a>

        </td>

        </tr>

        """


    content = f"""

    <h1>
    {case["title"]}
    </h1>

    <p>
    Case:
    <strong>
    {case["case_number"]}
    </strong>
    </p>


    <div class="panel">

    <p>
    {case["description"] or ""}
    </p>

    <a
    class="btn"
    href="/cases/{case_id}/upload"
    >
    + Add Evidence
    </a>

    </div>


    <div class="panel">

    <h2>
    Evidence Vault
    </h2>

    <table>

    <tr>

    <th>
    Evidence ID
    </th>

    <th>
    Filename
    </th>

    <th>
    SHA-256
    </th>

    <th>
    Actions
    </th>

    </tr>

    {rows}

    </table>

    </div>

    """

    return page(
        content,
        case["case_number"]
    )


# ============================================================
# UPLOAD EVIDENCE
# ============================================================

@app.route(
    "/cases/<int:case_id>/upload",
    methods=["GET", "POST"]
)
def upload(case_id):

    connection = db()


    case = connection.execute(
        """
        SELECT *
        FROM cases
        WHERE id=?
        """,
        (case_id,)
    ).fetchone()


    if not case:

        connection.close()

        return "Case not found", 404


    if request.method == "POST":

        uploaded_file = request.files.get(
            "evidence"
        )

        content = request.form.get(
            "content",
            ""
        )


        if not uploaded_file:

            flash(
                "Please select an evidence file",
                "danger"
            )

            connection.close()

            return redirect(
                request.url
            )


        original_name = (
            uploaded_file.filename
            or
            "evidence.txt"
        )


        evidence_id = (
            "EV-"
            +
            secrets.token_hex(3).upper()
        )


        safe_name = re.sub(
            r"[^A-Za-z0-9._-]",
            "_",
            original_name
        )


        stored_name = (
            evidence_id
            +
            "_"
            +
            safe_name
        )


        filepath = os.path.join(
            EVIDENCE_DIR,
            stored_name
        )


        uploaded_file.save(
            filepath
        )


        file_hash = calculate_sha256(
            filepath
        )


        connection.execute(
            """
            INSERT INTO evidence
            (
                evidence_id,
                case_id,
                filename,
                stored_filename,
                sha256,
                content,
                uploaded_by,
                uploaded_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evidence_id,
                case_id,
                original_name,
                stored_name,
                file_hash,
                content,
                session.get("user_id"),
                timestamp()
            )
        )


        evidence_db_id = (
            connection
            .execute(
                "SELECT last_insert_rowid()"
            )
            .fetchone()[0]
        )


        connection.execute(
            """
            INSERT INTO custody
            (
                evidence_id,
                action,
                notes,
                timestamp
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                evidence_db_id,
                "EVIDENCE_ACQUIRED",
                "Evidence entered into vault",
                timestamp()
            )
        )


        connection.commit()

        connection.close()


        flash(
            f"Evidence {evidence_id} "
            f"successfully added.",
            "success"
        )


        return redirect(
            f"/cases/{case_id}"
        )


    connection.close()


    content = f"""

    <h1>
    Add Evidence
    </h1>

    <div class="panel">

    <h2>
    {case["case_number"]}
    </h2>

    <form
    method="POST"
    enctype="multipart/form-data"
    >

    <label>
    Evidence File
    </label>

    <input
    type="file"
    name="evidence"
    required
    >


    <label>
    Email / Message / Log Content
    </label>

    <textarea
    name="content"
    rows="15"
    placeholder="Paste the evidence text here for AI analysis..."
    ></textarea>


    <button>
    Upload Evidence
    </button>

    </form>

    </div>

    """

    return page(
        content,
        "Add Evidence"
    )


# ============================================================
# AI ANALYSIS
# ============================================================

@app.route(
    "/evidence/<int:evidence_id>/ai"
)
def ai_analysis(evidence_id):

    connection = db()


    evidence = connection.execute(
        """
        SELECT
            evidence.*,
            cases.case_number,
            cases.title
        FROM evidence
        JOIN cases
        ON cases.id=evidence.case_id
        WHERE evidence.id=?
        """,
        (evidence_id,)
    ).fetchone()


    if not evidence:

        connection.close()

        return "Evidence not found", 404


    result = explain_ai(
        evidence["content"] or ""
    )


    connection.execute(
        """
        INSERT INTO ai_analysis
        (
            evidence_id,
            prediction,
            risk_score,
            confidence,
            explanation,
            analyzed_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            evidence_id,
            result["label"],
            result["risk"],
            result["confidence"],
            "; ".join(
                result["reasons"]
            ),
            timestamp()
        )
    )


    connection.commit()

    connection.close()


    # ========================================================
    # FEATURE BARS
    # ========================================================

    feature_html = ""


    for index, feature in enumerate(
        result["features"]
    ):

        width = min(
            95,
            45 + index * 8
        )


        matches = ""


        for match in feature["matches"]:

            matches += (
                f"<code>{match}</code>"
            )


        feature_html += f"""

        <div class="feature">

        <strong>
        {feature["name"]}
        </strong>

        <div class="feature-bar">

        <div
        class="feature-fill"
        style="width:{width}%"
        ></div>

        </div>

        <small>
        Detected:
        {matches}
        </small>

        </div>

        """


    if not feature_html:

        feature_html = """

        <p>
        No rule-based security indicators
        were detected.
        </p>

        """


    # ========================================================
    # REASONS
    # ========================================================

    reasons_html = ""


    for reason in result["reasons"]:

        reasons_html += f"""

        <div class="reason">

        ✓ {reason}

        </div>

        """


    # ========================================================
    # MODEL FEATURES
    # ========================================================

    model_html = ""


    for item in result[
        "model_features"
    ]:

        value = item[
            "contribution"
        ]


        if value >= 0:

            color = "positive"

            display = (
                "+"
                +
                f"{value:.4f}"
            )

        else:

            color = "negative"

            display = f"{value:.4f}"


        model_html += f"""

        <div class="model-feature">

        <span>
        {item["feature"]}
        </span>

        <span class="{color}">
        {display}
        </span>

        </div>

        """


    if result["label"] == "PHISHING":

        prediction_html = """

        <div class="prediction phishing">

        🔴 PHISHING

        </div>

        """

    else:

        prediction_html = """

        <div class="prediction legitimate">

        🟢 LIKELY LEGITIMATE

        </div>

        """


    content = f"""

    <div class="ai-header">

    <h1>
    CYBER CRIME EVIDENCE VAULT
    </h1>

    <p>
    Case:
    <strong>
    {evidence["case_number"]}
    </strong>
    </p>

    <p>
    Evidence:
    <strong>
    {evidence["evidence_id"]}
    </strong>
    </p>

    </div>


    <div class="panel">

    <h2>
    AI ANALYSIS
    </h2>

    {prediction_html}


    <div class="risk">

    Risk Score:

    <strong>
    {result["risk"]} / 100
    </strong>

    </div>


    <div class="progress">

    <div
    class="progress-bar"
    style="width:{result["risk"]}%"
    ></div>

    </div>


    <p>

    Model confidence:

    <strong>
    {result["confidence"]}%
    </strong>

    </p>

    </div>


    <div class="panel">

    <h2>

    WHY DID AI CLASSIFY
    THIS EVIDENCE?

    </h2>

    {feature_html}

    </div>


    <div class="panel">

    <h2>
    Evidence Supporting Prediction
    </h2>

    {reasons_html}

    </div>


    <div class="panel">

    <h2>
    Explainable AI Model Features
    </h2>

    <p>

    The values below show the most influential
    TF-IDF features contributing to the
    Logistic Regression prediction.

    Positive values increase phishing probability.
    Negative values push the prediction toward
    legitimate.

    </p>

    {model_html}

    </div>


    <div class="panel">

    <a
    class="btn green"
    href="/evidence/{evidence_id}/verify"
    >
    ✓ Verify SHA-256
    </a>

    <a
    class="btn"
    href="/evidence/{evidence_id}/custody"
    >
    View Chain of Custody
    </a>

    </div>

    """

    return page(
        content,
        "AI Analysis"
    )


# ============================================================
# SHA-256 VERIFICATION
# ============================================================

@app.route(
    "/evidence/<int:evidence_id>/verify"
)
def verify(evidence_id):

    connection = db()


    evidence = connection.execute(
        """
        SELECT *
        FROM evidence
        WHERE id=?
        """,
        (evidence_id,)
    ).fetchone()


    if not evidence:

        connection.close()

        return "Evidence not found", 404


    filepath = os.path.join(
        EVIDENCE_DIR,
        evidence["stored_filename"]
    )


    if not os.path.exists(filepath):

        connection.close()

        flash(
            "Evidence file is missing!",
            "danger"
        )

        return redirect(
            f"/evidence/{evidence_id}/ai"
        )


    current_hash = calculate_sha256(
        filepath
    )


    if current_hash == evidence["sha256"]:

        message = (
            "INTEGRITY VERIFIED: "
            "SHA-256 hash matches the "
            "original evidence."
        )

        category = "success"

    else:

        message = (
            "INTEGRITY FAILURE: "
            "SHA-256 hash does NOT match."
        )

        category = "danger"


    connection.execute(
        """
        INSERT INTO custody
        (
            evidence_id,
            action,
            notes,
            timestamp
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            evidence_id,
            "HASH_VERIFICATION",
            message,
            timestamp()
        )
    )


    connection.commit()

    connection.close()


    flash(
        message,
        category
    )


    return redirect(
        f"/evidence/{evidence_id}/ai"
    )


# ============================================================
# CHAIN OF CUSTODY
# ============================================================

@app.route(
    "/evidence/<int:evidence_id>/custody"
)
def custody(evidence_id):

    connection = db()


    evidence = connection.execute(
        """
        SELECT *
        FROM evidence
        WHERE id=?
        """,
        (evidence_id,)
    ).fetchone()


    logs = connection.execute(
        """
        SELECT *
        FROM custody
        WHERE evidence_id=?
        ORDER BY id ASC
        """,
        (evidence_id,)
    ).fetchall()


    connection.close()


    if not evidence:

        return "Evidence not found", 404


    rows = ""


    for log in logs:

        rows += f"""

        <tr>

        <td>
        {log["timestamp"]}
        </td>

        <td>
        {log["action"]}
        </td>

        <td>
        {log["notes"]}
        </td>

        </tr>

        """


    content = f"""

    <h1>
    Chain of Custody
    </h1>

    <div class="panel">

    <p>
    Evidence ID:
    <strong>
    {evidence["evidence_id"]}
    </strong>
    </p>

    <p class="hash">

    SHA-256:

    {evidence["sha256"]}

    </p>

    </div>


    <div class="panel">

    <table>

    <tr>

    <th>
    Timestamp
    </th>

    <th>
    Action
    </th>

    <th>
    Notes
    </th>

    </tr>

    {rows}

    </table>

    </div>

    """

    return page(
        content,
        "Chain of Custody"
    )


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 60)
    print(" CYBER CRIME EVIDENCE VAULT")
    print(" EXPLAINABLE AI INVESTIGATION SYSTEM")
    print("=" * 60)
    print()
    print("Login:")
    print("Username: admin")
    print("Password:", os.environ.get("ADMIN_PASSWORD", "Avishkar@2026!"))
    print()

    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get("FLASK_DEBUG", "1") == "1"

    print("Open:")
    print(f"http://127.0.0.1:{port}")
    print()

    host = os.environ.get("HOST", "127.0.0.1")

    app.run(
        host=host,
        port=port,
        debug=debug_mode
    )
