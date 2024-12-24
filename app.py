import os
import requests
import logging
from datetime import datetime
from flask import (
    Flask, request, render_template, redirect, url_for, flash, session, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, upgrade
from oauthlib.oauth2 import WebApplicationClient
import asyncio
from functools import wraps

# If you're using Anthropic or OpenAI, uncomment:
# from anthropic import Anthropic
# from openai import AsyncOpenAI

# --------------------------------------------------------------------------------
# Logging Configuration
# --------------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------------
# Flask Application Setup
# --------------------------------------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "sua_chave_secreta")  # change in production
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///app.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_POOL_SIZE"] = 20
app.config["SQLALCHEMY_MAX_OVERFLOW"] = 40

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# --------------------------------------------------------------------------------
# OAuth2 Setup (Google)
# --------------------------------------------------------------------------------
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
client = WebApplicationClient(GOOGLE_CLIENT_ID)

# --------------------------------------------------------------------------------
# If you use Anthropic/OpenAI
# --------------------------------------------------------------------------------
# anthropic_client = Anthropic(
#     api_key=os.getenv("ANTHROPIC_API_KEY"),
#     default_headers={"anthropic-beta": "prompt-caching-2024-07-31"}
# )
# openai_client = AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# --------------------------------------------------------------------------------
# Database Models
# --------------------------------------------------------------------------------
class Report(db.Model):
    """Stores reports generated for each user."""
    id = db.Column(db.Integer, primary_key=True)
    exame = db.Column(db.Text, nullable=True)
    achados = db.Column(db.Text, nullable=True)
    laudo = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

class User(db.Model):
    """Represents the user who logs in via Google OAuth."""
    id = db.Column(db.Integer, primary_key=True)
    unique_id = db.Column(db.String(500), unique=True, nullable=False)
    email = db.Column(db.String(500), unique=True, nullable=False)
    name = db.Column(db.String(500), nullable=False)
    picture = db.Column(db.String(500), nullable=False)
    total_reports = db.Column(db.Integer, default=0)
    total_time_saved = db.Column(db.Float, default=0.0)

class Template(db.Model):
    """Stores user-defined templates for reuse."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(500), nullable=False)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

# --------------------------------------------------------------------------------
# Decorator for routes requiring login
# --------------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash('Por favor, faça login para acessar esta página.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --------------------------------------------------------------------------------
# Inject Current Year into Templates
# --------------------------------------------------------------------------------
@app.context_processor
def inject_year():
    """Injects get_year() for dynamic use in Jinja templates."""
    return dict(get_year=lambda: datetime.now().year)

# --------------------------------------------------------------------------------
# Placeholder for generating a laudo with Anthropic (or any AI)
# --------------------------------------------------------------------------------
def generate_report_anthropic(exame, achados):
    """Fake or real logic to generate a radiology report from given data."""
    try:
        logger.info(f"[FAKE] Generating report for exame: {exame[:50]} ...")
        # If using real Anthropic, you'd do something like:
        # response = anthropic_client.messages.create(...)
        # return response.content[0].text

        # For now, just return a placeholder text:
        return f"Laudo gerado para exame: {exame}, Achados: {achados}."
    except Exception as e:
        logger.error(f"Erro ao gerar relatório: {str(e)}")
        return None

# --------------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------------
@app.route("/")
def index():
    """If user is logged in, go to profile; otherwise, show index."""
    if "user_id" in session:
        return redirect(url_for("profile"))
    return render_template("index.html")

@app.route("/login")
def login():
    """Starts Google OAuth login."""
    google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=url_for("callback", _external=True),
        scope=[
            "openid",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile",
        ],
    )
    return redirect(request_uri)

@app.route("/login/callback")
def callback():
    """OAuth callback route."""
    code = request.args.get("code")
    google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
    token_endpoint = google_provider_cfg["token_endpoint"]
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code,
    )
    token_response = requests.post(token_url, headers=headers, data=body,
                                   auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET))
    client.parse_request_body_response(token_response.text)

    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)
    userinfo = userinfo_response.json()

    unique_id = userinfo["sub"]
    users_email = userinfo["email"]
    users_name = userinfo["given_name"]
    users_picture = userinfo["picture"]

    # Save user data to session
    session["user_id"] = unique_id
    session["user_email"] = users_email
    session["user_name"] = users_name
    session["user_picture"] = users_picture

    # Check if user is in DB
    user = User.query.filter_by(unique_id=unique_id).first()
    if not user:
        user = User(
            unique_id=unique_id,
            email=users_email,
            name=users_name,
            picture=users_picture,
        )
        db.session.add(user)
        db.session.commit()

    return redirect(url_for("profile"))

@app.route("/logout")
def logout():
    """Logs user out and clears session."""
    session.clear()
    flash('Você foi desconectado.', 'success')
    return redirect(url_for("index"))

@app.route("/profile")
@login_required
def profile():
    """Shows user profile page."""
    user = User.query.filter_by(unique_id=session.get("user_id")).first()
    if not user:
        session.clear()
        flash('Usuário não encontrado.', 'danger')
        return redirect(url_for("login"))

    return render_template(
        "profile.html",
        user_picture=user.picture,
        current_user=user.name,
        user_email=user.email,
        total_reports=user.total_reports,
        time_saved=user.total_time_saved,
        ai_accuracy=95,
        achievements={
            "experienced_radiologist": user.total_reports > 100,
            "max_efficiency": user.total_time_saved > 10,
            "exceptional_accuracy": 95 > 90,
        },
    )

@app.route("/generate_report", methods=["GET", "POST"])
@login_required
def generate_report():
    """Generates a new radiology report from user input."""
    logger.info("Entrando em generate_report")
    user = User.query.filter_by(unique_id=session["user_id"]).first()

    if request.method == "POST":
        exame = request.form.get("exame")
        achados = request.form.get("achados")

        if not exame or not achados:
            flash('Preencha todos os campos obrigatórios.', 'danger')
            return redirect(url_for('generate_report'))

        laudo = generate_report_anthropic(exame, achados)
        if laudo is None:
            flash('Falha ao gerar o laudo.', 'danger')
            return redirect(url_for('generate_report'))

        report = Report(
            exame=exame,
            achados=achados,
            laudo=laudo,
            user_id=user.id
        )
        try:
            db.session.add(report)
            user.total_reports += 1
            user.total_time_saved += 0.09
            db.session.commit()
            flash('Laudo gerado com sucesso!', 'success')
            return redirect(url_for('result', report_id=report.id))
        except Exception as e:
            db.session.rollback()
            logger.error(f"DB error: {str(e)}")
            flash('Erro ao salvar o laudo.', 'danger')
            return redirect(url_for('generate_report'))

    # GET method
    templates_list = Template.query.filter_by(user_id=user.id).all()
    return render_template("generate_report.html", templates=templates_list,
                           user_picture=user.picture)

@app.route('/result/<int:report_id>')
@login_required
def result(report_id):
    """Displays the final generated report."""
    user = User.query.filter_by(unique_id=session.get('user_id')).first()
    if not user:
        flash('Usuário não encontrado.', 'danger')
        return redirect(url_for('login'))

    report = Report.query.get_or_404(report_id)
    if report.user_id != user.id:
        flash("Acesso não autorizado.", "danger")
        return redirect(url_for('generate_report'))

    return render_template('result.html', laudo=report.laudo, user_picture=user.picture)

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/services')
def services():
    return render_template('services.html')

@app.route('/carreiras')
def carreiras():
    return render_template('carreiras.html')

@app.route('/meus_laudos')
@login_required
def meus_laudos():
    """Shows paginated user’s reports."""
    user = User.query.filter_by(unique_id=session.get('user_id')).first()
    if not user:
        flash('Usuário não encontrado.', 'danger')
        return redirect(url_for('login'))

    page = request.args.get('page', 1, type=int)
    reports_paginated = (
        Report.query.filter_by(user_id=user.id)
        .order_by(Report.created_at.desc())
        .paginate(page=page, per_page=10)
    )

    return render_template(
        "meus_laudos.html",
        reports=reports_paginated.items,
        next_page=reports_paginated.next_num if reports_paginated.has_next else None,
        prev_page=reports_paginated.prev_num if reports_paginated.has_prev else None,
        user_picture=user.picture
    )

@app.route("/report/<int:report_id>", methods=["GET"])
@login_required
def get_report(report_id):
    """Returns a JSON representation of a report (API usage)."""
    user = User.query.filter_by(unique_id=session.get("user_id")).first()
    if not user:
        return jsonify({"error": "Acesso não autorizado"}), 401

    report = Report.query.get_or_404(report_id)
    if report.user_id != user.id:
        return jsonify({"error": "Acesso não autorizado"}), 401

    return jsonify({
        "exame": report.exame,
        "achados": report.achados,
        "laudo": report.laudo
    }), 200

@app.route("/templates", methods=["GET", "POST"], endpoint="templates")
@login_required
def templates_route():
    """
    Manages the user’s templates. 
    endpoint="templates" so you can do url_for('templates').
    """
    user = User.query.filter_by(unique_id=session.get("user_id")).first()

    if request.method == "POST":
        template_name = request.form["template_name"]
        template_content = request.form["template_content"]
        template_id = request.form.get("template_id")

        if template_id:
            tmpl = Template.query.get(template_id)
            if tmpl.user_id != user.id:
                flash("Acesso não autorizado para editar este template.", "danger")
                return redirect(url_for("templates"))
            tmpl.name = template_name
            tmpl.content = template_content
        else:
            tmpl = Template(
                name=template_name,
                content=template_content,
                user_id=user.id
            )
            db.session.add(tmpl)

        try:
            db.session.commit()
            flash("Template salvo com sucesso!", "success")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Erro ao salvar template: {str(e)}")
            flash("Falha ao salvar template.", "danger")

        return redirect(url_for("templates"))

    # GET method
    user_templates = Template.query.filter_by(user_id=user.id).all()
    return render_template("templates.html", templates=user_templates, user_picture=user.picture)

@app.route("/template/<int:template_id>", methods=["GET", "DELETE"])
@login_required
def template_detail(template_id):
    """Returns or deletes a template as JSON."""
    user = User.query.filter_by(unique_id=session.get("user_id")).first()
    tmpl = Template.query.get_or_404(template_id)

    if tmpl.user_id != user.id:
        return jsonify({"error": "Acesso não autorizado"}), 401

    if request.method == "GET":
        return jsonify({
            "id": tmpl.id,
            "name": tmpl.name,
            "content": tmpl.content
        })

    if request.method == "DELETE":
        try:
            db.session.delete(tmpl)
            db.session.commit()
            return jsonify({"success": "Template deletado"}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({"error": str(e)}), 500

@app.route('/search_laudos', methods=["GET"])
@login_required
def search_laudos():
    """Simple search on the user’s reports, returns JSON."""
    user = User.query.filter_by(unique_id=session.get('user_id')).first()
    query = request.args.get('query', '')
    if not query:
        return jsonify({'error': 'Consulta vazia.'}), 400

    results = Report.query.filter(
        Report.user_id == user.id,
        (Report.exame.ilike(f'%{query}%') |
         Report.achados.ilike(f'%{query}%') |
         Report.laudo.ilike(f'%{query}%'))
    ).all()

    return jsonify([{
        'id': r.id,
        'exame': r.exame,
        'achados': r.achados,
        'laudo': r.laudo
    } for r in results])

@app.route('/apply_suggestion', methods=["POST"])
@login_required
def apply_suggestion():
    """Applies a suggestion to the laudo text (example logic)."""
    data = request.get_json()
    current_laudo = data.get('current_laudo', '')
    suggestion = data.get('suggestion', '')

    if not suggestion:
        return jsonify({"error": "Sugestão inválida."}), 400

    # Example: just append the suggestion
    updated_laudo = f"{current_laudo}\n\nSugestão: {suggestion}"
    return jsonify({"laudo": updated_laudo, "suggestions": []}), 200

@app.route('/save_laudo', methods=["POST"])
@login_required
def save_laudo():
    """Saves laudo text to the last user report."""
    data = request.get_json()
    laudo = data.get('laudo', '')

    user = User.query.filter_by(unique_id=session.get("user_id")).first()
    if not user:
        return jsonify({"error": "Usuário não encontrado."}), 404

    last_report = Report.query.filter_by(user_id=user.id).order_by(Report.created_at.desc()).first()
    if not last_report:
        return jsonify({"error": "Nenhum relatório encontrado."}), 404

    last_report.laudo = laudo
    try:
        db.session.commit()
        return jsonify({"message": "Laudo salvo com sucesso!"}), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao salvar laudo: {str(e)}")
        return jsonify({"error": "Falha ao salvar."}), 500

# --------------------------------------------------------------------------------
# Error Handlers
# --------------------------------------------------------------------------------
@app.errorhandler(404)
def not_found_error(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_error(e):
    return render_template("500.html"), 500

# --------------------------------------------------------------------------------
# Main Execution
# --------------------------------------------------------------------------------
if __name__ == "__main__":
    with app.app_context():
        upgrade()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
