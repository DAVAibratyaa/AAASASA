import wsgi

from flask import Flask, request, render_template, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, upgrade
from oauthlib.oauth2 import WebApplicationClient
import requests
import json
import anthropic
import os
import aiohttp
import asyncio

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'Provethem123!')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql+psycopg2://laudai_vwgi_user:6S1inmLx2UOQqT4C1Z8K7ZIk20V4jFwz@dpg-cp7pd8uv3ddc73d9bcjg-a/laudai_vwgi')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_POOL_SIZE'] = 20
app.config['SQLALCHEMY_MAX_OVERFLOW'] = 40

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Google OAuth2 configuration
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID', "99134204430-qo0r2sthhpivu0itk0ddblj5b9q8581v.apps.googleusercontent.com")
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET', "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")
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

client = WebApplicationClient(GOOGLE_CLIENT_ID)

anthropic_client = anthropic.Anthropic(
    api_key=os.getenv('ANTHROPIC_API_KEY', "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")
)

wordware_api_keys_prompts = [
    {
        "api_key": os.getenv('WORDWARE_API_KEY_1', "ww-7tpVErWCpVnbC6vwuPLJiS9symSimSsiBrPRZdw5HM9txIWcKGzOL"),
        "prompt_id": "ad13d448-f7fe-4ce9-9119-686ff9e21317"
    },
    {
        "api_key": os.getenv('WORDWARE_API_KEY_2', "ww-7tpVErWCpVnbC6vwuPLJiS9symSimSsiBrPRZdw5HM9txIWcKGzOL"),
        "prompt_id": "ad13d448-f7fe-4ce9-9119-686ff9e21317"
    },
    {
        "api_key": os.getenv('WORDWARE_API_KEY_3', "ww-7tpVErWCpVnbC6vwuPLJiS9symSimSsiBrPRZdw5HM9txIWcKGzOL"),
        "prompt_id": "ad13d448-f7fe-4ce9-9119-686ff9e21317"
    }
]

# Database models
class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    exame = db.Column(db.Text, nullable=True)
    achados = db.Column(db.Text, nullable=True)
    laudo = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.String(1000), db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    unique_id = db.Column(db.String(500), unique=True, nullable=False)
    email = db.Column(db.String(500), unique=True, nullable=False)
    name = db.Column(db.String(500), nullable=False)
    picture = db.Column(db.String(500), nullable=False)
    total_reports = db.Column(db.Integer, default=0)
    total_time_saved = db.Column(db.Float, default=0.0)

class Template(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(500), nullable=False)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Helper functions
async def fetch_wordware(session, api_key, prompt_id, exame, achados):
    url = f"https://app.wordware.ai/api/prompt/{prompt_id}/run"
    headers = {"Authorization": f"Bearer {api_key}"}
    data = {"inputs": {"exame": exame, "achados": achados}}
    async with session.post(url, json=data, headers=headers) as response:
        if response.status == 200:
            laudo = ""
            async for line in response.content:
                if line:
                    content = json.loads(line.decode('utf-8'))
                    value = content['value']
                    if value['type'] == 'chunk':
                        laudo += value['value']
            return laudo.strip()
    return None

async def generate_report_wordware_async(exame, achados):
    async with aiohttp.ClientSession() as session:
        tasks = []
        for item in wordware_api_keys_prompts:
            task = fetch_wordware(session, item["api_key"], item["prompt_id"], exame, achados)
            tasks.append(task)
        results = await asyncio.gather(*tasks)
        for result in results:
            if result:
                return result
    return None

def generate_report_wordware(exame, achados):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(generate_report_wordware_async(exame, achados))
    finally:
        loop.close()

def generate_report_anthropic(exame, achados):
    try:
        message = anthropic_client.messages.create(
            model="claude-3-haiku-20240307",
            max_tokens=1000,
            temperature=0,
            system="Você atuará como um assistente de IA especializado em radiologia para escrever laudos radiológicos completos e de alta qualidade. Seu objetivo é gerar um laudo estruturado com base nas informações fornecidas pelo usuário sobre o tipo de exame realizado e os achados de imagem.",
            messages=[
                {"role": "user", "content": f"Tipo de Exame: {exame}\n\nAchados: {achados}\n\n"}
            ]
        )
        laudo = message.content[0].text.strip()
        return laudo
    except Exception as e:
        print(f"Error generating report with Anthropic API: {str(e)}")
        return None

def generate_suggestions(laudo):
    api_key = "ww-7tpVErWCpVnbC6vwuPLJiS9symSimSsiBrPRZdw5HM9txIWcKGzOL"
    prompt_id = "0bc60b3f-764f-4421-8e37-4ce9b65ac18e"
    r = requests.post(
        f"https://app.wordware.ai/api/prompt/{prompt_id}/run",
        json={"inputs": {"laudo": laudo}},
        headers={"Authorization": f"Bearer {api_key}"},
        stream=True
    )
    if r.status_code == 200:
        suggestions = ""
        for line in r.iter_lines():
            if line:
                content = json.loads(line.decode('utf-8'))
                value = content['value']
                if value['type'] == 'chunk':
                    suggestions += value['value']
        return json.loads(suggestions.strip())
    else:
        print(f"Request failed with status code {r.status_code}")
        return None

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('profile'))
    return render_template('index.html')

@app.route("/login")
def login():
    google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=url_for("callback", _external=True),
        scope=["openid", "https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"],
    )
    return redirect(request_uri)

@app.route("/login/callback")
def callback():
    code = request.args.get("code")
    google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
    token_endpoint = google_provider_cfg["token_endpoint"]
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )
    client.parse_request_body_response(token_response.text)
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)
    userinfo = userinfo_response.json()
    
    unique_id = userinfo["sub"]
    users_email = userinfo["email"]
    users_name = userinfo["given_name"]
    users_picture = userinfo["picture"]
    
    session['user_id'] = unique_id
    session['user_email'] = users_email
    session['user_name'] = users_name
    session['user_picture'] = users_picture
    
    user = User.query.filter_by(unique_id=unique_id).first()
    if not user:
        user = User(
            unique_id=unique_id,
            email=users_email,
            name=users_name,
            picture=users_picture
        )
        db.session.add(user)
        db.session.commit()
    
    return redirect(url_for("profile"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/profile")
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.filter_by(unique_id=session.get('user_id')).first()
    if user is None:
        session.clear()
        return redirect(url_for('login'))
    
    total_reports = user.total_reports
    time_saved = user.total_time_saved
    ai_accuracy = 95  # Assuming a constant accuracy of 95%
    
    return render_template(
        "profile.html",
        user_picture=user.picture,
        current_user=user.name,
        user_email=user.email,
        total_reports=total_reports,
        time_saved=time_saved,
        ai_accuracy=ai_accuracy,
        achievements={
            'experienced_radiologist': user.total_reports > 100,
            'max_efficiency': user.total_time_saved > 10,
            'exceptional_accuracy': ai_accuracy > 90,
        }
    )

@app.route("/generate_report", methods=["GET", "POST"])
def generate_report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.filter_by(unique_id=session['user_id']).first()
    templates = Template.query.filter_by(user_id=user.id).all()
    
    if request.method == "POST":
        exame = request.form["exame"]
        achados = request.form["achados"]
        existing_laudo = request.form.get("existing_laudo", "")
        suggestion = request.form.get("suggestion", "")
        
        if existing_laudo and suggestion:
            combined_achados = f"{existing_laudo}\n\nSugestão aplicada: {suggestion}"
        elif existing_laudo:
            combined_achados = f"{existing_laudo}\n\nAchados adicionais: {achados}"
        else:
            combined_achados = achados
        
        laudo = generate_report_wordware(exame, combined_achados)
        if laudo is None:
            laudo = generate_report_anthropic(exame, combined_achados)
        
        if laudo is None:
            flash("Falha ao gerar o laudo. Tente novamente mais tarde.", "error")
            return redirect(url_for('generate_report'))
        
        suggestions = generate_suggestions(laudo)
        
        report = Report(
            exame=exame,
            achados=combined_achados,
            laudo=laudo,
            user_id=user.id
        )
        
        try:
            db.session.add(report)
            db.session.commit()
            user.total_reports += 1
            user.total_time_saved += 0.09
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash(f"Falha ao salvar o laudo: {str(e)}", "error")
            return redirect(url_for('generate_report'))
        
        return render_template('result.html', laudo=laudo, suggestions=suggestions)
    else:
        return render_template("generate_report.html", templates=templates)

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
def meus_laudos():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.filter_by(unique_id=session.get('user_id')).first()
    page = request.args.get('page', 1, type=int)
    reports_paginated = Report.query.filter_by(user_id=str(user.id)).order_by(Report.created_at.desc()).paginate(page=page, per_page=25)
    return render_template('meus_laudos.html', reports=reports_paginated.items, next_page=reports_paginated.next_num if reports_paginated.has_next else None, prev_page=reports_paginated.prev_num if reports_paginated.has_prev else None)

@app.route('/report/<int:report_id>')
def get_report(report_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    report = Report.query.get_or_404(report_id)
    if report.user_id != User.query.filter_by(unique_id=session.get('user_id')).first().id:
        return jsonify({"error": "Unauthorized access"}), 401
    return jsonify({
        'exame': report.exame,
        'achados': report.achados,
        'laudo': report.laudo
    })

@app.route('/templates', methods=["GET", "POST"])
def templates():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == "POST":
        template_name = request.form["template_name"]
        template_content = request.form["template_content"]
        template_id = request.form.get("template_id")
        
        if template_id:
            template = Template.query.get(template_id)
            if template.user_id != User.query.filter_by(unique_id=session['user_id']).first().id:
                flash("Unauthorized access to edit this template", "danger")
                return redirect(url_for('templates'))
            template.name = template_name
            template.content = template_content
        else:
            template = Template(
                name=template_name,
                content=template_content,
                user_id=User.query.filter_by(unique_id=session['user_id']).first().id
            )
            db.session.add(template)
        
        try:
            db.session.commit()
            flash("Template saved successfully", "success")
        except Exception as e:
            db.session.rollback()
            flash("Failed to save the template to the database.", "danger")
            print(f"Error saving template to the database: {str(e)}")
        
        return redirect(url_for('templates'))
    else:
        user = User.query.filter_by(unique_id=session.get('user_id')).first()
        templates = Template.query.filter_by(user_id=user.id).all()
        return render_template("templates.html", templates=templates)

@app.route('/template/<int:template_id>', methods=['GET', 'DELETE'])
def template(template_id):
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized access"}), 401
    
    template = Template.query.get_or_404(template_id)
    
    if request.method == 'GET':
        if template.user_id != User.query.filter_by(unique_id=session.get('user_id')).first().id:
            return jsonify({"error": "Unauthorized access"}), 401
        return jsonify({
            'id': template.id,
            'name': template.name,
            'content': template.content
        })
    
    if request.method == 'DELETE':
        if template.user_id != User.query.filter_by(unique_id=session.get('user_id')).first().id:
            return jsonify({"error": "Unauthorized access"}), 401
        try:
            db.session.delete(template)
            db.session.commit()
            return jsonify({"success": "Template deleted"}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    with app.app_context():
        upgrade()
    app.run(host="0.0.0.0", port=5000)

wsgi_app = app.wsgi_app
