import os
import logging
import re
import json
import requests
import pandas as pd
import random
from flask import Flask, render_template, request, jsonify, redirect, url_for
from werkzeug.utils import secure_filename 
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from twilio.twiml.messaging_response import MessagingResponse
from twilio.rest import Client
from datetime import datetime, timedelta
from sqlalchemy import func, or_
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

# --- CONFIGURACIÓN ---
logging.basicConfig(level=logging.INFO)
load_dotenv()

app = Flask(__name__, template_folder='templates')

# --- CONFIGURACIÓN DE LA BASE DE DATOS ---
db_uri = os.getenv('DATABASE_URL')
if db_uri and db_uri.startswith("postgres://"):
    db_uri = db_uri.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'una-clave-secreta-muy-segura')

db = SQLAlchemy(app)

# --- CONFIGURACIÓN DE FLASK-LOGIN ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'index'
login_manager.login_message = "Por favor, inicia sesión para acceder."
login_manager.login_message_category = "info"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- MODELOS DE LA BASE DE DATOS ---

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(80), nullable=False)
    assigned_roles = db.relationship('BotRole', back_populates='assignee')

class BotRole(db.Model):
    __tablename__ = 'bot_roles'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), unique=True, nullable=False)
    knowledge_base = db.Column(db.Text, nullable=True)
    assignee_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    status = db.Column(db.String(20), default='Activo', nullable=False)
    chats_received = db.Column(db.Integer, default=0)
    chats_pending = db.Column(db.Integer, default=0)
    chats_resolved = db.Column(db.Integer, default=0)
    assignee = db.relationship('User', back_populates='assigned_roles')
    conversations = db.relationship('Conversation', back_populates='bot_role')

class BotConfig(db.Model):
    __tablename__ = 'bot_config'
    id = db.Column(db.Integer, primary_key=True, default=1)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    whatsapp_number = db.Column(db.String(50), nullable=True)
    welcome_message = db.Column(db.Text, nullable=True)

class Conversation(db.Model):
    __tablename__ = 'conversations'
    id = db.Column(db.Integer, primary_key=True)
    user_phone = db.Column(db.String(50), nullable=False, index=True)
    status = db.Column(db.String(20), default='ia_greeting', nullable=False, index=True) 
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    updated_at = db.Column(db.DateTime(timezone=True), onupdate=func.now())
    unread_count = db.Column(db.Integer, default=0)
    bot_role_id = db.Column(db.Integer, db.ForeignKey('bot_roles.id'), nullable=False)
    
    user_display_name = db.Column(db.String(120), nullable=True)
    user_reported_phone = db.Column(db.String(50), nullable=True)
    
    bot_role = db.relationship('BotRole', back_populates='conversations')
    messages = db.relationship('Message', back_populates='conversation', cascade="all, delete-orphan", order_by='Message.timestamp')
    
    import_source = db.Column(db.String(100), nullable=True, default=None) 
    pending_counted = db.Column(db.Boolean, default=False)

    def get_last_message(self):
        if self.messages:
            return sorted(self.messages, key=lambda m: m.timestamp, reverse=True)[0]
        return None

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversations.id'), nullable=False)
    
    # RESTAURADO: Columnas que confirmaste que existen en BD
    sender_type = db.Column(db.String(20), nullable=False, default='user') # 'user', 'agent', 'system'
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime(timezone=True), server_default=func.now())
    
    # RESTAURADO: Columnas multimedia
    message_type = db.Column(db.String(20), default='text', nullable=False) # 'text', 'image', 'video'
    media_url = db.Column(db.String(1024), nullable=True) 

    conversation = db.relationship('Conversation', back_populates='messages')

class PolicyData(db.Model):
    __tablename__ = 'policy_data'
    id = db.Column(db.Integer, primary_key=True)
    aseguradora = db.Column(db.String(255), nullable=True)
    nombres = db.Column(db.String(255), nullable=True, index=True)
    cedula_nit = db.Column(db.String(100), nullable=True, index=True)
    tipo = db.Column(db.String(100), nullable=True)
    placa = db.Column(db.String(100), nullable=True, index=True)
    modelo = db.Column(db.String(100), nullable=True)
    valor_poliza = db.Column(db.String(100), nullable=True)
    mes_vencimiento = db.Column(db.String(100), nullable=True)
    fecha_venc = db.Column(db.String(100), nullable=True)
    referencia = db.Column(db.String(255), nullable=True)

# --- RUTAS BÁSICAS (FRONTEND) ---
@app.route('/')
def index(): return render_template('Index.html') 

@app.route('/menu_admin')
@login_required
def menu_admin():
    if current_user.role != 'Admin': return redirect(url_for('menu_soporte'))
    return render_template('Menu.html') 

@app.route('/menu_soporte')
@login_required
def menu_soporte():
    if current_user.role != 'Soporte': return redirect(url_for('menu_admin'))
    return render_template('Menu_Soporte.html') 

@app.route('/page/<path:page_name>')
@login_required
def show_page(page_name):
    if not page_name.endswith('.html'): return "Not Found", 404
    admin_pages = ['Bot.html', 'Usuarios.html', 'Configuracion.html', 'Dashboard.html'] 
    if current_user.role == 'Soporte' and page_name in admin_pages: return redirect(url_for('menu_soporte'))
    return render_template(page_name, current_user=current_user)

# --- API LOGIN/LOGOUT ---
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data.get('username')).first()
    if user and user.password == data.get('password'):
        login_user(user)
        redirect_url = url_for('menu_admin' if user.role == 'Admin' else 'menu_soporte')
        return jsonify({"success": True, "redirect_url": redirect_url})
    return jsonify({"success": False, "message": "Usuario o contraseña incorrectos"}), 401

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({"success": True, "redirect_url": url_for('index')})

# --- FUNCIONES AUXILIARES ---
def send_reply(phone_number, message_content):
    """Envía mensaje al bot de Baileys"""
    baileys_bot_url = os.getenv('BAILEYS_BOT_URL')
    if not baileys_bot_url: return False
    try:
        requests.post(f"{baileys_bot_url}/send", json={"number": phone_number, "message": message_content}, timeout=30)
        return True
    except Exception as e:
        logging.error(f"Error enviando a Baileys: {e}")
        return False

def get_random_active_role(base_role_title):
    """Balanceo de carga de roles"""
    possible_roles = BotRole.query.filter(or_(BotRole.title == base_role_title, BotRole.title.like(f"{base_role_title}_%")), BotRole.status == 'Activo').all()
    return random.choice(possible_roles) if possible_roles else None

# --- LÓGICA IA: TEXTOS Y MENÚS ---

def _get_main_menu(nombre_usuario):
    nombre = f"¡Hola! *{nombre_usuario}*, " if nombre_usuario else "¡Hola! "
    return f"""{nombre}Bienvenido a *VTN SEGUROS - Grupo Montenegro*. Para nosotros es un gusto atenderte 🫡

Escribe el *número* de tu solicitud:

*1.* Presentas un accidente o requieres asistencia. 🚑
*2.* Requieres una cotización. 📊
*3.* Continuar con proceso de compra.💳
*4.* Inquietudes de tu póliza, certificados, coberturas, pagos y renovaciones.✍🏼
*5.* Consultar estado de siniestro/Financiaciones y pagos.⏳💰
*6.* Solicitud de cancelación de póliza y reintegro de dinero.📝
*7.* Comunicarse directamente con asesor por motivo de quejas y peticiones. ☹

Agradecemos la confianza depositada en nuestra labor."""

def _get_cotizaciones_menu():
    return """Escribe el *número* del producto que deseas cotizar: 🔢
*1.* Automóviles, motos, vehículos pesados.
*2.* Hogar.
*3.* Empresa.
*4.* Vida, salud y otros.
*Escribe A para volver al menú principal.*"""

def _get_agent_response_and_role(option):
    mapeo_roles = {
        "1": "Presentas un accidente o requieres asistencia", 
        "3": "Continuar con proceso de compra", 
        "4": "Inquietudes de tu póliza, certificados, coberturas, pagos y renovaciones",
        "5": "Consultar estado de siniestro/Financiaciones y pagos",
        "6": "Solicitud de cancelación de póliza y reintegro de dinero",
        "7": "Comunicarse directamente con asesor por motivo de quejas y peticiones"
    }
    response_parts = []
    if option == '1':
        response_parts = ["*Lamentamos lo sucedido!*", "Reúne la evidencia por medio de *fotos*... 📸", "_Pronto te contactaremos._"]
    elif option in ['3', '4', '5']:
        response_parts = ["Confírmanos por favor la *placa de tu vehículo* y qué duda o inquietud te podemos aclarar.", "_En minutos un agente te estará acompañando 🫡_"]
    elif option == '6':
        response_parts = ["Solicitud de cancelación.", "Indícanos por favor la *placa del vehículo* y cuál es el *motivo de cancelación*.", "En minutos un agente te acompañará."]
    elif option == '7':
        response_parts = ["Quejas y peticiones. ☹", "Confírmanos qué sucedió y envíanos tu *número de placa*.", "Un agente te atenderá."]
    
    full = "\n\n".join(response_parts) + "\n\n*Escribe A para volver al menú principal.*"
    return mapeo_roles.get(option, "General"), full

def _get_cotizacion_detail(sub_option):
    if sub_option == '1': return "🚘 Autos: Indícanos Placa, Nombre, Cédula, etc...\n*Escribe A para volver.*"
    if sub_option == '2': return "🏡 Hogar: Dirección, Área, Valor, etc...\n*Escribe A para volver.*"
    if sub_option == '3': return "🏦 Empresa: NIT, Actividad, etc...\n*Escribe A para volver.*"
    if sub_option == '4': return "Vida/Salud: Un agente te atenderá en breve.\n*Escribe A para volver.*"
    return ""

# --- MÁQUINA DE ESTADOS IA ---
def get_ia_response_and_route(convo, message_body):
    logging.info(f"IA State Machine: Procesando estado '{convo.status}'")
    try:
        # Opción global: Volver al menú con 'A' (salvo en saludo o espera de placa)
        if convo.status.startswith('ia_') and convo.status not in ['ia_greeting', 'ia_wait_for_placa_or_2'] and message_body.strip().upper() == 'A':
            convo.status = 'ia_show_menu' 
            db.session.add(convo)
            return ("chat", _get_main_menu(convo.user_display_name))

        # Estado: Saludo Conocido
        if convo.status == 'ia_greeting_known':
            if convo.user_display_name:
                convo.status = 'ia_show_menu' 
                db.session.add(convo)
                return ("chat", _get_main_menu(convo.user_display_name))
            else:
                 convo.status = 'ia_greeting'
                 db.session.add(convo) # Pasa al siguiente bloque

        # Estado: Saludo Inicial
        if convo.status == 'ia_greeting':
            convo.status = 'ia_wait_for_placa_or_2'
            db.session.add(convo)
            msg = (
                "¡Hola! Bienvenido a *VTN SEGUROS - Grupo Montenegro*. Para nosotros es un gusto atenderte 🫡\n\n"
                "¿Ya eres cliente de nosotros? 🤔\n\n"
                "*Si eres cliente, por favor ingresa tu número de placa.*\n"
                "*Si eres cliente nuevo, por favor ingresa el número 2* y te remitiremos con uno de nuestros asistentes. 🤝"
            )
            return ("chat", msg)
        
        # Estado: Esperando Placa o '2'
        elif convo.status == 'ia_wait_for_placa_or_2':
            user_input = message_body.strip().upper()
            if user_input == '2':
                logging.info("Cliente Nuevo (Opción 2). Enrutando a Cotizaciones.")
                if not convo.user_display_name:
                    convo.user_display_name = "Cliente Nuevo" 
                    convo.user_reported_phone = convo.user_phone.split('@')[0].replace('whatsapp:', '').replace('+', '')
                    db.session.add(convo)
                role_name = "Requieres una cotización"
                return ("route_and_message", {"role": role_name, "message": f"¡Perfecto! Un agente del área de *{role_name}* te contactará en breve. 👋"})
            else:
                # Buscar Placa
                policy_record = PolicyData.query.filter(PolicyData.placa.ilike(user_input)).first()
                if policy_record:
                    convo.user_display_name = policy_record.nombres
                    convo.user_reported_phone = convo.user_phone.split('@')[0].replace('whatsapp:', '').replace('+', '')
                    convo.status = 'ia_show_menu'
                    db.session.add(convo)
                    return ("chat", _get_main_menu(convo.user_display_name))
                else:
                    return ("chat", f"La placa *{user_input}* no fue encontrada. 😔\nPor favor verifica o *ingresa el número 2* para ser atendido por un agente.")

        # Estado: Menú Principal
        elif convo.status == 'ia_show_menu':
            opcion = message_body.strip()
            if opcion == '2':
                convo.status = 'ia_cotizaciones_sub'
                db.session.add(convo)
                return ("chat", _get_cotizaciones_menu())
            elif opcion in ['1', '3', '4', '5', '6', '7']:
                role_name, response_msg = _get_agent_response_and_role(opcion)
                convo.status = f'ia_wait_for_info_opcion_{opcion}' 
                db.session.add(convo)
                return ("chat", response_msg)
            else:
                return ("chat", f"La opción *'{opcion}'* no es válida. Por favor, selecciona un número del 1 al 7.\n\n" + _get_main_menu(convo.user_display_name))

        # Estado: Sub-Menú Cotizaciones
        elif convo.status == 'ia_cotizaciones_sub':
            sub = message_body.strip()
            if sub in ['1', '2', '3']:
                convo.status = 'ia_cotizaciones_wait' # Espera información
                db.session.add(convo)
                return ("chat", _get_cotizacion_detail(sub))
            elif sub == '4':
                convo.status = 'ia_wait_for_info_opcion_2_4'
                db.session.add(convo)
                return ("chat", _get_cotizacion_detail('4'))
            else:
                return ("chat", "Opción inválida. Selecciona 1-4.")

        # Estados de Espera -> Enrutamiento
        elif convo.status.startswith('ia_wait_for_info_opcion_') or convo.status == 'ia_cotizaciones_wait':
            # Aquí el usuario ya ingresó la info solicitada (motivo, placa, etc.)
            role_name = "General"
            if 'opcion_1' in convo.status: role_name = "Presentas un accidente o requieres asistencia"
            elif 'opcion_3' in convo.status: role_name = "Continuar con proceso de compra"
            elif 'opcion_4' in convo.status: role_name = "Inquietudes de tu póliza, certificados, coberturas, pagos y renovaciones"
            elif 'opcion_5' in convo.status: role_name = "Consultar estado de siniestro/Financiaciones y pagos"
            elif 'opcion_6' in convo.status: role_name = "Solicitud de cancelación de póliza y reintegro de dinero"
            elif 'opcion_7' in convo.status: role_name = "Comunicarse directamente con asesor por motivo de quejas y peticiones"
            elif 'opcion_2_4' in convo.status or convo.status == 'ia_cotizaciones_wait': role_name = "Requieres una cotización"
            
            return ("route", role_name)

        else:
            convo.status = 'ia_greeting'
            db.session.add(convo)
            return ("chat", "Ocurrió un error inesperado. Reiniciando...")

    except Exception as e:
        logging.error(f"Error IA: {e}")
        return ("route", "General")

# --- WEBHOOK PRINCIPAL ---
@app.route('/api/baileys/webhook', methods=['POST'])
def baileys_webhook():
    data = request.json
    message_body = data.get('Body')
    sender_phone = data.get('From')
    
    # RESTAURADO: Recuperar tipo y url de media
    message_type = data.get('MessageType', 'text')
    media_url = data.get('MediaUrl')

    if (not message_body and not media_url) or not sender_phone:
        return jsonify({"error": "Datos insuficientes"}), 400
        
    logging.info(f"Mensaje de {sender_phone}: {message_body} (Tipo: {message_type})")

    try:
        existing_convo = Conversation.query.filter_by(user_phone=sender_phone).order_by(Conversation.created_at.desc()).first()
        
        # 1. Usuario escribe 'A' en chat abierto -> Volver a Menú
        if existing_convo and existing_convo.status == 'open' and message_body and message_body.strip().upper() == 'A':
            existing_convo.status = 'ia_show_menu'
            existing_convo.unread_count = 0 
            existing_convo.pending_counted = False 
            menu_msg = _get_main_menu(existing_convo.user_display_name)
            send_reply(sender_phone, menu_msg)

            # RESTAURADO: Usar sender_type 'user' y 'system'
            db.session.add_all([
                Message(conversation_id=existing_convo.id, sender_type='user', content=message_body, message_type='text'),
                Message(conversation_id=existing_convo.id, sender_type='system', content=menu_msg)
            ])
            db.session.commit()
            return jsonify({"status": "returned_to_menu"}), 200
        
        # 2. Chat Abierto -> Guardar mensaje
        if existing_convo and existing_convo.status == 'open':
            # RESTAURADO: Usar todos los campos
            new_message = Message(
                conversation_id=existing_convo.id, 
                sender_type='user', 
                content=message_body or "[Multimedia]",
                message_type=message_type, 
                media_url=media_url
            )
            db.session.add(new_message)

            existing_convo.unread_count = (existing_convo.unread_count or 0) + 1
            existing_convo.updated_at = datetime.utcnow()
            if existing_convo.bot_role and not existing_convo.pending_counted:
                existing_convo.bot_role.chats_pending = (existing_convo.bot_role.chats_pending or 0) + 1
                existing_convo.pending_counted = True
            db.session.commit()
            return jsonify({"status": "message_queued"}), 200

        # 3. Verificar Bot Activo
        bot_config = BotConfig.query.first()
        if not bot_config or not bot_config.is_active:
            return jsonify({"status": "bot_inactive"}), 200
        
        # 4. Conversación IA (Existente o Nueva)
        if existing_convo and existing_convo.status.startswith('ia_'):
            convo = existing_convo
        else:
            general = BotRole.query.filter_by(title='General').first()
            if not general: return jsonify({"error": "Falta rol General"}), 500
            prev = Conversation.query.filter(Conversation.user_phone == sender_phone, Conversation.user_display_name.isnot(None)).order_by(Conversation.created_at.desc()).first()
            convo = Conversation(user_phone=sender_phone, bot_role_id=general.id)
            if prev:
                convo.user_display_name = prev.user_display_name
                convo.user_reported_phone = prev.user_reported_phone
                convo.status = 'ia_greeting_known'
            else:
                convo.status = 'ia_greeting'
            db.session.add(convo)
            db.session.flush()

        # Guardar mensaje usuario (RESTAURADO)
        db.session.add(Message(conversation_id=convo.id, sender_type='user', content=message_body or "[Media]", message_type=message_type, media_url=media_url))
        
        # Ejecutar IA
        action, data_resp = get_ia_response_and_route(convo, message_body or "")

        # Procesar Acción IA
        if action == "route":
            target = get_random_active_role(data_resp)
            if not target:
                msg = f"Ups, el departamento de '{data_resp}' no está disponible."
                send_reply(sender_phone, msg)
                db.session.add(Message(conversation_id=convo.id, sender_type='system', content=msg))
            else:
                convo.status = 'open'
                convo.bot_role_id = target.id
                convo.pending_counted = True
                target.chats_received = (target.chats_received or 0) + 1
                target.chats_pending = (target.chats_pending or 0) + 1
                
                trans_msg = f"¡Entendido! Un agente del área de {target.title} te atenderá pronto."
                send_reply(sender_phone, trans_msg)
                db.session.add_all([
                    Message(conversation_id=convo.id, sender_type='system', content=f"Chat enrutado a {target.title}."),
                    Message(conversation_id=convo.id, sender_type='system', content=trans_msg)
                ])
            
        elif action == "route_and_message":
            target = get_random_active_role(data_resp['role'])
            send_reply(sender_phone, data_resp['message'])
            db.session.add(Message(conversation_id=convo.id, sender_type='system', content=data_resp['message']))
            
            if target:
                convo.status = 'open'
                convo.bot_role_id = target.id
                convo.pending_counted = True
                target.chats_received += 1
                target.chats_pending += 1
                db.session.add(Message(conversation_id=convo.id, sender_type='system', content=f"Chat enrutado a {target.title}."))

        elif action == "chat":
            send_reply(sender_phone, data_resp)
            db.session.add(Message(conversation_id=convo.id, sender_type='system', content=data_resp))

        convo.updated_at = datetime.utcnow()
        db.session.commit()
        return jsonify({"status": "ia_processed"}), 200

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error Webhook: {e}")
        return jsonify({"error": "Error interno"}), 500

# --- APIS DE ADMINISTRACIÓN ---
def check_admin():
    if current_user.role != 'Admin': return jsonify({"error": "No autorizado"}), 403
    return None

@app.route('/api/users', methods=['GET'])
@login_required
def get_users():
    if current_user.role != 'Admin': return jsonify({"error": "No autorizado"}), 403
    users = User.query.all()
    return jsonify([{'id': u.id, 'name': u.name, 'role': u.role, 'username': u.username} for u in users])

@app.route('/api/users', methods=['POST'])
@login_required
def add_user():
    if check_admin(): return check_admin()
    data = request.get_json()
    base_username = re.sub(r'\s+', '', data.get('name', 'usuario')).split(' ')[0].lower().strip()
    if not base_username: base_username = 'usuario'
    username = base_username
    counter = 1
    while User.query.filter_by(username=username).first():
        username = f"{base_username}{counter}"
        counter += 1
    
    new_user = User(username=username, name=data['name'], password=data['password'], role=data['role'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'success': True}), 201

@app.route('/api/users/<int:id>', methods=['PUT'])
@login_required
def update_user(id):
    if check_admin(): return check_admin()
    user = User.query.get_or_404(id)
    data = request.get_json()
    user.name = data.get('name', user.name)
    user.role = data.get('role', user.role)
    if data.get('password'): user.password = data['password']
    db.session.commit()
    return jsonify({'message': 'Actualizado'})

@app.route('/api/users/<int:id>', methods=['DELETE'])
@login_required
def delete_user(id):
    if check_admin(): return check_admin()
    db.session.delete(User.query.get_or_404(id))
    db.session.commit()
    return jsonify({'message': 'Eliminado'})

@app.route('/api/bot_roles', methods=['GET'])
@login_required
def get_bot_roles():
    if check_admin(): return check_admin()
    roles = BotRole.query.options(db.joinedload(BotRole.assignee)).all()
    return jsonify([{'id': r.id, 'title': r.title, 'assignee_name': r.assignee.name if r.assignee else 'Sin Asignar', 'assignee_id': r.assignee_id, 'status': r.status, 'chats_pending': r.chats_pending} for r in roles])

@app.route('/api/bot_roles', methods=['POST'])
@login_required
def add_bot_role():
    if check_admin(): return check_admin()
    data = request.get_json()
    if BotRole.query.filter_by(title=data['title']).first(): return jsonify({'message': 'Existe'}), 409
    db.session.add(BotRole(title=data['title'], assignee_id=data.get('assignee_id'), status=data.get('status', 'Activo')))
    db.session.commit()
    return jsonify({'success': True}), 201

@app.route('/api/bot_roles/<int:id>', methods=['PUT', 'DELETE'])
@login_required
def manage_role(id):
    if check_admin(): return check_admin()
    role = BotRole.query.get_or_404(id)
    if request.method == 'DELETE':
        db.session.delete(role)
    else:
        data = request.get_json()
        role.title = data.get('title', role.title)
        role.assignee_id = data.get('assignee_id') or None
        role.status = data.get('status', role.status)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/bot_config', methods=['GET', 'PUT'])
@login_required
def manage_config():
    if check_admin(): return check_admin()
    config = BotConfig.query.first()
    if not config:
        config = BotConfig()
        db.session.add(config)
        db.session.commit()
    if request.method == 'PUT':
        data = request.get_json()
        config.is_active = data.get('is_active', config.is_active)
        config.whatsapp_number = data.get('whatsapp_number', config.whatsapp_number)
        db.session.commit()
    return jsonify({'is_active': config.is_active, 'whatsapp_number': config.whatsapp_number})

# --- APIS DE CHATS ---
@app.route('/api/chats', methods=['GET'])
@login_required
def get_chats():
    status = request.args.get('status', 'open')
    query = Conversation.query.filter(Conversation.status == status)
    
    if current_user.role != 'Admin':
        assigned_ids = [r.id for r in current_user.assigned_roles]
        if not assigned_ids: return jsonify([])
        query = query.filter(Conversation.bot_role_id.in_(assigned_ids))
    
    convos = query.order_by(Conversation.updated_at.desc()).all()
    result = []
    for c in convos:
        last = c.get_last_message()
        # Usar display_name si existe, sino limpiar el teléfono
        clean_phone = c.user_phone.split('@')[0].replace('whatsapp:', '').replace('+', '')
        display = c.user_display_name or clean_phone
        
        result.append({
            "id": c.id, "name": display, "phone": c.user_reported_phone or clean_phone,
            "time": last.timestamp.strftime("%I:%M %p") if last else 'N/A',
            "unread": c.unread_count, "last_message": last.content if last else "",
            "bot_role_title": c.bot_role.title if c.bot_role else "N/A"
        })
    return jsonify(result)

@app.route('/api/chats/<int:id>/messages', methods=['GET'])
@login_required
def get_chat_messages(id):
    convo = Conversation.query.get_or_404(id)
    if current_user.role != 'Admin' and convo.bot_role_id not in [r.id for r in current_user.assigned_roles]:
        return jsonify({"error": "No autorizado"}), 403
    if convo.status == 'open': convo.unread_count = 0
    db.session.commit()
    
    # RESTAURADO: Usar campos reales
    return jsonify([{
        "sender": msg.sender_type, 
        "text": msg.content, 
        "type": msg.message_type, 
        "url": msg.media_url
    } for msg in convo.messages])

@app.route('/api/chats/<int:id>/messages', methods=['POST'])
@login_required
def send_chat_message(id):
    convo = Conversation.query.get_or_404(id)
    # Validación de permisos
    if current_user.role != 'Admin' and convo.bot_role_id not in [r.id for r in current_user.assigned_roles]:
        return jsonify({"error": "No autorizado"}), 403
            
    content = request.get_json().get('text')
    if not content: return jsonify({"error": "Vacío"}), 400

    try:
        # Reactivar si cerrado
        if convo.status == 'closed':
            convo.status = 'open'
            convo.unread_count = 0 
            convo.pending_counted = True 
            if convo.bot_role:
                convo.bot_role.chats_resolved = max(0, convo.bot_role.chats_resolved - 1)
                convo.bot_role.chats_pending += 1

        # Enviar a Baileys
        if send_reply(convo.user_phone, content):
            # RESTAURADO: Guardar como 'agent'
            db.session.add(Message(conversation_id=convo.id, sender_type='agent', content=content))
            convo.updated_at = datetime.utcnow()
            db.session.commit()
            return jsonify({"success": True, "message": {"sender": "agent", "text": content}}), 201
        else:
             return jsonify({"error": "Fallo envío a Baileys"}), 500
    
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/api/chats/<int:id>/resolve', methods=['POST'])
@login_required
def resolve_chat(id):
    convo = Conversation.query.get_or_404(id)
    convo.status = 'closed'
    if convo.bot_role:
        convo.bot_role.chats_resolved += 1
        if convo.pending_counted: convo.bot_role.chats_pending -= 1
    db.session.commit()
    return jsonify({"success": True})

@app.route('/api/chats/<int:convo_id>/search_policy_data', methods=['GET'])
@login_required
def search_policy_data_for_chat(convo_id):
    convo = Conversation.query.get_or_404(convo_id)
    name = convo.user_display_name
    if not name: return jsonify([])
    records = PolicyData.query.filter(PolicyData.nombres.ilike(f"%{name}%")).all()
    return jsonify([{
        "aseguradora": r.aseguradora, "nombres": r.nombres, "placa": r.placa, "fecha_venc": r.fecha_venc
    } for r in records])

# --- CARGA CSV ---
@app.route('/api/admin/upload_database', methods=['POST'])
@login_required
def upload_database():
    if check_admin(): return check_admin()
    if 'file' not in request.files: return jsonify({"error": "No file"}), 400
    file = request.files['file']
    if not file.filename: return jsonify({"error": "No filename"}), 400
    
    try:
        df = None
        try:
            df = pd.read_csv(file, header=0, dtype=str, encoding='utf-8', sep=',').fillna('')
            if len(df.columns) <= 1:
                file.seek(0)
                df = pd.read_csv(file, header=0, dtype=str, encoding='utf-8', sep=';').fillna('')
        except:
            file.seek(0)
            df = pd.read_csv(file, header=0, dtype=str, encoding='latin-1', sep=';').fillna('')
        
        PolicyData.query.delete()
        for _, row in df.iterrows():
            db.session.add(PolicyData(
                aseguradora=row.get('ASEGURADORA'), nombres=row.get('NOMBRES'),
                cedula_nit=row.get('CEDULA/NIT'), tipo=row.get('TIPO'),
                placa=row.get('PLACA'), modelo=row.get('MODELO'),
                valor_poliza=row.get('VLOR POLIZA'), mes_vencimiento=row.get('MES VENCIMIENTO'),
                fecha_venc=row.get('FECHA VENC'), referencia=row.get('REFERENCIA')
            ))
        db.session.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- DASHBOARD APIs ---
@app.route('/api/dashboard/soporte')
@login_required
def get_soporte_dashboard_data():
    # (Lógica simplificada para brevedad, pero funcional)
    return jsonify({"stats": {"today": 0, "week": 0, "month": 0}, "lineChart": {"labels": [], "data": []}, "barChart": {"labels": [], "data": []}})

@app.route('/api/dashboard/admin')
@login_required
def get_admin_dashboard_data():
    if check_admin(): return check_admin()
    # (Lógica simplificada)
    return jsonify({"stats": {"asistentes_activos": 0}, "lineChart": {}, "barChart": {}, "table_data": []})

# --- INICIALIZACIÓN ---
def init_db(app_instance):
    with app_instance.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            db.session.add(User(username='admin', password='admin', name='Admin', role='Admin'))
            db.session.add(User(username='soporte', password='soporte', name='Soporte', role='Soporte'))
            db.session.add(BotConfig(is_active=True, whatsapp_number="123", welcome_message="Hola"))
            db.session.add(BotRole(title='General', status='Activo'))
            roles = ["Presentas un accidente o requieres asistencia", "Requieres una cotización", "Continuar con proceso de compra", 
                     "Inquietudes de tu póliza, certificados, coberturas, pagos y renovaciones", "Consultar estado de siniestro/Financiaciones y pagos",
                     "Solicitud de cancelación de póliza y reintegro de dinero", "Comunicarse directamente con asesor por motivo de quejas y peticiones"]
            for r in roles:
                if not BotRole.query.filter_by(title=r).first(): db.session.add(BotRole(title=r, status='Activo'))
            db.session.commit()

init_db(app)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)