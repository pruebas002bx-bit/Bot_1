import os
import logging
import re
import json
import requests
import pandas as pd # <-- NUEVA IMPORTACIÓN
from flask import Flask, render_template, request, jsonify, redirect, url_for
from werkzeug.utils import secure_filename 
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from twilio.twiml.messaging_response import MessagingResponse
from twilio.rest import Client
from datetime import datetime, timedelta
from sqlalchemy import func, or_ # <-- NUEVA IMPORTACIÓN

# --- IMPORTACIONES DE SESIONES ---
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

# --- CONFIGURACIÓN ---
logging.basicConfig(level=logging.INFO)
load_dotenv()

# --- CONFIGURACIÓN DE TWILIO (Se mantiene por si se usa en el futuro, pero no para el webhook) ---
TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID')
TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
TWILIO_WHATSAPP_NUMBER = os.getenv('TWILIO_WHATSAPP_NUMBER')
try:
    twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
    logging.info("Cliente de Twilio inicializado (no se usará para webhook de Baileys).")
except Exception as e:
    logging.warning(f"No se pudo inicializar el cliente de Twilio: {e}.")
    twilio_client = None

# --- CONFIGURACIÓN DE IA ---
try:
    import google.generativeai as genai
    genai.configure(api_key=os.getenv('GEMINI_API_KEY'))
    logging.info("API de Gemini configurada.")
except Exception as e:
    logging.error(f"Error al configurar la API de Gemini: {e}.")
    genai = None

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
    status = db.Column(db.String(20), default='ia_greeting', nullable=False, index=True) # 'ia_greeting', 'open', 'closed'
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    updated_at = db.Column(db.DateTime(timezone=True), onupdate=func.now())
    unread_count = db.Column(db.Integer, default=0)
    bot_role_id = db.Column(db.Integer, db.ForeignKey('bot_roles.id'), nullable=False)
    
    # --- INICIO DE MODIFICACIÓN ---
    user_display_name = db.Column(db.String(120), nullable=True)
    user_reported_phone = db.Column(db.String(50), nullable=True)
    # --- FIN DE MODIFICACIÓN ---
    
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
    sender_type = db.Column(db.String(20), nullable=False) # 'user', 'agent', 'system'
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime(timezone=True), server_default=func.now())
    conversation = db.relationship('Conversation', back_populates='messages')

# --- INICIO DE NUEVO MODELO: PolicyData ---
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
# --- FIN DE NUEVO MODELO ---


# --- RUTAS BÁSICAS (PROTEGIDAS) ---
@app.route('/')
def index():
    return render_template('Index.html') 

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
    
    # --- MODIFICACIÓN: Database.html NO está en admin_pages para que Soporte pueda verlo ---
    if current_user.role == 'Soporte' and page_name in admin_pages: 
        return redirect(url_for('menu_soporte'))
        
    return render_template(page_name, current_user=current_user)

# --- API DE LOGIN Y LOGOUT ---
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

# --- APIS DE ADMIN (PROTEGIDAS) ---
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
    admin_check = check_admin()
    if admin_check: return admin_check
    data = request.get_json()
    base_username = re.sub(r'\s+', '', data.get('name', 'usuario')).split(' ')[0].lower().strip()
    if not base_username: base_username = 'usuario'
    username = base_username
    counter = 1
    while User.query.filter_by(username=username).first():
        username = f"{base_username}{counter}"
        counter += 1
            
    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'El nombre de usuario ya existe'}), 409
    
    new_user = User(
        username=username, 
        name=data['name'], 
        password=data['password'], 
        role=data['role']
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'id': new_user.id, 'name': new_user.name, 'role': new_user.role, 'username': new_user.username}), 201

@app.route('/api/users/<int:id>', methods=['PUT'])
@login_required
def update_user(id):
    admin_check = check_admin()
    if admin_check: return admin_check
    user = User.query.get_or_404(id)
    data = request.get_json()
    user.name = data.get('name', user.name)
    user.role = data.get('role', user.role)
    if 'password' in data and data['password']:
        user.password = data['password']
    db.session.commit()
    return jsonify({'message': 'Usuario actualizado correctamente'})

@app.route('/api/users/<int:id>', methods=['DELETE'])
@login_required
def delete_user(id):
    admin_check = check_admin()
    if admin_check: return admin_check
    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'Usuario eliminado correctamente'})

@app.route('/api/bot_roles', methods=['GET'])
@login_required
def get_bot_roles():
    admin_check = check_admin()
    if admin_check: return admin_check
    roles = BotRole.query.options(db.joinedload(BotRole.assignee)).all()
    return jsonify([{'id': r.id, 'title': r.title, 'knowledge_base': r.knowledge_base,
                     'assignee_name': r.assignee.name if r.assignee else 'Sin Asignar',
                     'assignee_id': r.assignee_id, 'status': r.status,
                     'chats_received': r.chats_received or 0, 'chats_pending': r.chats_pending or 0,
                     'chats_resolved': r.chats_resolved or 0} for r in roles])

@app.route('/api/bot_roles/list', methods=['GET'])
@login_required
def get_bot_roles_list():
    try:
        roles = BotRole.query.filter(BotRole.status == 'Activo', BotRole.title != 'General').order_by(BotRole.title).all()
        return jsonify([{'id': r.id, 'title': r.title} for r in roles])
    except Exception as e:
        logging.error(f"Error en /api/bot_roles/list: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/bot_roles', methods=['POST'])
@login_required
def add_bot_role():
    admin_check = check_admin()
    if admin_check: return admin_check
    data = request.get_json()
    if BotRole.query.filter_by(title=data['title']).first():
        return jsonify({'message': 'Un rol con este título ya existe'}), 409
    assignee_id = data.get('assignee_id')
    new_role = BotRole(title=data['title'], knowledge_base=data.get('knowledge_base', ''),
                       assignee_id=int(assignee_id) if assignee_id else None, status=data.get('status', 'Activo'))
    db.session.add(new_role)
    db.session.commit()
    role_data = BotRole.query.get(new_role.id)
    return jsonify({'id': role_data.id, 'title': role_data.title, 'knowledge_base': role_data.knowledge_base,
                    'assignee_name': role_data.assignee.name if role_data.assignee else 'Sin Asignar',
                    'assignee_id': role_data.assignee_id, 'status': role_data.status,
                    'chats_received': role_data.chats_received or 0,
                    'chats_pending': role_data.chats_pending or 0,
                    'chats_resolved': role_data.chats_resolved or 0}), 201

@app.route('/api/bot_roles/<int:id>', methods=['PUT'])
@login_required
def update_bot_role(id):
    admin_check = check_admin()
    if admin_check: return admin_check
    role = BotRole.query.get_or_404(id)
    data = request.get_json()
    role.title = data.get('title', role.title)
    role.knowledge_base = data.get('knowledge_base', role.knowledge_base)
    role.status = data.get('status', role.status)
    assignee_id = data.get('assignee_id')
    role.assignee_id = int(assignee_id) if assignee_id else None
    db.session.commit()
    return jsonify({'message': 'Rol del bot actualizado correctamente'})

@app.route('/api/bot_roles/<int:id>', methods=['DELETE'])
@login_required
def delete_bot_role(id):
    admin_check = check_admin()
    if admin_check: return admin_check
    role = BotRole.query.get_or_404(id)
    db.session.delete(role)
    db.session.commit()
    return jsonify({'message': 'Rol del bot eliminado correctamente'})

@app.route('/api/bot_config', methods=['GET'])
@login_required
def get_bot_config():
    admin_check = check_admin()
    if admin_check: return admin_check
    config = BotConfig.query.first()
    if not config:
        config = BotConfig(is_active=True, whatsapp_number="+573132217862", welcome_message="¡Hola! Bienvenido a nuestro servicio de atención. ¿En qué puedo ayudarte hoy?")
        db.session.add(config)
        db.session.commit()
    return jsonify({'is_active': config.is_active, 'whatsapp_number': config.whatsapp_number, 'welcome_message': config.welcome_message})

@app.route('/api/bot_config', methods=['PUT'])
@login_required
def update_bot_config():
    admin_check = check_admin()
    if admin_check: return admin_check
    config = BotConfig.query.first_or_404()
    data = request.get_json()
    config.is_active = data.get('is_active', config.is_active)
    config.whatsapp_number = data.get('whatsapp_number', config.whatsapp_number)
    config.welcome_message = data.get('welcome_message', config.welcome_message)
    db.session.commit()
    return jsonify({'message': 'Configuración del bot actualizada correctamente'})

# --- LÓGICA DEL WEBHOOK (MODIFICADA PARA BAILEYS) ---

# --- NUEVA: Función helper para enviar respuestas a Baileys ---
def send_reply(phone_number, message_content):
    """
    Envía un mensaje de respuesta al bot de Baileys (Servicio B).
    """
    baileys_bot_url = os.getenv('BAILEYS_BOT_URL')
    if not baileys_bot_url:
        logging.error("BAILEYS_BOT_URL no está configurada. No se puede enviar respuesta.")
        return False

    send_url = f"{baileys_bot_url}/send"
    payload = {
        "number": phone_number, 
        "message": message_content
    }
    
    try:
        logging.info(f"Enviando respuesta a Baileys: {send_url} (Para: {phone_number})")
        # --- MODIFICACIÓN: Aumentar el timeout ---
        response = requests.post(send_url, json=payload, timeout=30)
        # --- FIN DE MODIFICACIÓN ---
        
        if response.status_code != 200:
            logging.error(f"El bot de Baileys respondió con {response.status_code}: {response.text}")
            return False
        
        logging.info(f"Respuesta enviada exitosamente a Baileys.")
        return True
        
    except Exception as e:
        logging.error(f"Error al llamar al bot de Baileys: {e}")
        return False


# --- REEMPLAZO COMPLETO PARA get_ia_response_and_route ---

# Función para obtener el menú principal (con formato)
def _get_main_menu(nombre_usuario):
    nombre_personalizado = f"¡Hola! *{nombre_usuario}*, " if nombre_usuario else "¡Hola! "
    return f"""{nombre_personalizado}Bienvenido a *VTN SEGUROS - Grupo Montenegro*. Para nosotros es un gusto atenderte 🫡

Escribe el *número* de tu solicitud:

*1.* Presentas un accidente o requieres asistencia. 🚑
*2.* Requieres una cotización. 📊
*3.* Continuar con proceso de compra.💳
*4.* Inquietudes de tu póliza, certificados, coberturas, pagos y renovaciones.✍🏼
*5.* Consultar estado de siniestro/Financiaciones y pagos.⏳💰
*6.* Solicitud de cancelación de póliza y reintegro de dinero.📝
*7.* Comunicarse directamente con asesor por motivo de quejas y peticiones. ☹

Agradecemos la confianza depositada en nuestra labor."""

# Función para obtener el sub-menú de Cotizaciones
def _get_cotizaciones_menu():
    return f"""Escribe el *número* del producto que deseas cotizar: 🔢

*1.* Automóviles, motos, vehículos pesados.
*2.* Hogar.
*3.* Empresa.
*4.* Vida, salud y otros.

*Escribe A para volver al menú principal.*
"""

# Función que define la respuesta y acción para opciones que enrutan (1, 3, 4, 5, 6, 7)
def _get_agent_response_and_role(option):
    mapeo_roles = {
        "1": "Siniestros, Consultas Póliza, Cancelaciones", 
        "3": "Ventas", 
        "4": "Siniestros, Consultas Póliza, Cancelaciones",
        "5": "Siniestros, Consultas Póliza, Cancelaciones",
        "6": "Siniestros, Consultas Póliza, Cancelaciones",
        "7": "Soporte Técnico"
    }
    
    response_parts = []
    
    if option == '1':
        response_parts = [
            "*Lamentamos lo sucedido!* Deseamos que te encuentres bien.",
            "Reúne la evidencia por medio de *fotos*, donde se vean placas, señales de transito y ubicación de los vehículos. 📸",
            "Si hay un tercero involucrado, comunícate con la aseguradora y solicita asistencia de abogado 💼 y si es necesario, servicio de grúa.",
            "_Pronto te contactaremos._"
        ]
    elif option == '3':
        response_parts = [
            "Indícanos qué dudas o inquietudes tienes 🤓.",
            "_En minutos un agente te estará acompañando 🫡_"
        ]
    elif option == '4':
        response_parts = [
            "Confírmanos por favor la *placa de tu vehículo* y qué duda o inquietud te podemos aclarar.",
            "_En minutos un agente te estará acompañando 🫡_"
        ]
    elif option == '5':
        response_parts = [
            "Confírmanos por favor la *placa de tu vehículo* y qué duda o inquietud te podemos aclarar.",
            "_En minutos un agente te estará acompañando 🫡_"
        ]
    elif option == '6':
        response_parts = [
            "Solicitud de cancelación de póliza y reintegro de dinero.📝",
            "Indícanos por favor la *placa del vehículo* y cuál es el *motivo de cancelación* de la póliza.",
            "En minutos un agente te estará acompañando en la solicitud 🫡"
        ]
    elif option == '7':
        response_parts = [
            "Comunicarse directamente con asesor por motivo de quejas y peticiones. ☹",
            "Confírmanos por favor *cómo te podemos colaborar, qué sucedió*, y envíanos el *número de placa*.",
            "En minutos un agente te estará acompañando en la solicitud."
        ]
    
    full_response = "\n\n".join(response_parts)
    
    # Se añade la nota de "escribe A para volver" SOLO para la opción 6
    if option == '6':
         full_response += "\n\n*Escribe A para volver al menú principal (si no quieres cancelar).* "

    return mapeo_roles.get(option, "General"), full_response


# Función que define la respuesta para las cotizaciones (Sub-Opciones de 2)
def _get_cotizacion_detail(sub_option):
    if sub_option == '1':
        return (
            "🚘 Para elaborarte varias propuestas, indícanos por escrito los siguientes datos:\n\n"
            "🔹*Placa:* (Si es 0km, marca, línea, modelo)\n"
            "🔹*Nombre propietario:*\n"
            "🔹*Cédula:*\n"
            "🔹*Fecha nacimiento:*\n"
            "🔹*Ciudad residencia:*\n\n"
            "¿El vehículo tiene prenda?\n"
            "¿El vehículo es blindado?\n"
            "Nos indicas por favor cuánto estás pagando de seguro actualmente.\n\n"
            "_Debido a la alta cantidad de propuestas que estamos elaborando, enviaremos tus propuestas en el transcurso del día siguiente._\n\n"
            "*Escribe A para volver al menú principal.*"
        )
    elif sub_option == '2':
        return (
            "Envíanos los siguientes datos para cotizar tú póliza de *Hogar*: 🏡\n\n"
            "*Dirección y ciudad:*\n"
            "*Área construida:*\n"
            "*Año de construcción:*\n"
            "*Número de pisos* (casa):\n"
            "*Número de pisos totales edificio* (apartamento):\n\n"
            "*Nombre propietario:*\n"
            "*Cédula:*\n\n"
            "▫*Valor edificación:* $\n"
            "▫*Valor contenidos muebles:* $\n"
            "▫*Valor contenidos equipos electrónicos:* $\n"
            "▫*Valor equipos móviles y portátiles (OPCIONAL):* $\n"
            "▫*Valor Celulares (OPCIONAL):* $\n"
            "▫*Valor contenidos joyas (OPCIONAL):* $\n\n"
            "*Desea asegurar los contenidos por hurto? o solo por daños?*\n\n"
            "*Escribe A para volver al menú principal.*"
        )
    elif sub_option == '3':
        return (
            "Envíanos los siguientes datos para cotizar tú seguro *Empresarial*: 🏦\n\n"
            "*Dirección y ciudad:*\n"
            "*Razón social:*\n"
            "*NIT:*\n"
            "*Detalle de actividad:*\n\n"
            "*Año de construcción de edificación:*\n"
            "*Material de construcción:*\n\n"
            "*Nombre del propietario y cédula:*\n\n"
            "▫*Edificación:* $ (solo si es propia)\n"
            "▫*Mejoras locativas:* $\n"
            "▫*Equipos eléctricos y electrónicos:* $\n"
            "▫*Equipo Móvil y portátil:* $\n"
            "▫*Muebles y enseres:* $\n"
            "▫*Maquinaria y Equipo:* $\n"
            "▫*Mercancías:* $\n"
            "▫*Dineros en el local:* $\n\n"
            "*Escribe A para volver al menú principal.*"
        )
    elif sub_option == '4':
        return (
            "Para cotizaciones de *Vida, Salud y Otros*:\n\n"
            "_En minutos un agente te estará acompañando 🫡_\n\n"
            "*Escribe A para volver al menú principal.*"
        )
    return ""


# --- FUNCIÓN PRINCIPAL DE LA MÁQUINA DE ESTADOS ---
def get_ia_response_and_route(convo, message_body):
    """
    Gestiona la conversación de la IA como una máquina de estados.
    Modifica el objeto 'convo' directamente.
    """
    logging.info(f"IA State Machine: Procesando estado '{convo.status}'")

    try:
        # -----------------------------------------------------
        # --- LÓGICA DE REGRESO AL MENÚ PRINCIPAL ('A') ---
        # -----------------------------------------------------
        if convo.status.startswith('ia_') and convo.status not in ['ia_greeting', 'ia_ask_name', 'ia_ask_phone', 'ia_confirm_details'] and message_body.strip().upper() == 'A':
            logging.info(f"Usuario {convo.user_phone} solicitó volver al menú principal desde {convo.status}.")
            convo.status = 'ia_show_menu' 
            db.session.add(convo)
            return ("chat", _get_main_menu(convo.user_display_name))


        # -----------------------------------------------------
        # --- MÁQUINA DE ESTADOS NORMAL ---
        # -----------------------------------------------------

        # --- ESTADO 0: Saludo (Usuario Conocido) ('ia_greeting_known') ---
        if convo.status == 'ia_greeting_known':
            convo.status = 'ia_show_menu' 
            db.session.add(convo)
            return ("chat", _get_main_menu(convo.user_display_name))

        # --- ESTADO 1: Saludo Inicial ('ia_greeting') ---
        elif convo.status == 'ia_greeting':
            convo.status = 'ia_ask_name' 
            db.session.add(convo)
            return ("chat", "¡Hola! Bienvenido a *VTN SEGUROS - Grupo Montenegro*. Para nosotros es un gusto atenderte. Por favor indícame tu *nombre completo*.")
        
        # --- ESTADO 2: Esperando el Nombre ('ia_ask_name') ---
        elif convo.status == 'ia_ask_name':
            convo.user_display_name = message_body.strip() 
            convo.status = 'ia_ask_phone' 
            db.session.add(convo)
            return ("chat", f"Gracias *{convo.user_display_name}*. Ahora, por favor, indícame tu *número de celular*.")

        # --- ESTADO 3: Esperando el Teléfono ('ia_ask_phone') ---
        elif convo.status == 'ia_ask_phone':
            convo.user_reported_phone = message_body.strip()
            convo.status = 'ia_confirm_details' 
            db.session.add(convo)
            return ("chat", f"Tu nombre es *{convo.user_display_name}* y tu celular es el *{convo.user_reported_phone}*. ¿Es esto *correcto*? (Responde 'sí' o 'no')")

        # --- ESTADO 4: Esperando Confirmación ('ia_confirm_details') ---
        elif convo.status == 'ia_confirm_details':
            respuesta_limpia = message_body.strip().lower()
            
            if respuesta_limpia in ['sí', 'si', 's', 'correcto', 'si es']:
                convo.status = 'ia_show_menu' 
                db.session.add(convo)
                return ("chat", _get_main_menu(convo.user_display_name))
            
            elif respuesta_limpia in ['no', 'n', 'incorrecto']:
                convo.status = 'ia_ask_name'
                convo.user_display_name = None 
                convo.user_reported_phone = None 
                db.session.add(convo)
                return ("chat", "Entendido, empecemos de nuevo. Por favor indícame tu *nombre completo*.")
            
            else:
                return ("chat", f"No entendí tu respuesta. Por favor, dime *'sí'* o *'no'*.\n\n¿Tus datos son correctos?\nNombre: *{convo.user_display_name}*\nCelular: *{convo.user_reported_phone}*")

        # --- ESTADO 5: Mostrando el Menú (Esperando opción 1-7) ('ia_show_menu') ---
        elif convo.status == 'ia_show_menu':
            opcion = message_body.strip()
            
            if opcion == '2':
                convo.status = 'ia_cotizaciones_sub' # Mover al sub-menú
                db.session.add(convo)
                return ("chat", _get_cotizaciones_menu())
            
            elif opcion in ['1', '3', '4', '5', '6', '7']:
                # Opción 1, 3, 4, 5, 6, 7: Enviar mensaje detallado y luego ENRUTAR
                role, response_msg = _get_agent_response_and_role(opcion)
                # La acción 'route_and_message' indica a webhook que envíe el mensaje Y ENRUTE.
                return ("route_and_message", {"role": role, "message": response_msg})
            
            else:
                return ("chat", f"La opción *'{opcion}'* no es válida. Por favor, selecciona un número del 1 al 7.\n\n" + _get_main_menu(convo.user_display_name))

        # --- ESTADO 6: Sub-Menú de Cotizaciones ('ia_cotizaciones_sub') ---
        elif convo.status == 'ia_cotizaciones_sub':
            sub_opcion = message_body.strip()
            
            if sub_opcion == '1':
                # Autos: Mover a estado de autos y dar respuesta
                convo.status = 'ia_cotizaciones_autos'
                db.session.add(convo)
                return ("chat", _get_cotizacion_detail('1'))
            elif sub_opcion == '2':
                # Hogar: Mover a estado de hogar y dar respuesta
                convo.status = 'ia_cotizaciones_hogar'
                db.session.add(convo)
                return ("chat", _get_cotizacion_detail('2'))
            elif sub_opcion == '3':
                # Empresa: Mover a estado de empresa y dar respuesta
                convo.status = 'ia_cotizaciones_empresa'
                db.session.add(convo)
                return ("chat", _get_cotizacion_detail('3'))
            elif sub_opcion == '4':
                # Vida/Salud/Otros: Dar respuesta y ENRUTAR a agente (Ventas)
                response_msg = _get_cotizacion_detail('4')
                return ("route_and_message", {"role": "Ventas", "message": response_msg})
            else:
                # Opción inválida, repetir el sub-menú
                return ("chat", f"La opción *'{sub_opcion}'* no es válida. Por favor, selecciona un número del 1 al 4.\n\n" + _get_cotizaciones_menu())

        # --- ESTADOS FINALES DE COTIZACIÓN (Solo esperan A o enrutan a Area Cotizaciones) ---
        elif convo.status in ['ia_cotizaciones_autos', 'ia_cotizaciones_hogar', 'ia_cotizaciones_empresa']:
            # Cualquier otro mensaje en estos estados (que no sea 'A') debe enrutar a un agente de cotizaciones
            return ("route", "Area Cotizaciones")

        # --- ESTADO FALLBACK (Por si acaso) ---
        else:
            convo.status = 'ia_greeting' # Reiniciar
            db.session.add(convo)
            return ("chat", "Parece que hubo un error. Empecemos de nuevo. ¡Hola! Bienvenido a *VTN SEGUROS*...")

    except Exception as e:
        logging.error(f"Error en la máquina de estados de IA: {e}")
        # Fallback de seguridad: enrutar a General
        return ("route", "General")




# --- WEBHOOK MODIFICADO PARA BAILEYS (CON MÁQUINA DE ESTADOS) ---
@app.route('/api/baileys/webhook', methods=['POST'])
def baileys_webhook():
    data = request.json
    message_body = data.get('Body')
    sender_phone = data.get('From')
    
    if not message_body or not sender_phone:
        logging.warning("Webhook (Baileys) recibido sin 'Body' o 'From'.")
        return jsonify({"error": "Faltan 'Body' o 'From'"}), 400
        
    logging.info(f"Mensaje (Baileys) recibido de {sender_phone}: {message_body}")

    try:
        # Escenario A: Chat abierto y asignado a un humano
        existing_convo = Conversation.query.filter_by(user_phone=sender_phone).order_by(Conversation.created_at.desc()).first()
        if existing_convo and existing_convo.status == 'open':
            logging.info(f"Conversación ABIERTA (ID: {existing_convo.id}) encontrada para {sender_phone}. Enviando a agente.")
            new_message = Message(conversation_id=existing_convo.id, sender_type='user', content=message_body)
            db.session.add(new_message)
            existing_convo.unread_count = (existing_convo.unread_count or 0) + 1
            existing_convo.updated_at = datetime.utcnow()
            role = existing_convo.bot_role
            if role and not existing_convo.pending_counted:
                role.chats_pending = (role.chats_pending or 0) + 1
                existing_convo.pending_counted = True
            db.session.commit()
            return jsonify({"status": "message_queued"}), 200

        bot_config = BotConfig.query.first()
        if not bot_config or not bot_config.is_active:
            logging.info("Bot inactivo. Ignorando mensaje.")
            return jsonify({"status": "bot_inactive"}), 200
        
        # Escenario B: Chat en CUALQUIER fase de IA ('ia_greeting', 'ia_ask_name', etc.)
        if existing_convo and existing_convo.status.startswith('ia_'):
            logging.info(f"Continuando chat IA (ID: {existing_convo.id}, Estado: {existing_convo.status})")
            convo = existing_convo
            
            # Guardar el mensaje del usuario (ej. "Juan Perez", "sí", "1")
            user_msg = Message(conversation_id=convo.id, sender_type='user', content=message_body)
            db.session.add(user_msg)
            
            # Obtener la respuesta de la máquina de estados
            action, data = get_ia_response_and_route(convo, message_body)

        # Escenario C: Conversación nueva (o 'closed')
        else:
            logging.info(f"Creando nueva conversación IA para {sender_phone}.")
            general_role = BotRole.query.filter_by(title='General').first()
            if not general_role:
                 logging.error("CRÍTICO: No se encontró el rol 'General' para iniciar chats IA.")
                 return jsonify({"error": "Configuración interna del servidor"}), 500

            # --- INICIO DE MODIFICACIÓN: Buscar datos anteriores ---
            previous_data = Conversation.query.filter(
                Conversation.user_phone == sender_phone,
                Conversation.user_display_name.isnot(None)
            ).order_by(Conversation.created_at.desc()).first()
            
            convo = Conversation(user_phone=sender_phone, bot_role_id=general_role.id)
            
            if previous_data:
                logging.info(f"Usuario conocido encontrado. Nombre: {previous_data.user_display_name}")
                # Si lo encontramos, copiamos los datos y saltamos al menú
                convo.user_display_name = previous_data.user_display_name
                convo.user_reported_phone = previous_data.user_reported_phone
                convo.status = 'ia_greeting_known' # El nuevo estado
            else:
                # Si no, iniciamos el flujo normal de bienvenida
                convo.status = 'ia_greeting'
            # --- FIN DE MODIFICACIÓN ---

            db.session.add(convo)
            db.session.flush() # Para obtener el convo.id
            
            # Guardar el primer mensaje del usuario (ej. "Hola")
            user_msg = Message(conversation_id=convo.id, sender_type='user', content=message_body)
            db.session.add(user_msg)
            
            # Obtener la respuesta de la máquina de estados
            action, data = get_ia_response_and_route(convo, message_body)
        
        # --- PROCESAR LA ACCIÓN DE LA IA ---
        
        if action == "route":
            role_title = data
            target_role = BotRole.query.filter_by(title=role_title, status='Activo').first()
            
            if not target_role:
                logging.error(f"IA enrutó a '{role_title}' pero no se encontró o está inactivo.")
                ia_response_msg = f"Ups, el departamento de '{role_title}' no está disponible en este momento. ¿Puedo ayudarte con algo más?"
                send_reply(sender_phone, ia_response_msg)
                ia_msg_db = Message(conversation_id=convo.id, sender_type='system', content=ia_response_msg)
                db.session.add(ia_msg_db)
                db.session.commit()
                return jsonify({"status": "route_failed"}), 200
            
            logging.info(f"IA enrutó chat {convo.id} a '{target_role.title}'. Cambiando status a 'open'.")
            convo.status = 'open'
            convo.bot_role_id = target_role.id
            convo.pending_counted = True
            
            target_role.chats_received = (target_role.chats_received or 0) + 1
            target_role.chats_pending = (target_role.chats_pending or 0) + 1

            transfer_message = f"¡Entendido! Un agente del área de {target_role.title} te atenderá pronto."
            send_reply(sender_phone, transfer_message)
            
            system_msg_db = Message(conversation_id=convo.id, sender_type='system', content=f"Chat enrutado por IA a {target_role.title}.")
            ia_msg_db = Message(conversation_id=convo.id, sender_type='system', content=transfer_message)
            db.session.add_all([system_msg_db, ia_msg_db])
            
        elif action == "route_and_message":
            # Nuevo tipo de acción: Enviar mensaje detallado Y luego enrutar (Opciones 1, 3, 4, 5, 6, 7 y 2.4)
            role_title = data['role']
            full_response = data['message'] # Es la respuesta completa con formato
            
            target_role = BotRole.query.filter_by(title=role_title, status='Activo').first()

            # 1. Enviar mensaje detallado al usuario
            send_reply(sender_phone, full_response)
            
            # 2. Guardar el mensaje en la BD
            ia_msg_db = Message(conversation_id=convo.id, sender_type='system', content=full_response)
            db.session.add(ia_msg_db)
            
            if not target_role:
                logging.error(f"IA intentó enrutar a '{role_title}' pero no se encontró o está inactivo.")
                # Si falla el ruteo, no cambiar estado, solo notificar.
                db.session.commit() 
                return jsonify({"status": "route_and_message_failed"}), 200

            # 3. Enrutar y cambiar estado a 'open'
            logging.info(f"IA envió mensaje y enrutó chat {convo.id} a '{target_role.title}'. Cambiando status a 'open'.")
            convo.status = 'open'
            convo.bot_role_id = target_role.id
            convo.pending_counted = True
            
            target_role.chats_received = (target_role.chats_received or 0) + 1
            target_role.chats_pending = (target_role.chats_pending or 0) + 1
            
            # 4. Registrar enrutamiento en la BD
            system_msg_db = Message(conversation_id=convo.id, sender_type='system', content=f"Chat enrutado por IA a {target_role.title}.")
            db.session.add(system_msg_db)

        elif action == "chat":
            # IA Sigue Chateando (ej. "ask phone", "confirm details", "menu")
            ia_response_msg = data
            send_reply(sender_phone, ia_response_msg)
            # Guardar la respuesta del bot
            ia_msg_db = Message(conversation_id=convo.id, sender_type='system', content=ia_response_msg)
            db.session.add(ia_msg_db)

        convo.updated_at = datetime.utcnow()
        db.session.commit()
        return jsonify({"status": "ia_processed"}), 200


@app.route('/api/chats', methods=['GET'])
@login_required
def get_chats():
    try:
        chat_status = request.args.get('status', 'open') 
        if chat_status not in ['open', 'closed']:
            chat_status = 'open'

        conversations_query = None
        if current_user.role == 'Admin':
            conversations_query = Conversation.query.filter_by(status=chat_status).options(
                db.joinedload(Conversation.messages),
                db.joinedload(Conversation.bot_role)
            )
        else:
            assigned_role_ids = [role.id for role in current_user.assigned_roles]
            if assigned_role_ids:
                conversations_query = Conversation.query.filter(
                    Conversation.bot_role_id.in_(assigned_role_ids),
                    Conversation.status == chat_status
                ).options(
                    db.joinedload(Conversation.messages),
                    db.joinedload(Conversation.bot_role)
                )
            else:
                logging.info(f"Usuario {current_user.username} (Soporte) no tiene roles asignados.")
                return jsonify([]) 

        if conversations_query is None:
             return jsonify([])

        open_conversations = conversations_query.order_by(Conversation.updated_at.desc()).all()
        
        chat_list = []
        for convo in open_conversations:
            last_msg = convo.get_last_message()
            
            # --- INICIO DE MODIFICACIÓN ---
            # Fallback JID (el ID ...@lid)
            clean_phone = convo.user_phone.split('@')[0].replace('whatsapp:', '').replace('+', '')
            
            # Usar el nombre/teléfono reportado si existe, si no, el JID
            display_name = convo.user_display_name or clean_phone
            display_phone = convo.user_reported_phone or clean_phone
            # --- FIN DE MODIFICACIÓN ---
            
            chat_list.append({
                "id": convo.id,
                "name": display_name,  # <-- MODIFICADO
                "phone": display_phone, # <-- MODIFICADO
                "time": last_msg.timestamp.strftime("%I:%M %p") if last_msg and last_msg.timestamp else 'N/A',
                "unread": convo.unread_count or 0,
                "last_message": last_msg.content if last_msg else "Sin mensajes",
                "updated_at": convo.updated_at.isoformat() if convo.updated_at else convo.created_at.isoformat(),
                "bot_role_id": convo.bot_role_id,
                "bot_role_title": convo.bot_role.title if convo.bot_role else "N/A"
            })
        return jsonify(chat_list)
    except Exception as e:
        logging.error(f"Error en /api/chats: {e}")
        logging.exception(e) 
        return jsonify({"error": str(e)}), 500

@app.route('/api/chats/<int:convo_id>/messages', methods=['GET'])
@login_required
def get_chat_messages(convo_id):
    convo = Conversation.query.get_or_404(convo_id)
    if current_user.role != 'Admin':
        assigned_role_ids = [role.id for role in current_user.assigned_roles]
        if convo.bot_role_id not in assigned_role_ids:
            return jsonify({"error": "No autorizado para ver este chat"}), 403
            
    if convo.status == 'open' and convo.unread_count > 0:
        convo.unread_count = 0
    
    if convo.status == 'open' and convo.pending_counted:
        role = convo.bot_role
        if role and role.chats_pending > 0:
            role.chats_pending = role.chats_pending - 1
        convo.pending_counted = False
        
    db.session.commit()
    
    messages = [{"sender": msg.sender_type, "text": msg.content} for msg in convo.messages]
    return jsonify(messages)

# --- FUNCIÓN DE ENVÍO DE MENSAJES (Agente Humano) ---
# (Esta función ya era correcta para la arquitectura de Baileys)
@app.route('/api/chats/<int:convo_id>/messages', methods=['POST'])
@login_required
def send_chat_message(convo_id):
    convo = Conversation.query.get_or_404(convo_id)
    
    # Lógica de permisos
    if current_user.role != 'Admin':
        assigned_role_ids = [role.id for role in current_user.assigned_roles]
        if convo.bot_role_id not in assigned_role_ids:
            return jsonify({"error": "No autorizado para enviar a este chat"}), 403
            
    data = request.get_json()
    content = data.get('text')
    if not content: return jsonify({"error": "El texto no puede estar vacío"}), 400

    # Obtener la URL del bot de Baileys desde las variables de entorno
    baileys_bot_url = os.getenv('BAILEYS_BOT_URL')
    if not baileys_bot_url:
        logging.error("BAILEYS_BOT_URL no está configurada. No se puede enviar mensaje.")
        return jsonify({"error": "El servicio de envío no está configurado"}), 500

    try:
        # Reactivar chat si está cerrado
        if convo.status == 'closed':
            logging.info(f"Reactivando chat {convo_id} (estado 'closed') por {current_user.name}.")
            convo.status = 'open'
            convo.unread_count = 0 
            convo.pending_counted = True 
            
            role = convo.bot_role
            if role:
                # Revertir contadores
                if role.chats_resolved and role.chats_resolved > 0:
                    role.chats_resolved = role.chats_resolved - 1
                role.chats_pending = (role.chats_pending or 0) + 1
                logging.info(f"Contadores del Rol '{role.title}' actualizados: Pendientes={role.chats_pending}, Resueltos={role.chats_resolved}")

        # --- REEMPLAZO DE TWILIO ---
        # Hacemos una petición POST al endpoint /send de nuestro bot.js
        
        send_url = f"{baileys_bot_url}/send"
        payload = {
            "number": convo.user_phone, # app.py ya lo guarda como 'whatsapp:+...'
            "message": content
        }
        
        # --- CORRECCIÓN DE TIMEOUT ---
        # Aumentamos el timeout a 30 segundos para manejar el "cold start" de OnRender
        response = requests.post(send_url, json=payload, timeout=30)
        
        # Si el bot de Baileys da error, lo reportamos
        if response.status_code != 200:
            raise Exception(f"El bot de Baileys respondió con {response.status_code}: {response.text}")
        # --- FIN DE REEMPLAZO ---
        
        new_message = Message(conversation_id=convo.id, sender_type='agent', content=content)
        db.session.add(new_message)
        convo.updated_at = datetime.utcnow()
        
        db.session.commit()
        return jsonify({"success": True, "message": {"sender": "agent", "text": content}}), 201
    
    except Exception as e:
        logging.error(f"Error al enviar mensaje (vía Baileys) o guardar en BD: {e}")
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@app.route('/api/chats/<int:convo_id>/resolve', methods=['POST'])
@login_required
def resolve_chat(convo_id):
    convo = Conversation.query.get_or_404(convo_id)
    if current_user.role != 'Admin':
        assigned_role_ids = [role.id for role in current_user.assigned_roles]
        if convo.bot_role_id not in assigned_role_ids:
            return jsonify({"error": "No autorizado para resolver este chat"}), 403
    try:
        convo.status = 'closed'
        role = convo.bot_role
        if role:
            role.chats_resolved = (role.chats_resolved or 0) + 1
            if convo.pending_counted and role.chats_pending > 0:
                role.chats_pending = role.chats_pending - 1
                convo.pending_counted = False
        db.session.commit()
        logging.info(f"Chat ID {convo_id} marcado como resuelto. Rol '{role.title if role else 'N/A'}' - Pendientes: {role.chats_pending if role else 'N/A'}, Resueltos: {role.chats_resolved if role else 'N/A'}")
        return jsonify({"success": True, "message": "Chat archivado."})
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al resolver chat {convo_id}: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/chats/<int:convo_id>/transfer', methods=['POST'])
@login_required
def transfer_chat(convo_id):
    convo = Conversation.query.get_or_404(convo_id)
    data = request.get_json()
    target_role_id = data.get('target_role_id')

    if not target_role_id:
        return jsonify({"error": "Falta el ID del rol de destino"}), 400

    if current_user.role != 'Admin':
         assigned_role_ids = [role.id for role in current_user.assigned_roles]
         if convo.bot_role_id not in assigned_role_ids:
             return jsonify({"error": "No autorizado para transferir este chat"}), 403

    try:
        original_role = convo.bot_role
        target_role = BotRole.query.get(target_role_id)

        if not target_role:
            return jsonify({"error": "Rol de destino no encontrado"}), 404
        if original_role and original_role.id == target_role.id:
            return jsonify({"error": "No se puede transferir al mismo rol"}), 400

        if original_role:
            if convo.pending_counted and original_role.chats_pending > 0:
                original_role.chats_pending = original_role.chats_pending - 1
        
        target_role.chats_pending = (target_role.chats_pending or 0) + 1
        
        convo.bot_role_id = target_role.id
        convo.pending_counted = True 
        convo.updated_at = datetime.utcnow() 
        
        system_message = Message(
            conversation_id=convo.id,
            sender_type='system',
            content=f"Chat transferido de '{original_role.title if original_role else 'N/A'}' a '{target_role.title}' por {current_user.name}."
        )
        db.session.add(system_message)
        
        db.session.commit()
        logging.info(f"Chat ID {convo_id} transferido de Rol ID {original_role.id if original_role else 'N/A'} a Rol ID {target_role.id}.")
        
        return jsonify({"success": True, "message": "Chat transferido correctamente."})

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al transferir chat {convo_id}: {e}")
        return jsonify({"error": str(e)}), 500

# --- INICIO DE MODIFICACIÓN: APIs de Importación de Chat ELIMINADAS ---
@app.route('/api/admin/upload_database', methods=['POST'])
@login_required
def upload_database():
    admin_check = check_admin()
    if admin_check: return admin_check

    try:
        if 'file' not in request.files:
            return jsonify({"error": "No se encontró el archivo"}), 400
        
        file = request.files['file']
        
        if not file or file.filename == '':
            return jsonify({"error": "No se seleccionó ningún archivo"}), 400
        
        # --- INICIO DE MODIFICACIÓN: Lógica de CSV ---
        # Nombres de columna esperados (los encabezados en A1, B1, C1...)
        expected_columns = [
            'ASEGURADORA', 'NOMBRES', 'CEDULA/NIT', 'TIPO', 'PLACA', 
            'MODELO', 'VLOR POLIZA', 'MES VENCIMIENTO', 'FECHA VENC', 'REFERENCIA'
        ]
        
        df = None
        
        try:
            # Primero, intentar con coma (estándar UTF-8)
            file.seek(0) # Asegurar que el puntero esté al inicio
            df = pd.read_csv(file, header=0, dtype=str, encoding='utf-8', sep=',').fillna('')
            
            # Si solo hay una columna, es probable que el separador sea incorrecto.
            # Probar con punto y coma (común en Excel de Windows/Latam).
            if len(df.columns) <= 1:
                logging.warning("Detectada una sola columna con coma. Reintentando con punto y coma.")
                file.seek(0) # Resetear puntero
                df = pd.read_csv(file, header=0, dtype=str, encoding='utf-8', sep=';').fillna('')
                
        except UnicodeDecodeError:
            # Si falla UTF-8, probar con latin-1, (muy común en Excel de Windows)
            logging.warning("Error con UTF-8. Reintentando con 'latin-1' y punto y coma.")
            try:
                file.seek(0)
                # Probar latin-1 con punto y coma primero
                df = pd.read_csv(file, header=0, dtype=str, encoding='latin-1', sep=';').fillna('')
                if len(df.columns) <= 1:
                    logging.warning("Detectada una sola columna (latin-1) con punto y coma. Reintentando con coma.")
                    file.seek(0)
                    df = pd.read_csv(file, header=0, dtype=str, encoding='latin-1', sep=',').fillna('')
            except Exception as e:
                 logging.error(f"Error final al leer CSV (latin-1): {e}")
                 return jsonify({"error": f"Error al leer el archivo. Intente guardar como 'CSV (Delimitado por comas)' o 'CSV (UTF-8)' desde Excel. Error: {e}"}), 400
        except Exception as e:
            logging.error(f"Error al leer el CSV: {e}")
            return jsonify({"error": f"Error al procesar el archivo CSV: {e}"}), 400
        # --- FIN DE MODIFICACIÓN ---

        if df is None:
             return jsonify({"error": "No se pudo procesar el DataFrame."}), 500

        # Verificar columnas después de cargar
        if not all(col in df.columns for col in expected_columns):
            logging.warning(f"Columnas faltantes. Esperadas: {expected_columns}. Encontradas: {list(df.columns)}")
            return jsonify({"error": f"El archivo CSV debe tener las columnas exactas (sensible a mayúsculas): {', '.join(expected_columns)}"}), 400
            
        # 1. Borrar todos los datos antiguos
        PolicyData.query.delete()
        logging.info("Base de datos de pólizas anterior eliminada.")
        
        # 2. Insertar nuevos datos
        records_added = 0
        for index, row in df.iterrows():
            new_record = PolicyData(
                aseguradora=row['ASEGURADORA'],
                nombres=row['NOMBRES'],
                cedula_nit=row['CEDULA/NIT'],
                tipo=row['TIPO'],
                placa=row['PLACA'],
                modelo=row['MODELO'],
                valor_poliza=row['VLOR POLIZA'],
                mes_vencimiento=row['MES VENCIMIENTO'],
                fecha_venc=row['FECHA VENC'],
                referencia=row['REFERENCIA']
            )
            db.session.add(new_record)
            records_added += 1
        
        db.session.commit()
        
        logging.info(f"Base de datos de pólizas cargada. {records_added} registros añadidos.")
        return jsonify({"success": True, "message": f"Base de datos cargada con éxito. Se añadieron {records_added} registros."})

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error fatal en /api/admin/upload_database: {e}")
        logging.exception(e)
        return jsonify({"error": f"Error interno del servidor: {e}"}), 500

@app.route('/api/database_records', methods=['GET'])
@login_required
def get_database_records():
    # Esta ruta es accesible tanto por Admin como por Soporte
    search_term = request.args.get('search', '').strip()
    
    try:
        query = PolicyData.query
        
        if search_term:
            search_pattern = f"%{search_term}%"
            query = query.filter(
                or_(
                    PolicyData.nombres.ilike(search_pattern),
                    PolicyData.cedula_nit.ilike(search_pattern),
                    PolicyData.placa.ilike(search_pattern)
                )
            )
            
        records = query.order_by(PolicyData.nombres).all()
        
        # Convertir objetos a diccionarios
        results = [
            {
                "id": r.id,
                "aseguradora": r.aseguradora,
                "nombres": r.nombres,
                "cedula_nit": r.cedula_nit,
                "tipo": r.tipo,
                "placa": r.placa,
                "modelo": r.modelo,
                "valor_poliza": r.valor_poliza,
                "mes_vencimiento": r.mes_vencimiento,
                "fecha_venc": r.fecha_venc,
                "referencia": r.referencia
            } for r in records
        ]
        
        return jsonify(results)
        
    except Exception as e:
        logging.error(f"Error en /api/database_records: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/database_records/<int:id>', methods=['PUT'])
@login_required
def update_database_record(id):
    # Soporte y Admin pueden editar
    record = PolicyData.query.get_or_404(id)
    data = request.get_json()
    
    try:
        record.aseguradora = data.get('aseguradora', record.aseguradora)
        record.nombres = data.get('nombres', record.nombres)
        record.cedula_nit = data.get('cedula_nit', record.cedula_nit)
        record.tipo = data.get('tipo', record.tipo)
        record.placa = data.get('placa', record.placa)
        record.modelo = data.get('modelo', record.modelo)
        record.valor_poliza = data.get('valor_poliza', record.valor_poliza)
        record.mes_vencimiento = data.get('mes_vencimiento', record.mes_vencimiento)
        record.fecha_venc = data.get('fecha_venc', record.fecha_venc)
        record.referencia = data.get('referencia', record.referencia)
        
        db.session.commit()
        return jsonify({"success": True, "message": "Registro actualizado."})
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error actualizando registro {id}: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/database_records/<int:id>', methods=['DELETE'])
@login_required
def delete_database_record(id):
    # Soporte y Admin pueden borrar
    record = PolicyData.query.get_or_404(id)
    
    try:
        db.session.delete(record)
        db.session.commit()
        return jsonify({"success": True, "message": "Registro eliminado."})
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error eliminando registro {id}: {e}")
        return jsonify({"error": str(e)}), 500

# --- FIN DE NUEVAS APIS ---


# --- APIs DE DASHBOARD ---
@app.route('/api/dashboard/soporte')
@login_required
def get_soporte_dashboard_data():
    try:
        assigned_role_ids = []
        if current_user.role == 'Admin':
            assigned_role_ids = [role.id for role in BotRole.query.all()]
        else:
            assigned_role_ids = [role.id for role in current_user.assigned_roles]
        if not assigned_role_ids:
            return jsonify({"stats": {"today": 0, "week": 0, "month": 0}, "lineChart": {"labels": [], "data": []}, "barChart": {"labels": [], "data": []}})
        today = datetime.utcnow().date()
        start_of_today = datetime(today.year, today.month, today.day)
        start_of_week = start_of_today - timedelta(days=today.weekday())
        start_of_month = datetime(today.year, today.month, 1)
        messages_today = Message.query.join(Conversation).filter(Message.timestamp >= start_of_today, Conversation.bot_role_id.in_(assigned_role_ids)).count()
        messages_week = Message.query.join(Conversation).filter(Message.timestamp >= start_of_week, Conversation.bot_role_id.in_(assigned_role_ids)).count()
        messages_month = Message.query.join(Conversation).filter(Message.timestamp >= start_of_month, Conversation.bot_role_id.in_(assigned_role_ids)).count()
        labels = []
        data = []
        for i in range(6, -1, -1):
            day = start_of_today - timedelta(days=i)
            next_day = day + timedelta(days=1)
            count = Message.query.join(Conversation).filter(Message.timestamp >= day, Message.timestamp < next_day, Conversation.bot_role_id.in_(assigned_role_ids)).count()
            labels.append(day.strftime("%a"))
            data.append(count)
        line_chart = {"labels": labels, "data": data}
        role_data = db.session.query(BotRole.title, func.count(Conversation.id)).join(Conversation, BotRole.id == Conversation.bot_role_id).filter(BotRole.id.in_(assigned_role_ids)).group_by(BotRole.title).all()
        bar_chart = {"labels": [r[0] for r in role_data], "data": [r[1] for r in role_data]}
        return jsonify({"stats": {"today": messages_today, "week": messages_week, "month": messages_month}, "lineChart": line_chart, "barChart": bar_chart})
    except Exception as e:
        logging.error(f"Error en /api/dashboard/soporte: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/dashboard/admin')
@login_required
def get_admin_dashboard_data():
    admin_check = check_admin()
    if admin_check: return admin_check
    try:
        today = datetime.utcnow().date()
        start_of_today = datetime(today.year, today.month, today.day)
        stats_asistentes_activos = User.query.filter_by(role='Soporte').count()
        stats_chats_hoy = Conversation.query.filter(Conversation.created_at >= start_of_today).count()
        stats_chats_resueltos = db.session.query(func.sum(BotRole.chats_resolved)).scalar() or 0
        labels = []
        data = []
        for i in range(6, -1, -1):
            day = start_of_today - timedelta(days=i)
            next_day = day + timedelta(days=1)
            count = Conversation.query.filter(Conversation.created_at >= day, Conversation.created_at < next_day).count()
            labels.append(day.strftime("%a"))
            data.append(count)
        line_chart = {"labels": labels, "data": data}
        role_data = db.session.query(BotRole.title, func.count(Conversation.id)).join(Conversation, BotRole.id == Conversation.bot_role_id).group_by(BotRole.title).all()
        bar_chart = {"labels": [r[0] for r in role_data], "data": [r[1] for r in role_data]}
        table_data = []
        latest_convos = Conversation.query.order_by(Conversation.created_at.desc()).limit(5).all()
        for convo in latest_convos:
            assignee_name = "N/A"
            role_title = "N/A"
            if convo.bot_role:
                role_title = convo.bot_role.title
                if convo.bot_role.assignee:
                    assignee_name = convo.bot_role.assignee.name
            table_data.append({"id": f"#{convo.id:04d}", "assignee": assignee_name, "role": role_title, "status": convo.status.capitalize()})
        return jsonify({"stats": {"asistentes_activos": stats_asistentes_activos, "chats_hoy": stats_chats_hoy, "chats_resueltos": stats_chats_resueltos}, "lineChart": line_chart, "barChart": bar_chart, "table_data": table_data})
    except Exception as e:
        logging.error(f"Error en /api/dashboard/admin: {e}")
        return jsonify({"error": str(e)}), 500


# --- INICIALIZACIÓN DE LA APLICACIÓN ---
def init_db(app_instance):
    with app_instance.app_context():
        try:
            db.create_all() # <-- Esto creará la nueva tabla PolicyData
            logging.info("Tablas de la base de datos verificadas/creadas.")
            if not User.query.filter_by(role='Admin').first():
                logging.info("Creando usuario 'admin' por defecto.")
                db.session.add(User(username='admin', password='admin', name='Administrador', role='Admin'))
            if not User.query.filter_by(role='Soporte').first():
                logging.info("Creando usuario 'soporte' por defecto.")
                db.session.add(User(username='soporte', password='soporte', name='Agente de Soporte', role='Soporte'))
            if not BotConfig.query.first():
                logging.info("Creando configuración de bot por defecto.")
                db.session.add(BotConfig(is_active=True, whatsapp_number="+573132217862", welcome_message="¡Hola! Bienvenido a nuestro servicio de atención. ¿En qué puedo ayudarte hoy?"))
            
            if not BotRole.query.filter_by(title='General').first():
                logging.info("Creando rol por defecto: 'General'")
                db.session.add(BotRole(title='General', knowledge_base='Preguntas frecuentes o chat inicial.', status='Activo'))

            roles_default = {
                "Area Cotizaciones": "Es el cotizador de negocios...", "Renovaciones": "De manera proactiva...",
                "Agente de ventas/Comercial #1": "Este módulo actúa como...", "Agente de ventas/Comercial #2": "Módulo de primer contacto...",
                "Agente de ventas/Comercial #3": "Módulo de primer contacto...", "Siniestros, Consultas Póliza, Cancelaciones": "Diseñado para asistir...",
                "Ventas": "Consultas sobre compra...", "Soporte Técnico": "Problemas con la plataforma..."
            }
            for title, knowledge in roles_default.items():
                if not BotRole.query.filter_by(title=title).first():
                    logging.info(f"Creando rol por defecto: '{title}'")
                    db.session.add(BotRole(title=title, knowledge_base=knowledge))
            
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error durante la inicialización de la BD: {e}")

init_db(app)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)