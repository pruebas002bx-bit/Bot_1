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
    bot_role = db.relationship('BotRole', back_populates='conversations')
    messages = db.relationship('Message', back_populates='conversation', cascade="all, delete-orphan", order_by='Message.timestamp')
    
    # --- CAMBIO: 'import_source' ya no se usa, pero se puede mantener si se desea ---
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

def get_ia_response_and_route(messages_list):
    """
    Gestiona la conversación con Gemini.
    Presenta un menú, confirma la selección y luego enruta.
    """
    logging.info("Iniciando IA conversacional (get_ia_response_and_route)...")
    if not genai:
        logging.error("Módulo de IA (Gemini) no está configurado.")
        # Fallback de seguridad: enrutar a General si Gemini falla
        return ("route", "General") 

    try:
        # Definimos el menú aquí para que sea fácil de editar
        menu_principal = """Hola! Bienvenido a VTN SEGUROS - Grupo Montenegro. Para nosotros es un gusto atenderte 🫡

Escribe el número de tu solicitud:

1. Presentas un accidente. 🚑
2. Requieres una cotización. 📊
3. Continuar con proceso de compra.💳
4. Inquietudes de tu póliza, certificados, coberturas, pagos y renovaciones.✍🏼
5. Consultar estado de siniestro⏳
6. Solicitud de cancelación de póliza y reintegro de dinero.📝
7. Comunicarse directamente con asesor por motivo de quejas y peticiones. ☹

Agradecemos la confianza depositada en nuestra labor."""

        # Mapeo de números a Roles (como están definidos en tu init_db)
        # Asegúrate de que estos roles existan en tu base de datos
        mapeo_roles = {
            "1": "Siniestros, Consultas Póliza, Cancelaciones", # Usado para accidentes
            "2": "Area Cotizaciones",
            "3": "Ventas",
            "4": "Renovaciones",
            "5": "Siniestros, Consultas Póliza, Cancelaciones", # Usado para consultar siniestro
            "6": "Siniestros, Consultas Póliza, Cancelaciones", # Usado para cancelación
            "7": "Soporte Técnico" # Usado para quejas y peticiones
        }

        # Opciones de texto para el menú (para que la IA las entienda)
        opciones_texto = {
            "1": "Presentas un accidente",
            "2": "Requieres una cotización",
            "3": "Continuar con proceso de compra",
            "4": "Inquietudes de tu póliza... y renovaciones",
            "5": "Consultar estado de siniestro",
            "6": "Solicitud de cancelación de póliza...",
            "7": "Comunicarse directamente con asesor..."
        }


        system_prompt = f"""
        Eres 'Montenegro', un asistente virtual de VTN SEGUROS. Tu ÚNICO trabajo es presentar un menú, obtener una selección numérica (1-7), confirmar esa selección y luego enrutar.

        Este es el menú que *siempre* debes mostrar al inicio y si el usuario se equivoca o escribe texto inválido:
        ---
        {menu_principal}
        ---

        Este es el mapeo de números a Roles (NO muestres esto al usuario, es tu guía interna):
        - "1": "{mapeo_roles['1']}"
        - "2": "{mapeo_roles['2']}"
        - "3": "{mapeo_roles['3']}"
        - "4": "{mapeo_roles['4']}"
        - "5": "{mapeo_roles['5']}"
        - "6": "{mapeo_roles['6']}"
        - "7": "{mapeo_roles['7']}"

        Reglas de Conversación:
        1.  **Primer Mensaje (Historial vacío o 1 mensaje de usuario):** Si el historial está vacío o solo contiene un saludo del usuario (como 'hola'), responde *únicamente* con el menú completo. No añadas nada más.
        2.  **Usuario selecciona un número (ej: '2'):**
            - Busca el rol (ej: "Area Cotizaciones") y el texto de la opción (ej: "Requieres una cotización").
            - Responde *únicamente* con el JSON de confirmación:
              {{"action": "chat", "response_message": "Seleccionaste la opción 2: 'Requieres una cotización'. ¿Es esto correcto? (Responde 'sí' o 'no')"}}
        3.  **Usuario confirma (ej: 'sí', 'correcto', 'si es'):**
            - (Esto ocurre DESPUÉS de tu pregunta de confirmación).
            - Identifica el rol que estabas confirmando (ej: "Area Cotizaciones").
            - Responde *únicamente* con el JSON de enrutamiento:
              {{"action": "route", "role_title": "Area Cotizaciones"}}
        4.  **Usuario niega (ej: 'no', 'me equivoqué'):**
            - Responde *únicamente* con el menú completo de nuevo.
        5.  **Usuario envía texto inválido (ej: 'ayuda', 'quiero un seguro'):**
            - Responde *únicamente* con el menú completo de nuevo.

        Historial de Conversación (último mensaje es del usuario):
        """

        chat_history_for_prompt = []
        for msg in messages_list:
            if msg.sender_type == 'user':
                chat_history_for_prompt.append(f"Usuario: {msg.content}")
            elif msg.sender_type == 'system':
                # Si el mensaje del sistema es el menú, no lo incluyas en el historial
                if menu_principal not in msg.content:
                    chat_history_for_prompt.append(f"Montenegro: {msg.content}")
        
        # --- LÓGICA SIMPLIFICADA PARA EL PRIMER MENSAJE ---
        # Si solo hay 1 mensaje (del usuario), forzamos la respuesta del menú
        # Esto evita que la IA intente "continuar" una conversación que no existe
        if len(messages_list) == 1 and messages_list[0].sender_type == 'user':
             logging.info("Forzando menú de bienvenida para el primer mensaje.")
             return ("chat", menu_principal)
        
        final_prompt = system_prompt + "\n".join(chat_history_for_prompt)

        logging.info(f"Enviando prompt a Gemini 2.5-flash...")
        model = genai.GenerativeModel('gemini-2.5-flash')
        response = model.generate_content(final_prompt)
        
        response_text = response.text.strip()
        logging.info(f"Respuesta de Gemini: {response_text}")

        try:
            # Limpiar el markdown JSON si Gemini lo envía
            if response_text.startswith("```json"):
                response_text = re.sub(r"```json\n(.*?)\n```", r"\1", response_text, flags=re.DOTALL)
            
            data = json.loads(response_text)
            action = data.get("action")
            
            if action == "route":
                role_title = data.get("role_title")
                # Verificamos que el rol exista en nuestro mapeo
                if role_title in mapeo_roles.values():
                    logging.info(f"IA decidió ENRUTAR a: '{role_title}'")
                    return ("route", role_title)
                else:
                    logging.warning(f"IA intentó enrutar a rol inválido: '{role_title}'. Mostrando menú.")
                    return ("chat", menu_principal) # Fallback si el rol no existe

            elif action == "chat":
                message = data.get("response_message")
                logging.info(f"IA decidió CHATEAR: '{message}'")
                # Si el mensaje es el menú, nos aseguramos que sea el texto exacto
                if "Escribe el número de tu solicitud" in message:
                    return ("chat", menu_principal)
                else:
                    return ("chat", message)
            
            else:
                raise ValueError("JSON de IA no tiene 'action' válido.")

        except (json.JSONDecodeError, ValueError, TypeError) as e:
            logging.warning(f"Respuesta de Gemini no fue JSON válido ({e}). Tratando como chat: {response_text}")
            # Si Gemini no devuelve JSON, probablemente es el menú o un error
            # Si contiene el texto clave del menú, enviamos el menú limpio.
            if "Escribe el número de tu solicitud" in response_text:
                return ("chat", menu_principal)
            
            # Si no es JSON y no es el menú, es una respuesta de chat simple (aunque no debería pasar)
            clean_response = response_text.replace("*", "").strip()
            if not clean_response:
                clean_response = menu_principal # Fallback final
            return ("chat", clean_response)

    except Exception as e:
        logging.error(f"Error en la llamada a la API de Gemini: {e}")
        # Si Gemini falla, enviamos el menú para que el usuario al menos pueda intentarlo
        return ("chat", menu_principal)

# --- WEBHOOK MODIFICADO PARA BAILEYS ---
@app.route('/api/baileys/webhook', methods=['POST'])
def baileys_webhook():
    # Leer desde JSON, no desde Form
    data = request.json
    message_body = data.get('Body')
    sender_phone = data.get('From')
    
    if not message_body or not sender_phone:
        logging.warning("Webhook (Baileys) recibido sin 'Body' o 'From'.")
        return jsonify({"error": "Faltan 'Body' o 'From'"}), 400
        
    logging.info(f"Mensaje (Baileys) recibido de {sender_phone}: {message_body}")

    try:
        # Buscar la conversación más reciente con este número
        existing_convo = Conversation.query.filter_by(user_phone=sender_phone).order_by(Conversation.created_at.desc()).first()

        # Escenario A: Chat abierto y asignado a un humano
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
            # Devolver JSON OK (no TwiML)
            return jsonify({"status": "message_queued"}), 200

        bot_config = BotConfig.query.first()
        if not bot_config or not bot_config.is_active:
            logging.info("Bot inactivo. Ignorando mensaje.")
            return jsonify({"status": "bot_inactive"}), 200

        # Escenario B: Chat en fase de saludo/IA ('ia_greeting')
        if existing_convo and existing_convo.status == 'ia_greeting':
            logging.info(f"Continuando chat IA (ID: {existing_convo.id}) para {sender_phone}.")
            convo = existing_convo
            user_msg = Message(conversation_id=convo.id, sender_type='user', content=message_body)
            db.session.add(user_msg)
            
            messages_history = Message.query.filter_by(conversation_id=convo.id).order_by(Message.timestamp).all()
            
            action, data = get_ia_response_and_route(messages_history)
            
            if action == "route":
                role_title = data
                target_role = BotRole.query.filter_by(title=role_title, status='Activo').first()
                
                if not target_role:
                    logging.error(f"IA enrutó a '{role_title}' pero no se encontró o está inactivo.")
                    ia_response_msg = f"Ups, el departamento de '{role_title}' no está disponible en este momento. ¿Puedo ayudarte con algo más?"
                    # Enviar respuesta usando el helper
                    send_reply(sender_phone, ia_response_msg)
                    ia_msg_db = Message(conversation_id=convo.id, sender_type='system', content=ia_response_msg)
                    db.session.add(ia_msg_db)
                    db.session.commit()
                    return jsonify({"status": "route_failed"}), 200
                
                # --- Enrutamiento Exitoso ---
                logging.info(f"IA enrutó chat {convo.id} a '{target_role.title}'. Cambiando status a 'open'.")
                convo.status = 'open'
                convo.bot_role_id = target_role.id
                convo.pending_counted = True
                convo.updated_at = datetime.utcnow()
                
                target_role.chats_received = (target_role.chats_received or 0) + 1
                target_role.chats_pending = (target_role.chats_pending or 0) + 1

                transfer_message = f"¡Entendido! Un agente del área de {target_role.title} te atenderá pronto."
                # Enviar respuesta usando el helper
                send_reply(sender_phone, transfer_message)
                
                system_msg_db = Message(conversation_id=convo.id, sender_type='system', content=f"Chat enrutado por IA a {target_role.title}.")
                ia_msg_db = Message(conversation_id=convo.id, sender_type='system', content=transfer_message)
                db.session.add_all([system_msg_db, ia_msg_db])
                db.session.commit()
                
                return jsonify({"status": "routed_successfully"}), 200

            elif action == "chat":
                # --- IA Sigue Chateando ---
                ia_response_msg = data
                # Enviar respuesta usando el helper
                send_reply(sender_phone, ia_response_msg)
                ia_msg_db = Message(conversation_id=convo.id, sender_type='system', content=ia_response_msg)
                db.session.add(ia_msg_db)
                convo.updated_at = datetime.utcnow()
                db.session.commit()
                return jsonify({"status": "chat_reply_sent"}), 200
        
        # Escenario C: Conversación nueva (o 'closed')
        logging.info(f"No hay conversación activa para {sender_phone}. Creando nueva conversación IA.")
        
        general_role = BotRole.query.filter_by(title='General').first()
        if not general_role:
             logging.error("CRÍTICO: No se encontró el rol 'General' para iniciar chats IA.")
             return jsonify({"error": "Configuración interna del servidor"}), 500

        convo = Conversation(user_phone=sender_phone, bot_role_id=general_role.id, status='ia_greeting')
        db.session.add(convo)
        db.session.flush() # Para obtener el convo.id

        user_msg = Message(conversation_id=convo.id, sender_type='user', content=message_body)
        db.session.add(user_msg)
        
        action, data = get_ia_response_and_route([user_msg])

        if action == "route": # Improbable en el primer mensaje, pero posible
            role_title = data
            target_role = BotRole.query.filter_by(title=role_title, status='Activo').first()
            if target_role:
                logging.info(f"IA enrutó chat {convo.id} INMEDIATAMENTE a '{target_role.title}'.")
                convo.status = 'open'
                convo.bot_role_id = target_role.id
                convo.pending_counted = True
                target_role.chats_received = (target_role.chats_received or 0) + 1
                target_role.chats_pending = (target_role.chats_pending or 0) + 1
                
                transfer_message = f"¡Entendido! Un agente del área de {target_role.title} te atenderá pronto."
                # Enviar respuesta usando el helper
                send_reply(sender_phone, transfer_message)
                
                system_msg_db = Message(conversation_id=convo.id, sender_type='system', content=f"Chat enrutado por IA a {target_role.title}.")
                ia_msg_db = Message(conversation_id=convo.id, sender_type='system', content=transfer_message)
                db.session.add_all([system_msg_db, ia_msg_db])
            else:
                action = "chat"
                data = "¡Hola! Soy Montenegro, tu asistente virtual de Seguros Montenegro. ¿En qué puedo ayudarte hoy?"
        
        if action == "chat":
            ia_response_msg = data
            # Enviar respuesta usando el helper
            send_reply(sender_phone, ia_response_msg)
            ia_msg_db = Message(conversation_id=convo.id, sender_type='system', content=ia_response_msg)
            db.session.add(ia_msg_db)
        
        convo.updated_at = datetime.utcnow()
        db.session.commit()
        return jsonify({"status": "new_convo_reply_sent"}), 200

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error fatal en el webhook de Baileys: {e}")
        logging.exception(e) 
        return jsonify({"error": "Error interno del servidor"}), 500
# --- FIN DE MODIFICACIÓN: Webhook ---


# --- APIS DE CHAT (PROTEGIDAS Y FILTRADAS) ---

@app.route('/api/chats', methods=['GET'])
@login_required
def get_chats():
    try:
        # Leer el estado deseado desde los query params, por defecto 'open'
        chat_status = request.args.get('status', 'open') 
        if chat_status not in ['open', 'closed']:
            chat_status = 'open'

        conversations_query = None
        if current_user.role == 'Admin':
            # Admin ve todos los chats del estado solicitado
            conversations_query = Conversation.query.filter_by(status=chat_status).options(
                db.joinedload(Conversation.messages),
                db.joinedload(Conversation.bot_role)
            )
        else:
            # Soporte ve solo chats del estado solicitado de sus roles asignados
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
                return jsonify([]) # Devolver lista vacía

        # Asegurarse de que la query no sea None antes de continuar
        if conversations_query is None:
             return jsonify([])

        open_conversations = conversations_query.order_by(Conversation.updated_at.desc()).all()
        
        chat_list = []
        for convo in open_conversations:
            last_msg = convo.get_last_message()
            
            # --- INICIO DE CORRECCIÓN ---
            # Limpiamos el JID (ej: "12345@lid" o "whatsapp:+12345") para la UI
            clean_phone = convo.user_phone.split('@')[0] # Obtiene la parte antes del '@'
            clean_phone = clean_phone.replace('whatsapp:', '').replace('+', '') # Limpieza extra por si acaso
            # --- FIN DE CORRECCIÓN ---
            
            chat_list.append({
                "id": convo.id,
                "name": clean_phone, # <-- Usar el número limpio
                "phone": clean_phone, # <-- Usar el número limpio
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
        logging.exception(e) # Imprime el stack trace para más detalles
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
        
        send_url = f"{bailele_bot_url}/send"
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
# Las rutas /api/imported_chats, /api/conversations/<id> (DELETE) y /api/admin/upload_chats
# han sido reemplazadas por las nuevas APIs de Base de Datos
# --- FIN DE MODIFICACIÓN ---


# --- INICIO DE NUEVAS APIS: Base de Datos de Pólizas ---

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
        
        # Asumimos que los encabezados están en la fila 1 (índice 0)
        # y los datos comienzan en la fila 2 (índice 1)
        try:
            df = pd.read_excel(file, header=0, dtype=str).fillna('')
        except Exception as e:
            logging.error(f"Error al leer el Excel: {e}")
            return jsonify({"error": f"Error al procesar el archivo Excel: {e}"}), 400
            
        # Nombres de columna esperados (los encabezados en A1, B1, C1...)
        expected_columns = [
            'ASEGURADORA', 'NOMBRES', 'CEDULA/NIT', 'TIPO', 'PLACA', 
            'MODELO', 'VLOR POLIZA', 'MES VENCIMIENTO', 'FECHA VENC', 'REFERENCIA'
        ]
        
        if not all(col in df.columns for col in expected_columns):
            logging.warning(f"Columnas faltantes. Esperadas: {expected_columns}. Encontradas: {list(df.columns)}")
            return jsonify({"error": f"El archivo Excel debe tener las columnas exactas: {', '.join(expected_columns)}"}), 400
            
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