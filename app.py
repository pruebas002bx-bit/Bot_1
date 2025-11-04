import os
import logging
import re  # <--- CORRECCIÓN: Añadido
import json  # <--- CORRECCIÓN: Añadido
from flask import Flask, render_template, request, jsonify, redirect, url_for
from werkzeug.utils import secure_filename # <-- AÑADIDO PARA UPLOAD
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from twilio.twiml.messaging_response import MessagingResponse
from twilio.rest import Client
from datetime import datetime, timedelta
from sqlalchemy import func

# --- IMPORTACIONES DE SESIONES ---
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

# --- CONFIGURACIÓN ---
logging.basicConfig(level=logging.INFO)
load_dotenv()

# --- CONFIGURACIÓN DE TWILIO ---
TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID')
TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
TWILIO_WHATSAPP_NUMBER = os.getenv('TWILIO_WHATSAPP_NUMBER')
try:
    twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
    logging.info("Cliente de Twilio inicializado.")
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
    # --- CORRECCIÓN: El estado 'ia_greeting' se maneja aquí ---
    status = db.Column(db.String(20), default='ia_greeting', nullable=False, index=True) # 'ia_greeting', 'open', 'closed'
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    updated_at = db.Column(db.DateTime(timezone=True), onupdate=func.now())
    unread_count = db.Column(db.Integer, default=0)
    bot_role_id = db.Column(db.Integer, db.ForeignKey('bot_roles.id'), nullable=False)
    bot_role = db.relationship('BotRole', back_populates='conversations')
    messages = db.relationship('Message', back_populates='conversation', cascade="all, delete-orphan", order_by='Message.timestamp')
    
    # --- INICIO DE MODIFICACIÓN ---
    # Campo para rastrear chats importados
    import_source = db.Column(db.String(100), nullable=True, default=None)
    # --- FIN DE MODIFICACIÓN ---
    
    pending_counted = db.Column(db.Boolean, default=False) # Flag para saber si ya incrementó/decrementó pending

    def get_last_message(self):
        if self.messages:
            # Ordenar por timestamp descendente y tomar el primero si no está pre-ordenado
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
    if current_user.role == 'Soporte' and page_name in admin_pages: return redirect(url_for('menu_soporte'))
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
    # Generar username automáticamente si no se provee
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

# --- LÓGICA DEL WEBHOOK (PÚBLICO) ---
def create_twilio_response(message_text):
    response = MessagingResponse()
    response.message(message_text)
    return str(response)

# --- INICIO CORRECCIÓN: Nueva función de IA Conversacional ---
def get_ia_response_and_route(messages_list):
    """
    Gestiona la conversación con Gemini.
    Decide si chatear más o enrutar.
    """
    logging.info("Iniciando IA conversacional (get_ia_response_and_route)...")
    if not genai:
        logging.error("Módulo de IA (Gemini) no está configurado.")
        # Fallback: enrutar directamente a 'General' si la IA falla
        return ("route", "General") 

    try:
        # Obtener roles (excluyendo 'General' ya que es el enrutador)
        all_roles = BotRole.query.filter(BotRole.status == 'Activo', BotRole.title != 'General').all()
        if not all_roles:
            logging.error("No hay roles (aparte de 'General') activos en la BD para enrutar.")
            return ("chat", "¡Hola! Soy Montenegro, tu asistente virtual de Seguros Montenegro. Actualmente todos nuestros departamentos están ocupados, pero déjame tu consulta y te atenderemos lo antes posible.")

        prompt_roles = ""
        for role in all_roles:
            prompt_roles += f"- Título: {role.title}\n  Descripción: {role.knowledge_base}\n"

        system_prompt = f"""
        Eres 'Montenegro', un asistente virtual experto de Seguros Montenegro.
        Tu objetivo es entender la necesidad del cliente y, *solo cuando estés seguro de su intención*, clasificarla en uno de los roles disponibles.
        Si no estás seguro, *debes* hacer preguntas de aclaración.

        Roles Disponibles para enrutar:
        {prompt_roles}

        Reglas de Conversación:
        1.  Para el primer mensaje del usuario: Preséntate *siempre* como "¡Hola! Soy Montenegro, tu asistente virtual de Seguros Montenegro." y luego añade tu pregunta o respuesta.
        2.  Ejemplo de primer mensaje (Usuario: "info"): "¡Hola! Soy Montenegro, tu asistente virtual de Seguros Montenegro. ¿En qué puedo ayudarte hoy?"
        3.  Ejemplo de primer mensaje (Usuario: "quiero comprar"): "¡Hola! Soy Montenegro, tu asistente virtual de Seguros Montenegro. ¡Claro! ¿Te refieres a comprar un seguro nuevo o a gestionar una renovación?"
        4.  Si la intención del usuario es ambigua (ej: 'quiero comprar'), ofrece opciones (ej: 'Claro, ¿te refieres a un seguro nuevo o a una renovación?').
        5.  Antes de enrutar, *siempre* confirma la intención (ej: El usuario dice 'renovación'. Tú respondes: 'Entendido, ¿puedes confirmarme que deseas gestionar una renovación?').
        6.  Si el cliente confirma ('sí', 'correcto', 'eso es'), responde *únicamente* con el JSON:
            {{"action": "route", "role_title": "[Título del Rol]"}}
        7.  Si el cliente niega la confirmación ('no', 'no es eso'), pide más detalles (ej: 'Entendido. ¿Podrías describirme mejor lo que necesitas?').
        8.  Para cualquier otra respuesta (saludos, aclaraciones, negaciones), responde *únicamente* con el JSON:
            {{"action": "chat", "response_message": "[Tu respuesta o pregunta]"}}

        Historial de Conversación (último mensaje es del usuario):
        """

        # Formatear el historial para el prompt
        chat_history_for_prompt = []
        for msg in messages_list:
            if msg.sender_type == 'user':
                # Usar 'Usuario' para el prompt
                chat_history_for_prompt.append(f"Usuario: {msg.content}")
            elif msg.sender_type == 'system':
                # Usar 'Montenegro' para los mensajes del bot en el prompt
                chat_history_for_prompt.append(f"Montenegro: {msg.content}")
        
        final_prompt = system_prompt + "\n".join(chat_history_for_prompt)

        logging.info(f"Enviando prompt a Gemini 2.5-flash...")
        model = genai.GenerativeModel('gemini-2.5-flash') # Usando el modelo solicitado
        response = model.generate_content(final_prompt)
        
        response_text = response.text.strip()
        logging.info(f"Respuesta de Gemini: {response_text}")

        # Intentar parsear JSON
        try:
            # Limpiar si Gemini añade '```json\n...\n```'
            if response_text.startswith("```json"):
                response_text = re.sub(r"```json\n(.*?)\n```", r"\1", response_text, flags=re.DOTALL)
            
            data = json.loads(response_text)
            action = data.get("action")
            
            if action == "route":
                role_title = data.get("role_title")
                role_titles = [role.title for role in all_roles]
                if role_title in role_titles:
                    logging.info(f"IA decidió ENRUTAR a: '{role_title}'")
                    return ("route", role_title)
                else:
                    logging.warning(f"IA intentó enrutar a rol inválido: '{role_title}'. Pidiendo aclaración.")
                    return ("chat", "Entendido, pero no estoy seguro de a qué departamento transferirte. ¿Podrías ser más específico?")

            elif action == "chat":
                message = data.get("response_message")
                logging.info(f"IA decidió CHATEAR: '{message}'")
                return ("chat", message)
            
            else:
                raise ValueError("JSON de IA no tiene 'action' válido.")

        except (json.JSONDecodeError, ValueError, TypeError) as e:
            logging.warning(f"Respuesta de Gemini no fue JSON válido ({e}). Tratando como chat: {response_text}")
            clean_response = response_text.replace("*", "").strip()
            if not clean_response:
                clean_response = "No estoy seguro de cómo responder a eso. ¿Puedes reformularlo?"
            return ("chat", clean_response)

    except Exception as e:
        logging.error(f"Error en la llamada a la API de Gemini: {e}")
        return ("chat", "Estoy teniendo problemas técnicos. Por favor, espera un momento.")
# --- FIN CORRECCIÓN: Nueva función de IA ---


# --- INICIO CORRECCIÓN: Webhook reescrito para IA conversacional ---
@app.route('/api/whatsapp/webhook', methods=['POST'])
def whatsapp_webhook():
    message_body = request.form.get('Body')
    sender_phone = request.form.get('From')
    if not message_body or not sender_phone:
        logging.warning("Webhook recibido sin 'Body' o 'From'.")
        return ('', 400)
    logging.info(f"Mensaje recibido de {sender_phone}: {message_body}")

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
            return ('', 200) # Twilio recibe 200 OK, no envía respuesta

        bot_config = BotConfig.query.first()
        if not bot_config or not bot_config.is_active:
            logging.info("Bot inactivo. Ignorando mensaje.")
            return ('', 200)

        # Escenario B: Chat en fase de saludo/IA ('ia_greeting')
        if existing_convo and existing_convo.status == 'ia_greeting':
            logging.info(f"Continuando chat IA (ID: {existing_convo.id}) para {sender_phone}.")
            convo = existing_convo
            # Añadir mensaje del usuario a la BD
            user_msg = Message(conversation_id=convo.id, sender_type='user', content=message_body)
            db.session.add(user_msg)
            
            # Obtener historial para la IA (incluyendo el nuevo mensaje)
            # Recargamos convo.messages para incluir el que acabamos de añadir
            messages_history = Message.query.filter_by(conversation_id=convo.id).order_by(Message.timestamp).all()
            
            # Llamar a la IA
            action, data = get_ia_response_and_route(messages_history)
            
            if action == "route":
                role_title = data
                target_role = BotRole.query.filter_by(title=role_title, status='Activo').first()
                
                if not target_role:
                    logging.error(f"IA enrutó a '{role_title}' pero no se encontró o está inactivo.")
                    ia_response_msg = f"Ups, el departamento de '{role_title}' no está disponible en este momento. ¿Puedo ayudarte con algo más?"
                    response_twiml = create_twilio_response(ia_response_msg)
                    ia_msg_db = Message(conversation_id=convo.id, sender_type='system', content=ia_response_msg)
                    db.session.add(ia_msg_db)
                    db.session.commit()
                    return str(response_twiml), 200, {'Content-Type': 'application/xml'}
                
                # --- Enrutamiento Exitoso ---
                logging.info(f"IA enrutó chat {convo.id} a '{target_role.title}'. Cambiando status a 'open'.")
                convo.status = 'open'
                convo.bot_role_id = target_role.id
                convo.pending_counted = True
                convo.updated_at = datetime.utcnow()
                
                target_role.chats_received = (target_role.chats_received or 0) + 1
                target_role.chats_pending = (target_role.chats_pending or 0) + 1

                transfer_message = f"¡Entendido! Un agente del área de {target_role.title} te atenderá pronto."
                response_twiml = create_twilio_response(transfer_message)
                
                # Mensaje de sistema (para el agente)
                system_msg_db = Message(conversation_id=convo.id, sender_type='system', content=f"Chat enrutado por IA a {target_role.title}.")
                # Mensaje de IA (para el usuario, guardado como 'system' para el historial del agente)
                ia_msg_db = Message(conversation_id=convo.id, sender_type='system', content=transfer_message)
                db.session.add_all([system_msg_db, ia_msg_db])
                db.session.commit()
                
                return str(response_twiml), 200, {'Content-Type': 'application/xml'}

            elif action == "chat":
                # --- IA Sigue Chateando ---
                ia_response_msg = data
                response_twiml = create_twilio_response(ia_response_msg)
                ia_msg_db = Message(conversation_id=convo.id, sender_type='system', content=ia_response_msg) # Guardado como 'system'
                db.session.add(ia_msg_db)
                convo.updated_at = datetime.utcnow()
                db.session.commit()
                return str(response_twiml), 200, {'Content-Type': 'application/xml'}
        
        # Escenario C: Conversación nueva (o 'closed')
        logging.info(f"No hay conversación activa para {sender_phone}. Creando nueva conversación IA.")
        
        general_role = BotRole.query.filter_by(title='General').first()
        if not general_role:
             logging.error("CRÍTICO: No se encontró el rol 'General' para iniciar chats IA.")
             return ('Error interno del servidor', 500)

        convo = Conversation(user_phone=sender_phone, bot_role_id=general_role.id, status='ia_greeting')
        db.session.add(convo)
        db.session.flush() # Para obtener el convo.id

        user_msg = Message(conversation_id=convo.id, sender_type='user', content=message_body)
        db.session.add(user_msg)
        
        # Llamar a la IA solo con el primer mensaje
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
                response_twiml = create_twilio_response(transfer_message)
                
                system_msg_db = Message(conversation_id=convo.id, sender_type='system', content=f"Chat enrutado por IA a {target_role.title}.")
                ia_msg_db = Message(conversation_id=convo.id, sender_type='system', content=transfer_message)
                db.session.add_all([system_msg_db, ia_msg_db])
            else:
                # Fallback si el rol no existe
                action = "chat"
                data = "¡Hola! Soy Montenegro, tu asistente virtual de Seguros Montenegro. ¿En qué puedo ayudarte hoy?"
        
        if action == "chat":
            ia_response_msg = data
            response_twiml = create_twilio_response(ia_response_msg)
            ia_msg_db = Message(conversation_id=convo.id, sender_type='system', content=ia_response_msg)
            db.session.add(ia_msg_db)
        
        convo.updated_at = datetime.utcnow()
        db.session.commit()
        return str(response_twiml), 200, {'Content-Type': 'application/xml'}

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error fatal en el webhook de WhatsApp: {e}")
        logging.exception(e) # Imprime el stack trace
        return ('Error interno del servidor', 500)
# --- FIN CORRECCIÓN: Webhook ---


# --- APIS DE CHAT (PROTEGIDAS Y FILTRADAS) ---

# --- INICIO DE MODIFICACIÓN: get_chats() ---
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
            chat_list.append({
                "id": convo.id,
                "name": convo.user_phone.replace('whatsapp:', ''),
                "phone": convo.user_phone.replace('whatsapp:', ''),
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
        return jsonify({"error": str(e)}), 500
# --- FIN DE MODIFICACIÓN: get_chats() ---

@app.route('/api/chats/<int:convo_id>/messages', methods=['GET'])
@login_required
def get_chat_messages(convo_id):
    convo = Conversation.query.get_or_404(convo_id)
    if current_user.role != 'Admin':
        assigned_role_ids = [role.id for role in current_user.assigned_roles]
        if convo.bot_role_id not in assigned_role_ids:
            # CORRECCIÓN: Permitir ver si el chat *estuvo* en su rol (transferido)
            # Modificación: Esta lógica se aplica a CUALQUIER estado (open o closed)
            # if convo.status == 'open': # Restricción eliminada
            return jsonify({"error": "No autorizado para ver este chat"}), 403
            
    # Marcar como leído (solo si está 'open' y tiene no leídos)
    if convo.status == 'open' and convo.unread_count > 0:
        convo.unread_count = 0
    
    # Decrementar 'pendientes' si se abre por primera vez (solo si está 'open')
    if convo.status == 'open' and convo.pending_counted:
        role = convo.bot_role
        if role and role.chats_pending > 0:
            role.chats_pending = role.chats_pending - 1
        convo.pending_counted = False
        
    db.session.commit()
    
    messages = [{"sender": msg.sender_type, "text": msg.content} for msg in convo.messages]
    return jsonify(messages)

# --- INICIO DE MODIFICACIÓN: send_chat_message() ---
@app.route('/api/chats/<int:convo_id>/messages', methods=['POST'])
@login_required
def send_chat_message(convo_id):
    convo = Conversation.query.get_or_404(convo_id)
    
    # Lógica de permisos (se aplica a 'open' y 'closed')
    if current_user.role != 'Admin':
        assigned_role_ids = [role.id for role in current_user.assigned_roles]
        if convo.bot_role_id not in assigned_role_ids:
            return jsonify({"error": "No autorizado para enviar a este chat"}), 403
            
    data = request.get_json()
    content = data.get('text')
    if not content: return jsonify({"error": "El texto no puede estar vacío"}), 400
    if not twilio_client or not TWILIO_WHATSAPP_NUMBER:
        logging.error("Twilio no está configurado para enviar mensajes.")
        return jsonify({"error": "El servicio de envío no está configurado"}), 500
    try:
        # Reactivar chat si está cerrado
        if convo.status == 'closed':
            logging.info(f"Reactivando chat {convo_id} (estado 'closed') por {current_user.name}.")
            convo.status = 'open'
            convo.unread_count = 0 # El agente lo está abriendo, no el cliente
            convo.pending_counted = True # Marcar como pendiente para el rol
            
            role = convo.bot_role
            if role:
                # Revertir contadores
                if role.chats_resolved and role.chats_resolved > 0:
                    role.chats_resolved = role.chats_resolved - 1
                role.chats_pending = (role.chats_pending or 0) + 1
                logging.info(f"Contadores del Rol '{role.title}' actualizados: Pendientes={role.chats_pending}, Resueltos={role.chats_resolved}")

        twilio_client.messages.create(from_=TWILIO_WHATSAPP_NUMBER, body=content, to=convo.user_phone)
        
        new_message = Message(conversation_id=convo.id, sender_type='agent', content=content)
        db.session.add(new_message)
        convo.updated_at = datetime.utcnow()
        
        db.session.commit()
        return jsonify({"success": True, "message": {"sender": "agent", "text": content}}), 201
    except Exception as e:
        logging.error(f"Error al enviar mensaje de Twilio o guardar en BD: {e}")
        db.session.rollback()
        return jsonify({"error": str(e)}), 500
# --- FIN DE MODIFICACIÓN: send_chat_message() ---


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

        # Ajustar contadores
        if original_role:
            # Decrementar pendiente del rol original SOLO si estaba contado
            if convo.pending_counted and original_role.chats_pending > 0:
                original_role.chats_pending = original_role.chats_pending - 1
        
        # Incrementar pendiente del nuevo rol
        target_role.chats_pending = (target_role.chats_pending or 0) + 1
        
        # Actualizar la conversación
        convo.bot_role_id = target_role.id
        convo.pending_counted = True # Marcar como pendiente para el nuevo rol
        convo.updated_at = datetime.utcnow() # Actualizar timestamp
        
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

# --- INICIO DE NUEVA RUTA: /api/admin/upload_chats ---
@app.route('/api/admin/upload_chats', methods=['POST'])
@login_required
def upload_chats():
    admin_check = check_admin()
    if admin_check: return admin_check

    try:
        if 'file' not in request.files:
            return jsonify({"error": "No se encontró el archivo"}), 400
        
        file = request.files['file']
        user_phone = request.form.get('phone')
        agent_name = request.form.get('agentName')

        if not file or file.filename == '':
            return jsonify({"error": "No se seleccionó ningún archivo"}), 400
        if not user_phone or not user_phone.startswith('whatsapp:'):
            return jsonify({"error": "El número de teléfono debe estar en formato 'whatsapp:+XXXXXXXXXX'"}), 400
        if not agent_name:
            return jsonify({"error": "Debe especificar el 'Nombre del Agente' tal como aparece en el chat"}), 400

        # Buscar el rol "General" para asignarlo
        general_role = BotRole.query.filter_by(title='General').first()
        if not general_role:
             # Fallback: asignarlo al primer rol de bot que exista
             general_role = BotRole.query.first()
             if not general_role:
                 return jsonify({"error": "No se encontraron roles de bot para asignar el chat importado"}), 500

        # Crear o buscar la conversación
        convo = Conversation.query.filter_by(user_phone=user_phone).first()
        if not convo:
            convo = Conversation(
                user_phone=user_phone,
                status='closed', # Importar como cerrado por defecto
                bot_role_id=general_role.id,
                import_source='whatsapp_txt_upload'
            )
            db.session.add(convo)
        else:
            # Si ya existe, solo actualizamos los metadatos y borramos mensajes antiguos
            convo.status = 'closed'
            convo.import_source = 'whatsapp_txt_upload'
            # Borrar mensajes antiguos para evitar duplicados en la re-importación
            Message.query.filter_by(conversation_id=convo.id).delete()

        db.session.flush() # Para obtener el convo.id

        content = file.read().decode('utf-8')
        lines = content.splitlines()
        
        # Regex para parsear el formato: [DD/MM/YYYY, HH:MM:SS] Nombre: Mensaje
        # Esto no manejará mensajes multilínea.
        chat_regex = re.compile(r"\[(\d{1,2}/\d{1,2}/\d{4}), (\d{1,2}:\d{2}:\d{2})\] (.*?): (.*)")
        
        messages_added = 0
        last_message_time = None

        for line in lines:
            match = chat_regex.match(line)
            if match:
                date_str, time_str, author, message_content = match.groups()
                
                try:
                    # Asumimos formato DD/MM/YYYY
                    timestamp_str = f"{date_str} {time_str}"
                    timestamp = datetime.strptime(timestamp_str, '%d/%m/%Y %H:%M:%S')
                    last_message_time = timestamp
                except ValueError:
                    # Intentar formato MM/DD/YYYY
                    try:
                        timestamp_str = f"{date_str} {time_str}" # Re-asignar por si acaso
                        timestamp = datetime.strptime(timestamp_str, '%m/%d/%Y %H:%M:%S')
                        last_message_time = timestamp
                    except ValueError:
                        logging.warning(f"Formato de fecha no reconocido en línea: {line}")
                        continue # Saltar esta línea

                sender_type = 'system' # Default
                if author == agent_name:
                    sender_type = 'agent'
                else:
                    sender_type = 'user' # Asumir que todo lo demás es el cliente

                new_msg = Message(
                    conversation_id=convo.id,
                    sender_type=sender_type,
                    content=message_content,
                    timestamp=timestamp
                )
                db.session.add(new_msg)
                messages_added += 1

        # Actualizar el timestamp de la conversación al del último mensaje
        if last_message_time:
            convo.updated_at = last_message_time
        
        db.session.commit()
        
        return jsonify({"success": True, "message": f"Chat importado para {user_phone}. Se añadieron {messages_added} mensajes."})

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error fatal en /api/admin/upload_chats: {e}")
        logging.exception(e)
        return jsonify({"error": str(e)}), 500
# --- FIN DE NUEVA RUTA ---


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
            db.create_all()
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
            
            # Asegurar que el rol 'General' exista
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

# Llama a la inicialización aquí
init_db(app)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)