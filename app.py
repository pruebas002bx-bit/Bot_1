import os
import logging
import re
from flask import Flask, render_template, request, jsonify, redirect, url_for
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
    # --- INICIO CORRECCIÓN: Nueva columna ---
    chats_resolved = db.Column(db.Integer, default=0)
    # --- FIN CORRECCIÓN ---
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
    status = db.Column(db.String(20), default='open', nullable=False, index=True) # 'open', 'closed'
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    updated_at = db.Column(db.DateTime(timezone=True), onupdate=func.now())
    unread_count = db.Column(db.Integer, default=0)
    bot_role_id = db.Column(db.Integer, db.ForeignKey('bot_roles.id'), nullable=False)
    bot_role = db.relationship('BotRole', back_populates='conversations')
    messages = db.relationship('Message', back_populates='conversation', cascade="all, delete-orphan", order_by='Message.timestamp')
    # --- INICIO CORRECCIÓN: Nuevo campo para saber si ya descontó pendiente ---
    pending_counted = db.Column(db.Boolean, default=True) # True para nuevos chats, False si ya se descontó
    # --- FIN CORRECCIÓN ---

    def get_last_message(self):
        if self.messages:
            return self.messages[-1]
        return None

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversations.id'), nullable=False)
    sender_type = db.Column(db.String(20), nullable=False) # 'user' o 'agent'
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
    if current_user.role != 'Admin':
        return redirect(url_for('menu_soporte'))
    return render_template('Menu.html')

@app.route('/menu_soporte')
@login_required
def menu_soporte():
    if current_user.role != 'Soporte':
        return redirect(url_for('menu_admin'))
    return render_template('Menu_Soporte.html')

@app.route('/page/<path:page_name>')
@login_required
def show_page(page_name):
    if not page_name.endswith('.html'):
        return "Not Found", 404
    
    admin_pages = ['Bot.html', 'Usuarios.html', 'Configuracion.html', 'Dashboard.html']
    if current_user.role == 'Soporte' and page_name in admin_pages:
        return redirect(url_for('menu_soporte'))
    
    return render_template(page_name, current_user=current_user)

# --- API DE LOGIN Y LOGOUT ---
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()
    
    if user and user.password == password:
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
    if current_user.role != 'Admin':
        return jsonify({"error": "No autorizado"}), 403
    return None

@app.route('/api/users', methods=['GET'])
@login_required
def get_users():
    if current_user.role != 'Admin':
        return jsonify({"error": "No autorizado"}), 403
    users = User.query.all()
    return jsonify([{'id': user.id, 'name': user.name, 'role': user.role, 'username': user.username} for user in users])

@app.route('/api/users', methods=['POST'])
@login_required
def add_user():
    admin_check = check_admin()
    if admin_check: return admin_check
    data = request.get_json()
    username = data.get('username')
    if not username:
        base_username = data.get('name', 'usuario').split(' ')[0].lower().strip()
        username = base_username
        counter = 1
        while User.query.filter_by(username=username).first():
            username = f"{base_username}{counter}"
            counter += 1
    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'El nombre de usuario ya existe'}), 409
    new_user = User(username=username, name=data['name'], password=data['password'], role=data['role'])
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

# --- INICIO CORRECCIÓN: API de Roles ---
@app.route('/api/bot_roles', methods=['GET'])
@login_required
def get_bot_roles():
    admin_check = check_admin()
    if admin_check: return admin_check
    
    roles = BotRole.query.options(db.joinedload(BotRole.assignee)).all()
    # Incluir 'chats_resolved' en la respuesta
    return jsonify([{'id': role.id, 'title': role.title, 'knowledge_base': role.knowledge_base,
                     'assignee_name': role.assignee.name if role.assignee else 'Sin Asignar',
                     'assignee_id': role.assignee_id, 'status': role.status,
                     'chats_received': role.chats_received or 0, # Asegurar 0 si es None
                     'chats_pending': role.chats_pending or 0,
                     'chats_resolved': role.chats_resolved or 0 } # Añadido
                    for role in roles])
# --- FIN CORRECCIÓN ---

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
    # Incluir 'chats_resolved' en la respuesta
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

def get_ai_classification(message_body):
    logging.info("Iniciando clasificación con IA...")
    if not genai:
        logging.error("Módulo de IA (Gemini) no está configurado.")
        return "General"
    try:
        all_roles = BotRole.query.filter_by(status='Activo').all()
    except Exception as e:
        logging.error(f"Error al consultar roles en la BD: {e}")
        return "General"
    if not all_roles:
        logging.error("No hay roles activos en la base de datos para clasificar.")
        return "General"
    prompt_roles = ""
    for role in all_roles:
        prompt_roles += f"- Título: {role.title}\n  Descripción: {role.knowledge_base}\n"
    prompt_roles += "- Título: General\n  Descripción: Para saludos iniciales (hola, buenos días), despedidas o cualquier consulta que no encaje claramente en las otras categorías.\n"
    system_prompt = f"""
    Eres un enrutador de soporte al cliente. Tu tarea es clasificar el mensaje de un usuario en una de las siguientes categorías.
    Lee la descripción de cada rol y la base de conocimiento para tomar tu decisión.
    Responde *únicamente* con el Título exacto de la categoría que mejor coincida.
    Categorías Disponibles:
    {prompt_roles}
    Mensaje del Usuario:
    "{message_body}"
    Categoría:
    """
    try:
        model = genai.GenerativeModel('gemini-2.5-flash')
        response = model.generate_content(system_prompt)
        classified_role = response.text.strip().replace("*", "")
        role_titles = [role.title for role in all_roles] + ["General"]
        if classified_role in role_titles:
            logging.info(f"IA clasificó el mensaje como: '{classified_role}'")
            return classified_role
        else:
            logging.warning(f"IA devolvió un rol no válido: '{classified_role}'. Usando 'General'.")
            return "General"
    except Exception as e:
        logging.error(f"Error en la llamada a la API de Gemini: {e}")
        return "General"

@app.route('/api/whatsapp/webhook', methods=['POST'])
def whatsapp_webhook():
    message_body = request.form.get('Body')
    sender_phone = request.form.get('From')
    if not message_body or not sender_phone:
        logging.warning("Webhook recibido sin 'Body' o 'From'.")
        return ('', 400)
    logging.info(f"Mensaje recibido de {sender_phone}: {message_body}")

    try:
        existing_convo = Conversation.query.filter_by(user_phone=sender_phone, status='open').first()
        if existing_convo:
            logging.info(f"Conversación abierta (ID: {existing_convo.id}) encontrada para {sender_phone}. Omitiendo IA.")
            new_message = Message(conversation_id=existing_convo.id, sender_type='user', content=message_body)
            db.session.add(new_message)
            existing_convo.unread_count = (existing_convo.unread_count or 0) + 1
            existing_convo.updated_at = datetime.utcnow()
            role = existing_convo.bot_role
            # --- INICIO CORRECCIÓN: Incrementar pendiente solo si no lo estaba ya ---
            if role and not existing_convo.pending_counted:
                role.chats_pending = (role.chats_pending or 0) + 1
                existing_convo.pending_counted = True # Marcar que ya se contó como pendiente
            # --- FIN CORRECCIÓN ---
            db.session.commit()
            return ('', 200)
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al buscar/guardar en conversación existente: {e}")
        return ('Error interno del servidor', 500)

    logging.info(f"No hay conversación abierta para {sender_phone}. Pasando a IA.")
    bot_config = BotConfig.query.first()
    if not bot_config or not bot_config.is_active:
        logging.info("Bot inactivo. Ignorando mensaje.")
        return ('', 200)

    role_title = get_ai_classification(message_body)
    if role_title == 'General':
        logging.info("Intención 'General' detectada. Enviando saludo.")
        welcome_message = bot_config.welcome_message or "¡Hola! ¿En qué puedo ayudarte hoy?"
        response_twiml = create_twilio_response(welcome_message)
        return response_twiml, 200, {'Content-Type': 'application/xml'}

    target_role = BotRole.query.filter_by(title=role_title).first()
    if not target_role:
        logging.warning(f"IA devolvió '{role_title}' pero no se encontró en BD. Asignando a 'General'.")
        target_role = BotRole.query.filter_by(title='General').first()
        if not target_role:
             logging.error("CRÍTICO: No se encontró el rol específico ni un rol 'General'.")
             return ('Error interno del servidor', 500)

    try:
        # --- INICIO CORRECCIÓN: Asegurar pending_counted=True al crear ---
        convo = Conversation(user_phone=sender_phone, bot_role_id=target_role.id, status='open', pending_counted=True)
        # --- FIN CORRECCIÓN ---
        db.session.add(convo)
        db.session.flush()
        new_message = Message(conversation_id=convo.id, sender_type='user', content=message_body)
        db.session.add(new_message)
        target_role.chats_received = (target_role.chats_received or 0) + 1
        target_role.chats_pending = (target_role.chats_pending or 0) + 1
        convo.unread_count = 1
        convo.updated_at = datetime.utcnow()
        db.session.commit()
        logging.info(f"NUEVA conversación creada (ID: {convo.id}) y asignada a '{target_role.title}'.")
        transfer_message = f"¡Entendido! Un agente del área de {target_role.title} te atenderá pronto."
        response_twiml = create_twilio_response(transfer_message)
        return response_twiml, 200, {'Content-Type': 'application/xml'}
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al crear nueva conversación y guardar mensaje: {e}")
        return ('Error interno del servidor', 500)

# --- APIS DE CHAT (PROTEGIDAS Y FILTRADAS) ---
@app.route('/api/chats', methods=['GET'])
@login_required
def get_chats():
    try:
        open_conversations = []
        if current_user.role == 'Admin':
            open_conversations = Conversation.query.filter_by(status='open').order_by(Conversation.updated_at.desc()).all()
        else:
            assigned_role_ids = [role.id for role in current_user.assigned_roles]
            if assigned_role_ids:
                open_conversations = Conversation.query.filter(
                    Conversation.bot_role_id.in_(assigned_role_ids),
                    Conversation.status == 'open'
                ).order_by(Conversation.updated_at.desc()).all()
            else:
                logging.info(f"Usuario {current_user.username} (Soporte) no tiene roles asignados.")
        chat_list = []
        for convo in open_conversations:
            last_msg = convo.get_last_message()
            chat_list.append({
                "id": convo.id, "name": convo.user_phone.replace('whatsapp:', ''),
                "phone": convo.user_phone.replace('whatsapp:', ''),
                "time": last_msg.timestamp.strftime("%I:%M %p") if last_msg and last_msg.timestamp else 'N/A',
                "unread": convo.unread_count, "last_message": last_msg.content if last_msg else "Sin mensajes"
            })
        return jsonify(chat_list)
    except Exception as e:
        logging.error(f"Error en /api/chats: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/chats/<int:convo_id>/messages', methods=['GET'])
@login_required
def get_chat_messages(convo_id):
    convo = Conversation.query.get_or_404(convo_id)
    if current_user.role != 'Admin':
        assigned_role_ids = [role.id for role in current_user.assigned_roles]
        if convo.bot_role_id not in assigned_role_ids:
            return jsonify({"error": "No autorizado para ver este chat"}), 403
            
    # --- INICIO CORRECCIÓN: Lógica mejorada de pendientes ---
    # Solo descontar pendiente si tenía mensajes sin leer Y si estaba contado como pendiente
    if convo.unread_count > 0 and convo.pending_counted:
        role = convo.bot_role
        if role and role.chats_pending > 0:
            role.chats_pending = role.chats_pending - 1
            convo.pending_counted = False # Marcar que ya se descontó
    # --- FIN CORRECCIÓN ---
    
    convo.unread_count = 0
    db.session.commit()
    
    messages = [{"sender": msg.sender_type, "text": msg.content} for msg in convo.messages]
    return jsonify(messages)

@app.route('/api/chats/<int:convo_id>/messages', methods=['POST'])
@login_required
def send_chat_message(convo_id):
    convo = Conversation.query.get_or_404(convo_id)
    if current_user.role != 'Admin':
        assigned_role_ids = [role.id for role in current_user.assigned_roles]
        if convo.bot_role_id not in assigned_role_ids:
            return jsonify({"error": "No autorizado para enviar a este chat"}), 403
    data = request.get_json()
    content = data.get('text')
    if not content:
        return jsonify({"error": "El texto no puede estar vacío"}), 400
    if not twilio_client or not TWILIO_WHATSAPP_NUMBER:
        logging.error("Twilio no está configurado para enviar mensajes.")
        return jsonify({"error": "El servicio de envío no está configurado"}), 500
    try:
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

# --- INICIO CORRECCIÓN: API para resolver chat ---
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
            # Incrementar resueltos
            role.chats_resolved = (role.chats_resolved or 0) + 1
            # Decrementar pendientes SOLO si no se descontó ya al leerlo
            if convo.pending_counted and role.chats_pending > 0:
                role.chats_pending = role.chats_pending - 1
                convo.pending_counted = False # Asegurar que no se descuente de nuevo

        db.session.commit()
        logging.info(f"Chat ID {convo_id} marcado como resuelto. Rol '{role.title}' - Pendientes: {role.chats_pending}, Resueltos: {role.chats_resolved}")
        return jsonify({"success": True, "message": "Chat archivado."})
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al resolver chat {convo_id}: {e}")
        return jsonify({"error": str(e)}), 500
# --- FIN CORRECCIÓN ---

# --- API DE DASHBOARD (PROTEGIDA Y FILTRADA) ---
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
        # --- INICIO CORRECCIÓN: Usar la nueva columna ---
        # stats_chats_resueltos = Conversation.query.filter_by(status='closed').count() # Forma antigua
        stats_chats_resueltos = db.session.query(func.sum(BotRole.chats_resolved)).scalar() or 0 # Suma de todos los roles
        # --- FIN CORRECCIÓN ---
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
            logging.info("Tablas de la base de datos verificadas/creadas (con chats_resolved).")
            # Crear datos por defecto (usuarios, config, roles) si no existen...
            # (Omitido por brevedad, es el mismo código de antes)
            if not User.query.filter_by(role='Admin').first():
                logging.info("Creando usuario 'admin' por defecto.")
                db.session.add(User(username='admin', password='admin', name='Administrador', role='Admin'))
            if not User.query.filter_by(role='Soporte').first():
                logging.info("Creando usuario 'soporte' por defecto.")
                db.session.add(User(username='soporte', password='soporte', name='Agente de Soporte', role='Soporte'))
            if not BotConfig.query.first():
                logging.info("Creando configuración de bot por defecto.")
                db.session.add(BotConfig(is_active=True, whatsapp_number="+573132217862", welcome_message="¡Hola! Bienvenido a nuestro servicio de atención. ¿En qué puedo ayudarte hoy?"))
            roles_default = {
                "Area Cotizaciones": "Es el cotizador de negocios que permite a cualquier usuario obtener un precio de seguro al instante.",
                "Renovaciones": "De manera proactiva, este módulo se encarga de mantener a los clientes. Notifica sobre el próximo vencimiento de su póliza.",
                "Agente de ventas/Comercial #1": "Este módulo actúa como el primer contacto para atraer nuevos clientes. Identifica las necesidades del usuario.",
                "Agente de ventas/Comercial #2": "Módulo de primer contacto para nuevos clientes, similar al #1 pero con otro agente.",
                "Agente de ventas/Comercial #3": "Módulo de primer contacto para nuevos clientes, similar al #1 pero con otro agente.",
                "Siniestros, Consultas Póliza, Cancelaciones": "Diseñado para asistir al cliente en momentos difíciles, reportar incidentes, consultar estado de su caso y gestionar cancelaciones.",
                "Ventas": "Consultas sobre compra de seguros, cotizaciones, precios, planes de vehículos (carros, motos) y procesos de adquisición.",
                "Soporte Técnico": "Problemas con la plataforma, la app no funciona, errores de sistema, facturación, problemas de conexión y ayuda general.",
                "General": "Preguntas frecuentes generales, saludos, despedidas o consultas que no encajan en otras áreas."
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