import os
from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import logging
import re # Para el análisis de intención (NLP)
from twilio.twiml.messaging_response import MessagingResponse # Para responder a Twilio

# Configuración de logging para ver los mensajes en OnRender
logging.basicConfig(level=logging.INFO)

load_dotenv()

app = Flask(__name__, template_folder='templates')

# --- CONFIGURACIÓN DE LA BASE DE DATOS ---
db_uri = os.getenv('DATABASE_URL')
if db_uri and db_uri.startswith("postgres://"):
    db_uri = db_uri.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'una-clave-secreta-por-defecto-muy-segura')

db = SQLAlchemy(app)

# --- MODELOS DE LA BASE DE DATOS ---
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(80), nullable=False)

class BotRole(db.Model):
    __tablename__ = 'bot_roles'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    knowledge_base = db.Column(db.Text, nullable=True)
    assignee_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    status = db.Column(db.String(20), default='Activo', nullable=False)
    chats_received = db.Column(db.Integer, default=0)
    chats_pending = db.Column(db.Integer, default=0)
    assignee = db.relationship('User', backref='assigned_roles')

class BotConfig(db.Model):
    __tablename__ = 'bot_config'
    id = db.Column(db.Integer, primary_key=True, default=1)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    whatsapp_number = db.Column(db.String(50), nullable=True)
    welcome_message = db.Column(db.Text, nullable=True)

# --- RUTAS BÁSICAS DE FLASK (PARA SERVIR PÁGINAS) ---
@app.route('/')
def index():
    return render_template('Index.html')

@app.route('/menu_admin')
def menu_admin():
    return render_template('Menu.html')

@app.route('/menu_soporte')
def menu_soporte():
    return render_template('Menu_Soporte.html')

@app.route('/page/<path:page_name>')
def show_page(page_name):
    if not page_name.endswith('.html'):
        return "Not Found", 404
    return render_template(page_name)

# --- API DE LOGIN ---
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()
    if user and user.password == password: # ¡En producción, usa hashing de contraseñas!
        redirect_url = url_for('menu_admin' if user.role == 'Admin' else 'menu_soporte')
        return jsonify({"success": True, "redirect_url": redirect_url})
    return jsonify({"success": False, "message": "Usuario o contraseña incorrectos"}), 401

# --- API DE USUARIOS (CRUD) ---
@app.route('/api/users', methods=['GET'])
def get_users():
    users = User.query.all()
    return jsonify([{'id': user.id, 'name': user.name, 'role': user.role, 'username': user.username} for user in users])

@app.route('/api/users', methods=['POST'])
def add_user():
    data = request.get_json()
    username = data.get('username')
    # Generar username si no se provee, y chequear colisiones
    if not username:
        base_username = data.get('name', 'usuario').split(' ')[0].lower().strip()
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
        password=data['password'], # ¡En producción, usa hashing!
        role=data['role']
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'id': new_user.id, 'name': new_user.name, 'role': new_user.role, 'username': new_user.username}), 201

@app.route('/api/users/<int:id>', methods=['PUT'])
def update_user(id):
    user = User.query.get_or_404(id)
    data = request.get_json()
    user.name = data.get('name', user.name)
    user.role = data.get('role', user.role)
    if 'password' in data and data['password']:
        user.password = data['password'] # ¡En producción, usa hashing!
    db.session.commit()
    return jsonify({'message': 'Usuario actualizado correctamente'})

@app.route('/api/users/<int:id>', methods=['DELETE'])
def delete_user(id):
    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'Usuario eliminado correctamente'})

# --- API DE ROLES DE BOT (CRUD) ---
@app.route('/api/bot_roles', methods=['GET'])
def get_bot_roles():
    roles = BotRole.query.options(db.joinedload(BotRole.assignee)).all()
    return jsonify([{'id': role.id, 'title': role.title, 'knowledge_base': role.knowledge_base, 'assignee_name': role.assignee.name if role.assignee else 'Sin Asignar', 'assignee_id': role.assignee_id, 'status': role.status, 'chats_received': role.chats_received, 'chats_pending': role.chats_pending} for role in roles])

@app.route('/api/bot_roles', methods=['POST'])
def add_bot_role():
    data = request.get_json()
    assignee_id = data.get('assignee_id')
    new_role = BotRole(
        title=data['title'],
        knowledge_base=data.get('knowledge_base', ''),
        assignee_id=int(assignee_id) if assignee_id else None,
        status=data.get('status', 'Activo')
    )
    db.session.add(new_role)
    db.session.commit()
    # Recargar para obtener el nombre del asignado
    role_data = BotRole.query.get(new_role.id)
    return jsonify({
        'id': role_data.id, 
        'title': role_data.title, 
        'knowledge_base': role_data.knowledge_base, 
        'assignee_name': role_data.assignee.name if role_data.assignee else 'Sin Asignar', 
        'assignee_id': role_data.assignee_id, 
        'status': role_data.status, 
        'chats_received': role_data.chats_received, 
        'chats_pending': role_data.chats_pending
    }), 201


@app.route('/api/bot_roles/<int:id>', methods=['PUT'])
def update_bot_role(id):
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
def delete_bot_role(id):
    role = BotRole.query.get_or_404(id)
    db.session.delete(role)
    db.session.commit()
    return jsonify({'message': 'Rol del bot eliminado correctamente'})

# --- API DE CONFIGURACIÓN DE BOT ---
@app.route('/api/bot_config', methods=['GET'])
def get_bot_config():
    config = BotConfig.query.first()
    if not config:
        # Si no existe configuración, crea una por defecto
        config = BotConfig(
            is_active=True,
            whatsapp_number="+573132217862",
            welcome_message="¡Hola! Bienvenido a nuestro servicio de atención. ¿En qué puedo ayudarte hoy?"
        )
        db.session.add(config)
        db.session.commit()
        logging.info("Creando configuración de bot por defecto.")
    return jsonify({'is_active': config.is_active, 'whatsapp_number': config.whatsapp_number, 'welcome_message': config.welcome_message})

@app.route('/api/bot_config', methods=['PUT'])
def update_bot_config():
    config = BotConfig.query.first_or_404()
    data = request.get_json()
    config.is_active = data.get('is_active', config.is_active)
    config.whatsapp_number = data.get('whatsapp_number', config.whatsapp_number)
    config.welcome_message = data.get('welcome_message', config.welcome_message)
    db.session.commit()
    return jsonify({'message': 'Configuración del bot actualizada correctamente'})

# --- LÓGICA DEL WEBHOOK DE WHATSAPP ---

def create_twilio_response(message_text):
    """
    Crea una respuesta en el formato TwiML que Twilio espera.
    """
    response = MessagingResponse()
    response.message(message_text)
    return str(response)

def get_intent_and_role(message_body):
    """
    Analiza el mensaje del usuario para detectar la intención y el rol objetivo.
    Esta es una implementación de NLP muy simple basada en palabras clave.
    """
    message_lower = message_body.lower().strip()
    
    # Palabras clave para Ventas
    sales_keywords = ['seguro', 'comprar', 'adquirir', 'cotizar', 'precio', 'costo', 'carro', 'moto', 'vehículo', 'compra', 'plan']
    
    # Palabras clave para Soporte
    support_keywords = ['ayuda', 'problema', 'no funciona', 'soporte', 'factura', 'error', 'queja']

    # Palabras clave de Saludo (para detectar el inicio)
    greeting_keywords = ['hola', 'buenos días', 'buenas tardes', 'buenas noches', 'info', 'inicio', 'empezar', 'menu']

    # 1. Chequear intenciones específicas primero
    if any(re.search(r'\b' + re.escape(keyword) + r'\b', message_lower) for keyword in sales_keywords):
        return 'Ventas' # Este debe ser el 'title' exacto de tu BotRole en la BD

    if any(re.search(r'\b' + re.escape(keyword) + r'\b', message_lower) for keyword in support_keywords):
        return 'Soporte Técnico' # Asumiendo que tienes un rol con este título

    # 2. Si no es específica, chequear si es un saludo
    if any(re.search(r'\b' + re.escape(keyword) + r'\b', message_lower) for keyword in greeting_keywords):
        return 'General' # Intención para disparar el saludo

    # 3. Si no es nada de lo anterior, también es 'General'
    return 'General'

@app.route('/api/whatsapp/webhook', methods=['POST'])
def whatsapp_webhook():
    """
    Webhook para recibir mensajes de un proveedor de WhatsApp API (ej. Twilio).
    """
    
    # El formato de Twilio usa 'Body' y 'From' en un formulario
    message_body = request.form.get('Body')
    sender_phone = request.form.get('From')
    
    if not message_body or not sender_phone:
        logging.warning("Webhook recibido sin 'Body' o 'From'.")
        # Asumir formato JSON (como Meta) si el de formulario falla
        try:
            data = request.get_json()
            if data and data.get('entry', [])[0].get('changes', [])[0].get('value', {}).get('messages', []):
                message_data = data['entry'][0]['changes'][0]['value']['messages'][0]
                message_body = message_data['text']['body']
                sender_phone = message_data['from']
        except Exception:
             logging.warning("Payload no es ni formulario Twilio ni JSON Meta reconocible.")
             return ('', 400) # Payload inválido

    if not message_body or not sender_phone:
         return ('', 400) # Definitivamente faltan datos

    logging.info(f"Mensaje recibido de {sender_phone}: {message_body}")

    # 1. Obtener la configuración del bot
    bot_config = BotConfig.query.first()
    if not bot_config or not bot_config.is_active:
        logging.info("Bot inactivo. Ignorando mensaje.")
        return ('', 200)

    # 2. Analizar el mensaje para determinar el rol/intención
    role_title = get_intent_and_role(message_body)
    logging.info(f"Intención detectada: '{role_title}'")

    # 3. Decidir la acción
    
    # --- Lógica de Saludo ---
    # Si la intención es 'General' (un saludo como "hola"), 
    # respondemos con el mensaje de bienvenida.
    if role_title == 'General':
        logging.info("Intención 'General' detectada. Enviando saludo.")
        welcome_message = bot_config.welcome_message or "¡Hola! ¿En qué puedo ayudarte?"
        response_twiml = create_twilio_response(welcome_message)
        return response_twiml, 200, {'Content-Type': 'application/xml'}

    # --- Lógica de Asignación ---
    # Si la intención es específica (Ventas, Soporte, etc.), 
    # asignamos el chat y notificamos al usuario.
    target_role = BotRole.query.filter_by(title=role_title).first()

    if not target_role:
        logging.warning(f"No se encontró el BotRole: '{role_title}'. Buscando rol 'General'.")
        target_role = BotRole.query.filter_by(title='General').first()
        if not target_role:
             logging.error("No se encontró el rol específico ni un rol 'General'. Abortando.")
             return ('', 500) # Error de configuración del servidor

    # 4. Incrementar los contadores del rol
    try:
        target_role.chats_received = (target_role.chats_received or 0) + 1
        target_role.chats_pending = (target_role.chats_pending or 0) + 1
        db.session.commit()
        logging.info(f"Chat asignado al rol '{target_role.title}'. Pendientes: {target_role.chats_pending}")
        
        # 5. Notificar al usuario que fue transferido
        # (Quitamos la parte de 'Tu solicitud sobre...' para evitar eco)
        transfer_message = f"¡Entendido! Un agente del área de {target_role.title} te atenderá pronto."
        response_twiml = create_twilio_response(transfer_message)
        return response_twiml, 200, {'Content-Type': 'application/xml'}

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al actualizar contadores del rol: {e}")
        return ('Error interno del servidor', 500)

# --- INICIO DE LA APLICACIÓN Y CREACIÓN DE BD ---
if __name__ == '__main__':
    # Creación inicial de la base de datos y datos por defecto
    with app.app_context():
        try:
            db.create_all()
            logging.info("Tablas de la base de datos verificadas/creadas.")
            
            # Asegurarse de que exista al menos un usuario Admin
            if not User.query.filter_by(role='Admin').first():
                logging.info("No se encontró Admin. Creando usuario 'admin' por defecto.")
                admin_user = User(
                    username='admin',
                    password='admin', # ¡Cambiar esto en producción!
                    name='Administrador',
                    role='Admin'
                )
                db.session.add(admin_user)
                db.session.commit()
            
            # Asegurarse de que exista la configuración del bot
            if not BotConfig.query.first():
                logging.info("No se encontró config. Creando configuración de bot por defecto.")
                default_config = BotConfig(
                    is_active=True,
                    whatsapp_number="+573132217862",
                    welcome_message="¡Hola! Bienvenido a nuestro servicio de atención. ¿En qué puedo ayudarte hoy?"
                )
                db.session.add(default_config)
                db.session.commit()

            # Asegurarse de que existan los roles de ejemplo
            if not BotRole.query.filter_by(title='Ventas').first():
                logging.info("Creando rol de 'Ventas' por defecto.")
                db.session.add(BotRole(title='Ventas', knowledge_base='Información de seguros de vehículos.'))
                db.session.commit()

            if not BotRole.query.filter_by(title='Soporte Técnico').first():
                logging.info("Creando rol de 'Soporte Técnico' por defecto.")
                db.session.add(BotRole(title='Soporte Técnico', knowledge_base='Manual de solución de problemas.'))
                db.session.commit()
                
            if not BotRole.query.filter_by(title='General').first():
                logging.info("Creando rol 'General' por defecto.")
                db.session.add(BotRole(title='General', knowledge_base='Preguntas frecuentes generales.'))
                db.session.commit()

        except Exception as e:
            logging.error(f"Error durante la inicialización de la BD: {e}")
            # Esto puede pasar si la BD está conectada pero no lista, es bueno saberlo
            logging.error("Asegúrate de que la base de datos PostgreSQL esté accesible.")


    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)