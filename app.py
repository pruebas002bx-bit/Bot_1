import os
from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from sqlalchemy.inspection import inspect

# Cargar variables de entorno desde el archivo .env
load_dotenv()

app = Flask(__name__, template_folder='templates')

# --- CONFIGURACIÓN DE LA BASE DE DATOS ---
db_uri = os.getenv('DATABASE_URL')
if db_uri and db_uri.startswith("postgres://"):
    db_uri = db_uri.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'una-clave-secreta-por-defecto-muy-segura')

# Inicializar la extensión de SQLAlchemy
db = SQLAlchemy(app)


# --- DEFINICIÓN DE LOS MODELOS DE LA BASE DE DATOS ---
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(80), nullable=False) # 'Admin' o 'Soporte'

class BotRole(db.Model):
    __tablename__ = 'bot_roles'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    knowledge_base = db.Column(db.Text, nullable=True)
    assignee_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
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

# --- FUNCIÓN PARA INICIALIZAR Y POBLAR LA BASE DE DATOS ---
def initialize_database():
    """Crea las tablas y añade datos iniciales si no existen."""
    print("Iniciando la inicialización de la base de datos...")
    
    # Borrar y crear de nuevo asegura un estado limpio
    db.drop_all()
    db.create_all()
    print("¡Tablas creadas con éxito!")

    print("Poblando la base de datos con usuarios y roles iniciales...")
    # Creación de usuarios
    admin_user = User(
        username='Admin123',
        password_hash=generate_password_hash('12345', method='pbkdf2:sha256'),
        name='Administrador',
        role='Admin'
    )
    support_user = User(
        username='Carlos_Ruiz',
        password_hash=generate_password_hash('12345', method='pbkdf2:sha256'),
        name='Carlos Ruiz',
        role='Soporte'
    )
    db.session.add(admin_user)
    db.session.add(support_user)
    db.session.commit()
    print("...usuarios creados.")

    # Creación de roles de bot
    roles_iniciales = [
        BotRole(title='Soporte Técnico Nivel 1', knowledge_base='Guías de resolución de problemas comunes.', assignee_id=support_user.id, status='Activo', chats_received=1204, chats_pending=15),
        BotRole(title='Agente de Ventas', knowledge_base='Catálogo de productos y promociones.', assignee_id=support_user.id, status='Activo', chats_received=856, chats_pending=5),
        BotRole(title='Gestión de Citas', knowledge_base='Acceso a calendarios y políticas.', status='Inactivo'),
        BotRole(title='Recursos Humanos', knowledge_base='Políticas de la empresa y beneficios.', status='Activo')
    ]
    db.session.bulk_save_objects(roles_iniciales)
    db.session.commit()
    print("...roles de bot creados.")

    # Creación de la configuración inicial del bot
    config_inicial = BotConfig(
        is_active=True,
        whatsapp_number='+57 3132217862',
        welcome_message='¡Hola! Bienvenido a nuestro servicio de atención. ¿En qué puedo ayudarte hoy?'
    )
    db.session.add(config_inicial)
    db.session.commit()
    print("...configuración del bot creada.")

    print("¡Población de la base de datos completada con éxito!")


# --- RUTAS DE LA APLICACIÓN ---

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


# --- API ENDPOINTS ---

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"success": False, "message": "Usuario y contraseña requeridos"}), 400

    user = User.query.filter_by(username=username).first()

    if user and check_password_hash(user.password_hash, password):
        redirect_url = 'menu_admin' if user.role == 'Admin' else 'menu_soporte'
        return jsonify({
            "success": True,
            "message": "Inicio de sesión exitoso",
            "redirect_url": url_for(redirect_url)
        })
    else:
        return jsonify({"success": False, "message": "Usuario o contraseña incorrectos"}), 401

# --- Endpoints para la gestión de Usuarios ---
@app.route('/api/users', methods=['GET'])
def get_users():
    users = User.query.all()
    return jsonify([{'id': user.id, 'name': user.name, 'role': user.role, 'username': user.username} for user in users])

@app.route('/api/users', methods=['POST'])
def add_user():
    data = request.get_json()
    username = data.get('username') or data.get('name', '').replace(' ', '_').lower()
    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'El nombre de usuario ya existe'}), 409
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(username=username, name=data['name'], password_hash=hashed_password, role=data['role'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'id': new_user.id, 'name': new_user.name, 'role': new_user.role}), 201

@app.route('/api/users/<int:id>', methods=['PUT'])
def update_user(id):
    user = User.query.get_or_404(id)
    data = request.get_json()
    user.name = data.get('name', user.name)
    user.role = data.get('role', user.role)
    if 'password' in data and data['password']:
        user.password_hash = generate_password_hash(data['password'], method='pbkdf2:sha256')
    db.session.commit()
    return jsonify({'message': 'Usuario actualizado correctamente'})

@app.route('/api/users/<int:id>', methods=['DELETE'])
def delete_user(id):
    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'Usuario eliminado correctamente'})

# --- Endpoints para la gestión de Roles del Bot ---
@app.route('/api/bot_roles', methods=['GET'])
def get_bot_roles():
    roles = BotRole.query.options(db.joinedload(BotRole.assignee)).all()
    return jsonify([{
        'id': role.id, 'title': role.title, 'knowledge_base': role.knowledge_base,
        'assignee_name': role.assignee.name if role.assignee else 'Sin Asignar',
        'assignee_id': role.assignee_id, 'status': role.status,
        'chats_received': role.chats_received, 'chats_pending': role.chats_pending
    } for role in roles])

@app.route('/api/bot_roles/<int:id>', methods=['PUT'])
def update_bot_role(id):
    role = BotRole.query.get_or_404(id)
    data = request.get_json()
    role.title = data.get('title', role.title)
    role.knowledge_base = data.get('knowledge_base', role.knowledge_base)
    role.status = data.get('status', role.status)
    role.assignee_id = data.get('assignee_id')
    db.session.commit()
    return jsonify({'message': 'Rol del bot actualizado correctamente'})

# --- Endpoint para la Configuración del Bot ---
@app.route('/api/bot_config', methods=['GET'])
def get_bot_config():
    config = BotConfig.query.first()
    return jsonify({
        'is_active': config.is_active, 'whatsapp_number': config.whatsapp_number,
        'welcome_message': config.welcome_message
    }) if config else (jsonify({'message': 'Configuración no encontrada'}), 404)

@app.route('/api/bot_config', methods=['PUT'])
def update_bot_config():
    config = BotConfig.query.first_or_404()
    data = request.get_json()
    config.is_active = data.get('is_active', config.is_active)
    config.whatsapp_number = data.get('whatsapp_number', config.whatsapp_number)
    config.welcome_message = data.get('welcome_message', config.welcome_message)
    db.session.commit()
    return jsonify({'message': 'Configuración del bot actualizada correctamente'})


# --- INICIALIZACIÓN AUTOMÁTICA DE LA BASE DE DATOS ---
with app.app_context():
    # Usamos un inspector para verificar si la tabla 'users' ya existe
    inspector = inspect(db.engine)
    if not inspector.has_table("users"):
        print("La tabla 'users' no existe. Se procederá a inicializar la base de datos.")
        initialize_database()
    else:
        print("La base de datos ya parece estar inicializada. Saltando la creación de datos.")


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

