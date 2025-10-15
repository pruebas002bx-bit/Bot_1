import os
from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

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


# --- RUTAS DE LA APLICACIÓN ---

# Rutas para servir las páginas HTML principales
@app.route('/')
def index():
    return render_template('Index.html')

@app.route('/menu_admin')
def menu_admin():
    return render_template('Menu.html')

@app.route('/menu_soporte')
def menu_soporte():
    return render_template('Menu_Soporte.html')

# Rutas para el contenido del iframe
@app.route('/page/<path:page_name>')
def show_page(page_name):
    # Por seguridad, solo permitir archivos .html
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

    # --- CORRECCIÓN CLAVE ---
    # Se elimina el parámetro 'method' de check_password_hash.
    # La función detecta el método automáticamente desde el hash almacenado.
    if user and check_password_hash(user.password_hash, password):
        # El rol determina a qué menú redirigir
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
    # No enviar el hash de la contraseña al frontend
    return jsonify([{'id': user.id, 'name': user.name, 'role': user.role, 'username': user.username} for user in users])

@app.route('/api/users', methods=['POST'])
def add_user():
    data = request.get_json()
    # Generar un nombre de usuario a partir del nombre completo si no se proporciona
    username = data.get('username') or data.get('name', '').replace(' ', '_').lower()
    
    # Verificar si el usuario ya existe
    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'El nombre de usuario ya existe'}), 409

    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(
        username=username, 
        name=data['name'], 
        password_hash=hashed_password, 
        role=data['role']
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'id': new_user.id, 'name': new_user.name, 'role': new_user.role}), 201

@app.route('/api/users/<int:id>', methods=['PUT'])
def update_user(id):
    user = User.query.get_or_404(id)
    data = request.get_json()
    user.name = data.get('name', user.name)
    user.role = data.get('role', user.role)
    
    # Actualizar la contraseña solo si se proporciona una nueva
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
    result = []
    for role in roles:
        result.append({
            'id': role.id,
            'title': role.title,
            'knowledge_base': role.knowledge_base,
            'assignee_name': role.assignee.name if role.assignee else 'Sin Asignar',
            'assignee_id': role.assignee_id,
            'status': role.status,
            'chats_received': role.chats_received,
            'chats_pending': role.chats_pending
        })
    return jsonify(result)

@app.route('/api/bot_roles/<int:id>', methods=['PUT'])
def update_bot_role(id):
    role = BotRole.query.get_or_404(id)
    data = request.get_json()
    role.title = data.get('title', role.title)
    role.knowledge_base = data.get('knowledge_base', role.knowledge_base)
    role.status = data.get('status', role.status)
    
    assignee_id = data.get('assignee_id')
    # Permite desasignar un rol enviando un ID nulo
    role.assignee_id = assignee_id if assignee_id else None

    db.session.commit()
    return jsonify({'message': 'Rol del bot actualizado correctamente'})
    
# --- Endpoint para la Configuración del Bot ---
@app.route('/api/bot_config', methods=['GET'])
def get_bot_config():
    config = BotConfig.query.first()
    if config:
        return jsonify({
            'is_active': config.is_active,
            'whatsapp_number': config.whatsapp_number,
            'welcome_message': config.welcome_message
        })
    return jsonify({'message': 'Configuración no encontrada'}), 404

@app.route('/api/bot_config', methods=['PUT'])
def update_bot_config():
    config = BotConfig.query.first()
    if not config:
        return jsonify({'message': 'Configuración no encontrada'}), 404
    
    data = request.get_json()
    config.is_active = data.get('is_active', config.is_active)
    config.whatsapp_number = data.get('whatsapp_number', config.whatsapp_number)
    config.welcome_message = data.get('welcome_message', config.welcome_message)
    
    db.session.commit()
    return jsonify({'message': 'Configuración del bot actualizada correctamente'})


# --- COMANDO CLI PARA INICIALIZAR LA BASE DE DATOS ---
@app.cli.command('init-db')
def init_db_command():
    """Crea las tablas de la base de datos y añade datos iniciales."""
    with app.app_context():
        print("Borrando todas las tablas existentes...")
        db.drop_all()
        print("Creando todas las tablas...")
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
        db.session.commit() # Guardar usuarios para obtener sus IDs
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


if __name__ == '__main__':
    # Usar el puerto definido por OnRender, con un valor por defecto para desarrollo local
    port = int(os.environ.get('PORT', 5000))
    # 'debug=False' es importante para producción
    app.run(host='0.0.0.0', port=port, debug=False)

