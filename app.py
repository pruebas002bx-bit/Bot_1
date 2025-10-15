import os
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import json

# =============================================================================
# --- CONFIGURACIÓN DE LA APLICACIÓN Y BASE DE DATOS ---
# =============================================================================

# MODIFICACIÓN: Se elimina `template_folder='.'`. 
# Flask ahora buscará los archivos HTML en una carpeta llamada "templates" por defecto.
app = Flask(__name__) 

# Configuración para la base de datos. OnRender la proveerá a través de la variable de entorno DATABASE_URL.
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///local.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Clave secreta para la gestión de sesiones. Es crucial para la seguridad.
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'una-clave-secreta-muy-segura-para-desarrollo')

db = SQLAlchemy(app)

# =============================================================================
# --- MODELOS DE LA BASE DE DATOS (DEFINICIÓN DE TABLAS) ---
# =============================================================================

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(80), nullable=False) # e.g., 'Admin', 'Soporte Técnico Nivel 1'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class BotRole(db.Model):
    __tablename__ = 'bot_roles'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    knowledge_base = db.Column(db.Text, nullable=True)
    assignee_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    status = db.Column(db.String(20), default='Activo') # 'Activo' o 'Desactivado'
    chats_received = db.Column(db.Integer, default=0)
    chats_pending = db.Column(db.Integer, default=0)

    assignee = db.relationship('User')

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'knowledge_base': self.knowledge_base,
            'assignee': self.assignee.name if self.assignee else 'Sin Asignar',
            'status': self.status,
            'chats_received': self.chats_received,
            'chats_pending': self.chats_pending
        }

class BotConfig(db.Model):
    __tablename__ = 'bot_config'
    id = db.Column(db.Integer, primary_key=True, default=1)
    is_active = db.Column(db.Boolean, default=True)
    whatsapp_number = db.Column(db.String(50), nullable=True)
    welcome_message = db.Column(db.Text, nullable=True)

# =============================================================================
# --- DECORADOR DE AUTENTICACIÓN ---
# =============================================================================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# =============================================================================
# --- RUTAS PARA SERVIR LAS PÁGINAS HTML ---
# =============================================================================

@app.route('/')
def index():
    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        if user and user.username == 'Admin123':
             return redirect(url_for('menu'))
        else:
             return redirect(url_for('menu_soporte'))
    return render_template('Index.html')

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        session['user_id'] = user.id
        session['username'] = user.username
        session['role'] = user.role
        
        # Redirigir basado en el username (podría ser por rol también)
        if user.username == 'Admin123':
            return jsonify({'success': True, 'redirect_url': url_for('menu')})
        else:
            return jsonify({'success': True, 'redirect_url': url_for('menu_soporte')})
    
    return jsonify({'success': False, 'message': 'Usuario o contraseña incorrectos.'}), 401

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# --- Páginas Protegidas ---

@app.route('/menu')
@login_required
def menu():
    return render_template('Menu.html')

@app.route('/menu_soporte')
@login_required
def menu_soporte():
    return render_template('Menu_Soporte.html')

# Las siguientes rutas sirven las páginas que se cargarán en el iframe
@app.route('/<page_name>')
@login_required
def serve_page(page_name):
    # Asegurarse de que el nombre del archivo es seguro y existe
    safe_pages = [
        'Dashboard.html', 'Bot.html', 'Usuarios.html', 'Configuracion.html',
        'Dashboard_Soporte.html', 'Chats_Generales.html'
    ]
    if page_name in safe_pages:
        return render_template(page_name)
    return "Página no encontrada", 404

# =============================================================================
# --- API ENDPOINTS (PARA QUE EL FRONTEND OBTENGA Y MANDE DATOS) ---
# =============================================================================

# --- API para Gestión de Usuarios ---
@app.route('/api/users', methods=['GET', 'POST'])
@login_required
def manage_users():
    if request.method == 'GET':
        users = User.query.all()
        return jsonify([{'id': u.id, 'name': u.name, 'role': u.role, 'username': u.username} for u in users])
    
    if request.method == 'POST':
        data = request.get_json()
        # Validación básica
        if not all(k in data for k in ['name', 'password', 'role', 'username']):
            return jsonify({'message': 'Faltan datos'}), 400
        
        new_user = User(name=data['name'], role=data['role'], username=data['username'])
        new_user.set_password(data['password'])
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'id': new_user.id, 'name': new_user.name, 'role': new_user.role, 'username': new_user.username}), 201

@app.route('/api/users/<int:user_id>', methods=['PUT', 'DELETE'])
@login_required
def manage_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'message': 'Usuario no encontrado'}), 404
        
    if request.method == 'PUT':
        data = request.get_json()
        user.name = data.get('name', user.name)
        user.role = data.get('role', user.role)
        user.username = data.get('username', user.username)
        if 'password' in data and data['password']:
            user.set_password(data['password'])
        db.session.commit()
        return jsonify({'id': user.id, 'name': user.name, 'role': user.role, 'username': user.username})

    if request.method == 'DELETE':
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': 'Usuario eliminado'}), 200

# --- API para Roles del Bot ---
@app.route('/api/bot_roles', methods=['GET'])
@login_required
def get_bot_roles():
    roles = BotRole.query.order_by(BotRole.id).all()
    return jsonify([role.to_dict() for role in roles])

@app.route('/api/bot_roles/<int:role_id>', methods=['PUT'])
@login_required
def update_bot_role(role_id):
    role = db.session.get(BotRole, role_id)
    if not role:
        return jsonify({'message': 'Rol no encontrado'}), 404

    data = request.get_json()
    role.title = data.get('title', role.title)
    role.knowledge_base = data.get('knowledge_base', role.knowledge_base)
    role.status = data.get('status', role.status)
    assignee_name = data.get('assignee')
    if assignee_name:
        user = User.query.filter_by(name=assignee_name).first()
        role.assignee_id = user.id if user else None
    
    db.session.commit()
    return jsonify(role.to_dict())

# --- API para Configuración General del Bot ---
@app.route('/api/config', methods=['GET', 'POST'])
@login_required
def manage_config():
    config = BotConfig.query.first()
    if not config:
        # Crea una configuración por defecto si no existe
        config = BotConfig(whatsapp_number="+57 3132217862", welcome_message="¡Hola! Bienvenido.", is_active=True)
        db.session.add(config)
        db.session.commit()

    if request.method == 'GET':
        return jsonify({
            'is_active': config.is_active,
            'whatsapp_number': config.whatsapp_number,
            'welcome_message': config.welcome_message
        })

    if request.method == 'POST':
        data = request.get_json()
        config.is_active = data.get('is_active', config.is_active)
        config.whatsapp_number = data.get('whatsapp_number', config.whatsapp_number)
        config.welcome_message = data.get('welcome_message', config.welcome_message)
        db.session.commit()
        return jsonify({'message': 'Configuración guardada con éxito'})

# =============================================================================
# --- INICIALIZACIÓN Y EJECUCIÓN ---
# =============================================================================

# Comando para inicializar la base de datos (se ejecuta una vez)
@app.cli.command("init-db")
def init_db_command():
    """Crea las tablas de la base de datos y la puebla con datos iniciales."""
    db.create_all()
    
    # --- Poblar con datos iniciales si las tablas están vacías ---
    if User.query.count() == 0:
        print("Poblando la base de datos con datos iniciales...")
        
        # Crear Usuarios
        admin = User(username='Admin123', name='Administrador Principal', role='Admin')
        admin.set_password('12345')
        
        carlos = User(username='Carlos_Ruiz', name='Carlos Ruiz', role='Agente de Ventas')
        carlos.set_password('12345')
        
        ana = User(name="Ana Gómez", username="Ana_Gomez", role="Soporte Técnico Nivel 1")
        ana.set_password("pass123")
        
        laura = User(name="Laura Méndez", username="Laura_Mendez", role="Recursos Humanos")
        laura.set_password("laurita_HR")
        
        db.session.add_all([admin, carlos, ana, laura])
        db.session.commit()
        
        # Crear Roles del Bot
        role1 = BotRole(title='Soporte Técnico Nivel 1', knowledge_base='Guías de resolución de problemas.', assignee_id=ana.id, status='Activo', chats_received=1204, chats_pending=15)
        role2 = BotRole(title='Agente de Ventas', knowledge_base='Catálogo de productos.', assignee_id=carlos.id, status='Activo', chats_received=856, chats_pending=5)
        role3 = BotRole(title='Recursos Humanos', knowledge_base='Políticas de la empresa.', assignee_id=laura.id, status='Activo', chats_received=98, chats_pending=2)
        role4 = BotRole(title='Gestión de Citas', knowledge_base='Acceso a calendarios.', status='Desactivado')
        
        db.session.add_all([role1, role2, role3, role4])
        
        # Crear Configuración
        config = BotConfig(is_active=True, whatsapp_number='+57 3132217862', welcome_message='¡Hola! Bienvenido a nuestro servicio de atención. ¿En qué puedo ayudarte hoy?')
        db.session.add(config)
        
        db.session.commit()
        print("Base de datos inicializada y poblada con éxito.")
    else:
        print("La base de datos ya contiene datos. No se realizaron cambios.")

if __name__ == '__main__':
    # El host '0.0.0.0' es necesario para que OnRender pueda acceder a la app.
    # El puerto es proporcionado por OnRender a través de una variable de entorno.
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

