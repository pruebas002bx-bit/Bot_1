from app import db
from werkzeug.security import generate_password_hash, check_password_hash

# Este archivo puede ser usado en el futuro si la lógica de los modelos
# crece demasiado y se quiere separar de app.py para mayor organización.

# Por ahora, todos los modelos están definidos en app.py para simplicidad.
# Si mueves los modelos aquí, necesitarás importar 'db' desde la app
# y luego importar los modelos en app.py desde este archivo.

# Ejemplo de cómo se vería si se separaran:
# from main_app import db  # Suponiendo que renombras app.py a main_app.py

# class User(db.Model):
#     ... (definición del modelo) ...

pass
