import tkinter as tk
from tkinter import messagebox
import os

# Nombre del archivo que guardará el contador
ARCHIVO_CONTADOR = "contador.txt"

def obtener_siguiente_numero():
    """
    Lee el número del archivo contador.txt, lo incrementa y lo devuelve.
    Si el archivo no existe, lo crea y empieza en 0.
    """
    if not os.path.exists(ARCHIVO_CONTADOR):
        with open(ARCHIVO_CONTADOR, "w") as f:
            f.write("0")
        return 0
    
    with open(ARCHIVO_CONTADOR, "r") as f:
        try:
            numero = int(f.read())
            return numero
        except ValueError:
            # Si el archivo está corrupto o vacío, reinicia a 0
            with open(ARCHIVO_CONTADOR, "w") as f_write:
                f_write.write("0")
            return 0

def guardar_siguiente_numero(numero):
    """Guarda el siguiente número en el archivo contador."""
    with open(ARCHIVO_CONTADOR, "w") as f:
        f.write(str(numero))

def ejecutar_git():
    """
    Ejecuta los comandos de Git para añadir, comitear y subir los cambios.
    El mensaje del commit es un número consecutivo de dos dígitos.
    """
    try:
        # Obtiene el número actual para el commit
        numero_commit = obtener_siguiente_numero()
        
        # Formatea el número para que siempre tenga dos dígitos (ej: 01, 02, ..., 10)
        mensaje_commit = f"{numero_commit:02d}"
        
        print(f"--- Iniciando subida a Git con commit: {mensaje_commit} ---")

        # 1. Ejecutar git add .
        print("Ejecutando: git add .")
        os.system("git add .")
        
        # 2. Ejecutar git commit
        comando_commit = f'git commit -m "{mensaje_commit}"'
        print(f"Ejecutando: {comando_commit}")
        os.system(comando_commit)
        
        # 3. Ejecutar git push
        print("Ejecutando: git push origin main")
        os.system("git push origin main")
        
        print("--- Proceso completado ---")
        
        # Incrementar y guardar el siguiente número para la próxima vez
        guardar_siguiente_numero(numero_commit + 1)
        
        # Actualizar el texto de la interfaz
        label_contador.config(text=f"Próximo commit será: {numero_commit + 1:02d}")
        
        messagebox.showinfo("Éxito", f"¡Archivos subidos con éxito!\nCommit: {mensaje_commit}")

    except Exception as e:
        messagebox.showerror("Error", f"Ocurrió un error: {e}")

# --- Configuración de la Interfaz Gráfica (GUI) ---
ventana = tk.Tk()
ventana.title("Asistente de Git")
ventana.geometry("350x200") # Tamaño de la ventana

# Etiqueta para mostrar información
titulo = tk.Label(ventana, text="Subir Cambios a Git", font=("Helvetica", 16))
titulo.pack(pady=10)

# Botón para ejecutar la función
boton_subir = tk.Button(ventana, text="Añadir, Comitear y Subir", command=ejecutar_git, bg="lightblue", fg="black", font=("Helvetica", 12))
boton_subir.pack(pady=20, ipadx=10, ipady=5)

# Etiqueta para mostrar el próximo número de commit
proximo_numero = obtener_siguiente_numero()
label_contador = tk.Label(ventana, text=f"Próximo commit será: {proximo_numero:02d}", font=("Helvetica", 10))
label_contador.pack(pady=5)

# Iniciar el bucle de la interfaz
ventana.mainloop()