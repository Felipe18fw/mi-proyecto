from pymongo import MongoClient
from datetime import datetime
import os
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

# Configuración de la conexión a MongoDB
class Database:
    def __init__(self):
        try:
            self.client = MongoClient(os.getenv('MONGO_URI'), serverSelectionTimeoutMS=5000)
            self.client.server_info()  # Esto generará una excepción si la conexión falla
            self.db = self.client['proyecto']
            self.usuarios = self.db['usuarios']
            self.logs = self.db['logs']
        except Exception as e:
            print(f"Error al conectar con MongoDB: {str(e)}")  # Registrar el error
            raise Exception("No se pudo establecer la conexión con la base de datos")
    
    def crear_usuario(self, nombre, contraseña, foto_data):
        """Crear un nuevo usuario con la imagen almacenada como datos binarios"""
        usuario = {
            'nombre': nombre,
            'contraseña': contraseña,
            'foto': foto_data,  # Almacena los datos binarios de la imagen directamente
            'fecha_creacion': datetime.now()
        }
        print(f"Datos del usuario a insertar: {usuario}")  # Debug: Print user data
        result = self.usuarios.insert_one(usuario)
        print(f"Usuario creado con ID: {result.inserted_id}")  # Debug: Print the inserted ID
        return result
    
    def obtener_usuario(self, nombre):
        """Obtener un usuario por nombre"""
        usuario = self.usuarios.find_one({'nombre': nombre})
        return usuario
    
    def actualizar_usuario(self, nombre, datos_actualizados):
        """Actualizar datos de un usuario"""
        return self.usuarios.update_one(
            {'nombre': nombre},
            {'$set': datos_actualizados}
        )
    
    def eliminar_usuario(self, nombre):
        """Eliminar un usuario"""
        return self.usuarios.delete_one({'nombre': nombre})
    
    def listar_usuarios(self):
        """Obtener lista de todos los usuarios"""
        return list(self.usuarios.find({}, {'contraseña': 0}))
    
    def registrar_login(self, nombre_usuario):
        """Registrar un intento de inicio de sesión exitoso"""
        log = {
            'nombre_usuario': nombre_usuario,
            'fecha_hora': datetime.now(),
            'tipo': 'login_exitoso'
        }
        return self.logs.insert_one(log)