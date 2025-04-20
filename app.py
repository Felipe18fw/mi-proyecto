from flask import Flask, request, render_template, redirect, url_for, flash, jsonify, Request
from werkzeug.utils import secure_filename
from database import Database
import face_recognition
import cv2
import numpy as np
import os
import base64
from datetime import datetime
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth
from flask_bcrypt import Bcrypt

# Cargar variables de entorno
load_dotenv()

app = Flask(__name__)
bcrypt = Bcrypt(app)

# Configuración de OAuth
oauth = OAuth(app)

oauth.register(
    name='google',
    client_id=os.getenv('1063060969819-b7glmg1vn5r9pmopdvmqec2ba32evs6b.apps.googleusercontent.com'),
    client_secret=os.getenv('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'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)
app.secret_key = 'tu_clave_secreta_aqui'  # Cambiar en producción

# Instancia de la base de datos
db = Database()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        foto_data = request.form.get('foto')
        nombre = request.form.get('nombre')
        contraseña = request.form.get('contraseña')
        
        if not foto_data or not foto_data.startswith('data:image/'):
            flash('No se ha capturado ninguna foto')
            return redirect(request.url)
        
        try:
            # Eliminar el encabezado de data URL y obtener los datos binarios
            foto_data = foto_data.split(',')[1]
            foto_bytes = base64.b64decode(foto_data)
            
            # Convertir a imagen para verificación facial
            nparr = np.frombuffer(foto_bytes, np.uint8)
            image = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            image_rgb = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
            
            # Verificar que la imagen contiene un rostro
            face_locations = face_recognition.face_locations(image_rgb)
            
            if not face_locations:
                flash('No se detectó ningún rostro en la imagen')
                return redirect(request.url)
            
            # Encriptar la contraseña
            hashed_password = bcrypt.generate_password_hash(contraseña).decode('utf-8')
            
            # Guardar usuario en la base de datos con la imagen en formato binario
            db.crear_usuario(nombre, hashed_password, foto_bytes)
            flash('Usuario registrado exitosamente')
            return redirect(url_for('home'))
            
        except Exception as e:
            print(f"Error durante el registro: {str(e)}")
            flash('Error al procesar la imagen')
            return redirect(request.url)
    
    return render_template('registro.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        foto_data = request.form.get('foto')
        nombre = request.form.get('nombre')
        contraseña = request.form.get('contraseña')
        
        if not foto_data or not foto_data.startswith('data:image/'):
            flash('No se ha capturado ninguna foto')
            return redirect(request.url)
        
        # Obtener usuario de la base de datos
        usuario = db.obtener_usuario(nombre)
        if not usuario:
            flash('Usuario no encontrado')
            return redirect(request.url)
        
        try:
            # Convertir la imagen de login a array para face_recognition
            foto_data = foto_data.split(',')[1]
            foto_bytes = base64.b64decode(foto_data)
            nparr = np.frombuffer(foto_bytes, np.uint8)
            login_image = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            login_image_rgb = cv2.cvtColor(login_image, cv2.COLOR_BGR2RGB)
            
            # Obtener encodings de la imagen de login
            login_encodings = face_recognition.face_encodings(login_image_rgb)
            
            if not login_encodings:
                flash('No se detectó ningún rostro en la imagen proporcionada')
                return redirect(request.url)
            
            # Convertir la imagen almacenada a array para comparación
            nparr_stored = np.frombuffer(usuario['foto'], np.uint8)
            stored_image = cv2.imdecode(nparr_stored, cv2.IMREAD_COLOR)
            stored_image_rgb = cv2.cvtColor(stored_image, cv2.COLOR_BGR2RGB)
            
            # Obtener encoding de la imagen almacenada
            stored_encoding = face_recognition.face_encodings(stored_image_rgb)[0]
            
            # Comparar rostros
            match = face_recognition.compare_faces([stored_encoding], login_encodings[0])[0]
            
            if match:
                # Registrar login exitoso
                db.registrar_login(nombre)
                flash('Inicio de sesión exitoso')
                return redirect(url_for('dashboard'))
            else:
                # Verificar contraseña si el reconocimiento facial falla
                if bcrypt.check_password_hash(usuario['contraseña'], contraseña):
                    db.registrar_login(nombre)
                    flash('Inicio de sesión exitoso con contraseña')
                    return redirect(url_for('dashboard'))
                else:
                    flash('El rostro no coincide y la contraseña es incorrecta')
                    return redirect(request.url)
            
        except Exception as e:
            print("Error durante la verificación facial:", e)
            flash('Error en la verificación facial')
            return redirect(request.url)
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    usuarios = db.listar_usuarios()
    # Convertir las imágenes binarias a base64 para mostrarlas en el navegador
    for usuario in usuarios:
        if 'foto' in usuario and usuario['foto']:
            img_data = base64.b64encode(usuario['foto']).decode('utf-8')
            usuario['foto_base64'] = f'data:image/jpeg;base64,{img_data}'
        else:
            usuario['foto_base64'] = None
    return render_template('dashboard.html', usuarios=usuarios)

# Rutas CRUD para usuarios
@app.route('/usuarios', methods=['GET'])
def listar_usuarios():
    usuarios = db.listar_usuarios()
    return jsonify(usuarios)

# Configuración para subida de archivos
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/usuarios/<nombre>', methods=['PUT'])
def actualizar_usuario(nombre):
    try:
        datos = {}
        if 'nombre_nuevo' in request.form:
            datos['nombre'] = request.form['nombre_nuevo']
        if 'contraseña' in request.form:
            datos['contraseña'] = request.form['contraseña']
        
        # Manejar la foto si se proporciona como base64
        if 'foto' in request.form:
            foto_data = request.form['foto']
            if foto_data.startswith('data:image/'):
                # Procesar imagen en base64
                foto_data = foto_data.split(',')[1]
                foto_bytes = base64.b64decode(foto_data)
                
                # Verificar que la imagen contiene un rostro
                nparr = np.frombuffer(foto_bytes, np.uint8)
                image = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                image_rgb = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
                face_locations = face_recognition.face_locations(image_rgb)
                
                if not face_locations:
                    return jsonify({'success': False, 'message': 'No se detectó ningún rostro en la imagen'}), 400
                
                datos['foto'] = foto_bytes
        # Manejar la foto si se proporciona como archivo
        elif 'foto' in request.files:
            foto = request.files['foto']
            if foto and allowed_file(foto.filename):
                foto_bytes = foto.read()
                datos['foto'] = foto_bytes
        
        resultado = db.actualizar_usuario(nombre, datos)
        return jsonify({'success': True, 'message': 'Usuario actualizado correctamente'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400

@app.route('/usuarios/<nombre>', methods=['DELETE'])
def eliminar_usuario(nombre):
    resultado = db.eliminar_usuario(nombre)
    return jsonify({'success': resultado.deleted_count > 0})

# Google Sign-in
# Configuración de Google OAuth
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')

@app.route('/auth/google')
def login_via_google():
    redirect_uri = os.getenv('REDIRECT_URI')
    return oauth.google.authorize_redirect(request, redirect_uri)

@app.route('/auth/google/callback')
def auth_google_callback():
    try:
        token = oauth.google.authorize_access_token()
        user_info = oauth.google.parse_id_token(token)
        
        # Registrar usuario de Google si no existe
        usuario = db.obtener_usuario(user_info['email'])
        if not usuario:
            db.crear_usuario(
                nombre=user_info['email'],
                contraseña=None,  # Usuario de Google no necesita contraseña
                foto=user_info.get('picture', '')  # URL de la foto de perfil de Google
            )
        
        # Registrar login exitoso
        db.registrar_login(user_info['email'])
        flash('Inicio de sesión con Google exitoso')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        flash('Error en la autenticación con Google')
        return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)