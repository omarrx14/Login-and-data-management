from flask import Flask, render_template, request, jsonify, make_response, session, redirect, url_for, Blueprint, flash
import psycopg2
import psycopg2.extras
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps
import re
import sqlite3
from elasticsearch import Elasticsearch


app = Flask(__name__)
auth = Blueprint('auth', __name__)
app.config['SECRET_KEY'] = '9hD$#Wp2Tqy6A^z@e7sC'
app.config['ELASTICSEARCH_HOST'] = 'http://127.0.0.1'  
app.config['ELASTICSEARCH_PORT'] = '5000' 

es = Elasticsearch([f"{app.config['ELASTICSEARCH_HOST']}:{app.config['ELASTICSEARCH_PORT']}"])




def consultar_tabla(tabla):
    try:
        conexion = psycopg2.connect(user='postgres',
                                    password='omar123',
                                    host='localhost',
                                    port='5432',
                                    database='mydb')

        cursor = conexion.cursor()

        consulta_obtener_registros = f"""
        SELECT * FROM {tabla};
        """

        cursor.execute(consulta_obtener_registros)

        registros = cursor.fetchall()

        return registros

    except (Exception, psycopg2.Error) as error:
        print(f"Error al obtener los registros de la tabla '{tabla}':", error)
    finally:
        if conexion:
            cursor.close()
            conexion.close()

class User:
    def __init__(self, id, public_id, username, email, contrasena):
        self.id = id
        self.public_id = public_id
        self.name = username
        self.email = email
        self.password = contrasena

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message': 'Token is missing !!'}), 401
  
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query\
                .filter_by(public_id=data['public_id'])\
                .first()
        except:
            return jsonify({
                'message': 'Token is invalid !!'
            }), 401
        return f(current_user, *args, **kwargs)
  
    return decorated
  
@app.route('/user', methods=['GET', 'POST'])
@token_required
def get_all_users(current_user):
    registros = consultar_tabla("users")
    users = []
    for registro in registros:
        user = User(registro[0], registro[1], registro[2], registro[3], registro[4], registro[5], registro[6])
        users.append(user)
    output = []
    for user in users:
        output.append({
            'public_id': user.public_id,
            'username': user.username,
            'email': user.email
        })
    return jsonify({'users': output})

@app.route('/')
def home():
    if 'loggedin' in session:
    
        return render_template('home.html', username=session['username'])
    return redirect(url_for('login'))
  
@app.route('/login2', methods=['GET', 'POST'])
def login():
    conn = connect_db()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    
   
    if request.method == 'POST' and 'username' in request.form and 'contrasena' in request.form:
        username = request.form['username']
        contrasena = request.form['contrasena']
 
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        account = cursor.fetchone()
 
        if account:
            password_rs = account['contrasena']
            if check_password_hash(password_rs, contrasena):
                session['loggedin'] = True
                session['id'] = account['id']
                session['username'] = account['username']
                return redirect(url_for('home'))
            else:
                flash('Incorrect username/password')
        else:
            flash('Incorrect username/password')
 
    return render_template('login2.html')


def connect_db():
    return psycopg2.connect(user='postgres', password='omar123', host='localhost', port='5432', database='mydb')

  
@app.route('/signup', methods=['GET', 'POST'])
def register():
    
    conn = connect_db()
    cursor = conn.cursor()

    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        nombre = request.form['name']
        apellido = request.form['apellido']
        username = request.form['username']
        edad = request.form['edad']
        contrasena = request.form['password']
        email = request.form['email']
    
        _hashed_password = generate_password_hash(contrasena)
 
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        account = cursor.fetchone()
        
        if account:
            flash('Account already exists!')
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            flash('Invalid email address!')
        elif not re.match(r'[A-Za-z0-9]+', username):
            flash('Username must contain only characters and numbers!')
        elif not username or not contrasena or not email:
            flash('Please fill out the form!')
        else:
            cursor.execute("INSERT INTO users (nombre, username, contrasena, email) VALUES (%s,%s,%s,%s)", (nombre, username, _hashed_password, email))
            conn.commit()
            flash('You have successfully registered!')
            conn.close()
            return redirect(url_for('login')) 
    
    elif request.method == 'POST':
        flash('Please fill out the form!')
    
    conn.close()
    
    return render_template('signup.html')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/dashboard')
def dashboard():    
    try:
        conn = psycopg2.connect(
            user='postgres',
            password='omar123',
            host='localhost',
            port='5432',
            database='mydb')
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM equipos')
        data = cursor.fetchall()


        
        conn.close()

        return render_template('dashboard.html', data=data)

    except Exception as e:
        return f"Error: {str(e)}"

@app.route('/dashboard', methods=['POST'])
def index_data():
    try:
        data = request.get_json()

        es.index(index='mi_indice', body=data)

        return 'Documento indexado con éxito', 200
    except Exception as e:
        return handle_error(e)

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('q')
    if query:
        try:
            results = es.search(index='mi_indice', body={'query': {'match': {'nombre_del_campo': query}}})

            hits = results.get('hits', {}).get('hits', [])
            data = [hit['_source'] for hit in hits]
        except Exception as e:
            return handle_error(e)
    else:
        data = []

    return render_template('dashboard.html', data=data)


@app.route('/usuarios.html', methods=["GET", "POST"])
def mostrar_usuarios():
    registros = consultar_tabla("users")

    return render_template('/usuarios.html', registros=registros)

@app.route('/agregar', methods=['GET', 'POST'])
def agregar_usuario():
    if request.method == 'POST':
        try:
            nombre = request.form['nombre']
            apellido = request.form['apellido']
            edad = int(request.form['edad'])
            contrasena = request.form['contrasena']
            correo = request.form['correo']
            username = request.form['username']


            conexion = psycopg2.connect(user='postgres',
                                        password='omar123',
                                        host='localhost',
                                        port='5432',
                                        database='mydb')

            cursor = conexion.cursor()

            consulta_insertar_usuario = f"""
            INSERT INTO users (nombre, apellido, edad, email, contrasena, username)
            VALUES ('{nombre}', '{apellido}', {edad}, '{correo}', '{contrasena}', '{username}');
            """

            cursor.execute(consulta_insertar_usuario)

            conexion.commit()
            conexion.close()

            return redirect(url_for('mostrar_usuarios'))

        except (Exception, psycopg2.Error) as error:
            return f"Error al agregar el usuario: {error}"

    return render_template('agregar_usuario.html')

@app.route('/editar/<int:id>', methods=['GET', 'POST'])
def editar_usuario(id):
    if request.method == 'POST':
        try:
            nombre = request.form['nombre']
            apellido = request.form['apellido']
            edad = int(request.form['edad'])
            contrasena = request.form['contrasena']
            correo = request.form['correo']
            username = request.form['username']


            conexion = psycopg2.connect(user='postgres',
                                        password='omar123',
                                        host='localhost',
                                        port='5432',
                                        database='mydb')

            cursor = conexion.cursor()

            consulta_actualizar_usuario = f"""
            UPDATE users
            SET nombre = '{nombre}', apellido = '{apellido}', edad = {edad}, email = '{correo}', contrasena = '{contrasena}', username = '{username}'
            WHERE id = {id};
            """

            cursor.execute(consulta_actualizar_usuario)

            conexion.commit()
            conexion.close()

            return redirect(url_for('mostrar_usuarios'))

        except (Exception, psycopg2.Error) as error:
            return f"Error al editar el usuario: {error}"

    try:
        conexion = psycopg2.connect(user='postgres',
                                    password='omar123',
                                    host='localhost',
                                    port='5432',
                                    database='mydb')

        cursor = conexion.cursor()

        consulta_obtener_usuario = f"""
        SELECT * FROM users WHERE id = {id};
        """

        cursor.execute(consulta_obtener_usuario)

        usuario = cursor.fetchone()

        conexion.close()

        return render_template('editar_usuario.html', usuario=usuario)

    except (Exception, psycopg2.Error) as error:
        return f"Error al obtener el usuario: {error}"



@app.route('/eliminar/<int:id>')
def eliminar_usuario(id):
    try:
        conexion = psycopg2.connect(user='postgres',
                                    password='omar123',
                                    host='localhost',
                                    port='5432',
                                    database='mydb')

        cursor = conexion.cursor()

        consulta_eliminar_usuario = f"""
        DELETE FROM users WHERE id = {id};
        """

        cursor.execute(consulta_eliminar_usuario)

        conexion.commit()
        conexion.close()

        return redirect(url_for('mostrar_usuarios'))

    except (Exception, psycopg2.Error) as error:
        return f"Error al eliminar el usuario: {error}"
    
@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('login'))
    

@app.route('/profile/')
def profile():
    if 'loggedin' in session:
        user_id = session['id']
        
        conn = psycopg2.connect(
            host='localhost',
            port='5432',
            database='mydb',
            user='postgres',
            password='omar123'
        )
        
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = %s',(user_id,))
        account = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        return render_template('/profile.html/', account=account)
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True) 
