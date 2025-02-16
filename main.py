from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email
from werkzeug.security import generate_password_hash
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)  # create an app instance
app.config['SECRET_KEY'] = 'DEV'
csrf = CSRFProtect(app)

# Lista para almacenar los usuarios registrados
usuarios = []

class Formulario(FlaskForm):
    username = StringField('Nombre de usuario', validators=[DataRequired(), Length(min=4, max=15)])
    email = StringField('Correo electrónico', validators=[DataRequired(), Email()])
    telefono = StringField('Teléfono', validators=[DataRequired(), Length(min=10, max=15)])
    password = PasswordField('Contraseña', validators=[DataRequired(), Length(min=8, max=80)])
    submit = SubmitField('Enviar')


@app.route('/')
def mostrar_formulario():
    form = Formulario()
    return render_template('auth/Register.html', form=form)


@app.route('/register', methods=['POST'])
def registrar_usuario():
    form = Formulario()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        telefono = form.telefono.data
        password = form.password.data

        # Verificar si el correo ya existe
        if any(user['email'] == email for user in usuarios):
            flash('Error: El correo electrónico ya está registrado.', 'danger')
            return redirect(url_for('mostrar_formulario'))

        # Cifrar contraseña
        password_hash = generate_password_hash(password)

        # Agregar usuario
        usuarios.append({
            'username': username,
            'email': email,
            'telefono': telefono,
            'password': password_hash
        })

        flash('¡Usuario registrado correctamente!', 'success')
        return redirect(url_for('mostrar_formulario'))
    else:
        flash('Error: Datos no válidos. Verifique los campos e inténtelo de nuevo.', 'danger')
        return redirect(url_for('mostrar_formulario'))


@app.route('/usuarios', methods=['GET'])
def ver_usuarios():
    if not usuarios:
        flash('No hay usuarios registrados aún.', 'info')
    return render_template('auth/lista.html', usuarios=enumerate(usuarios))


if __name__ == "__main__":
    app.run(debug=True)
