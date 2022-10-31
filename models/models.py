from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, widgets
from wtforms.validators import InputRequired, Email, Length, DataRequired

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Submit")

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=100)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=100)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=100)])
    submit = SubmitField("Submit")

class ChangePasswordForm(FlaskForm):
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=100)])
    confirm = PasswordField('password', validators=[InputRequired(), Length(min=8, max=100)])
    submit = SubmitField("Submit")

class UserForm(FlaskForm):
    id = StringField('id')
    username = StringField('username')
    email = StringField('email')
    first_name = StringField('first_name')
    last_name = StringField('last_name')
    roles = StringField('roles')
    submit1 = SubmitField('Aktualisieren')

class UserRolesForm(FlaskForm):
    admin = widgets.CheckboxInput()
    read = widgets.CheckboxInput()
    delete = widgets.CheckboxInput()
    change = widgets.CheckboxInput()
    create = widgets.CheckboxInput()
    submit = SubmitField("Submit")

