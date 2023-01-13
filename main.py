import datetime
import os
from flask import Flask, render_template, flash, redirect, url_for, request
import secrets
from werkzeug.security import check_password_hash, generate_password_hash

import models.models as model
import models.messages as messages
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

PATH = os.path.dirname(__file__)


class ConfigClass(object):
    SECRET_KEY = secrets.token_hex(16)

    # Database
    # SQLALCHEMY_DATABASE_URI = 'sqlite:///' + PATH + '/database/data.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False  # Avoids SQLAlchemy warning
    ## Test Database
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + PATH + '/database/test_database.db'
    SQLALCHEMY_POOL_RECYCLE = 299



app = Flask(__name__)
app.config.from_object(__name__ + '.ConfigClass')
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = messages.LOGIN_MESSAGE


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True)
    active = db.Column('is_active', db.Boolean(), nullable=False, server_default='1')

    # User authentication information. The collation='NOCASE' is required
    # to search case insensitively when USER_IFIND_MODE is 'nocase_collation'.
    email = db.Column(db.String(255, collation='NOCASE'), nullable=False, unique=True)
    email_confirmed_at = db.Column(db.DateTime())
    password = db.Column(db.String(255), nullable=False, server_default='')

    # User information
    first_name = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
    last_name = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')

    # Define the relationship to Role via UserRoles
    roles = db.relationship('Role', secondary='user_roles')


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(50), unique=True)


class UserRoles(db.Model):
    __tablename__ = 'user_roles'
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('users.id', ondelete='CASCADE'))
    role_id = db.Column(db.Integer(), db.ForeignKey('roles.id', ondelete='CASCADE'))


with app.app_context():
    db.create_all()

# user_manager = UserManager(app, db, User)

with app.app_context():
    # Create 'admin@example.com' user with 'Admin' and 'Agent' roles

    if not User.query.filter(User.email == 'admin@example.com').first():
        user = User(
            username='admin',
            email='admin@example.com',
            email_confirmed_at=datetime.datetime.utcnow(),
            password=generate_password_hash('Password1'),
        )
        user.roles.append(Role(name=messages.ROLENAME_FOR_ADMIN))
        user.roles.append(Role(name=messages.ROLENAME_FOR_READ))
        user.roles.append(Role(name=messages.ROLENAME_FOR_DELETE))
        user.roles.append(Role(name=messages.ROLENAME_FOR_CHANGE))
        user.roles.append(Role(name=messages.ROLENAME_FOR_CREATE))

        db.session.add(user)
        db.session.commit()

    # Create 'member@example.com' user with no roles
    if not User.query.filter(User.email == 'member@example.com').first():
        user = User(
            username='member',
            email='member@example.com',
            email_confirmed_at=datetime.datetime.utcnow(),
            password=generate_password_hash('Password1'),
        )
        # user.roles.append(Role(name='User'))
        db.session.add(user)
        db.session.commit()


def role_checker(User, Role):
    user_rollen = get_roles(User)

    if Role in user_rollen:
        return True
    else:
        False


def get_roles(User):
    rollen = User.roles
    user_roles = []
    for role in rollen:
        user_roles.append(role.name)
    return user_roles


#################################################################################
############################## DEFINITIONS ######################################
#################################################################################
admin = messages.ROLENAME_FOR_ADMIN
read = messages.ROLENAME_FOR_READ
create = messages.ROLENAME_FOR_CREATE
delete = messages.ROLENAME_FOR_DELETE
change = messages.ROLENAME_FOR_CHANGE
#################################################################################

#################################################################################
#################################   LOGIN-PAGE   ################################
#################################################################################
@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = model.LoginForm()
    form.submit.label.text = messages.LOGIN_BUTTON_TEXT
    form.password.label.text = messages.LABEL_FOR_PASSWORD
    form.username.label.text = messages.LABEL_FOR_USERNAME
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                flash(messages.LOGIN_SUCCESS)
                return redirect(url_for('show_dashboard'))
            else:
                flash(messages.LOGIN_FAILED)
        else:
            flash(messages.LOGIN_FAILED)

    return render_template('base/login.html', form=form)


#################################################################################


##################################################################################
###################################   LOGOUT   ###################################
##################################################################################
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


#################################################################################


#################################################################################
################################   DASHBOARD   ##################################
#################################################################################
@app.route("/dashboard")
@login_required
def show_dashboard():
    if role_checker(current_user, read):

        # Userstats:
        user_query = User.query.order_by(User.id)
        alle_user = [u for u in user_query]
        alle_admins = []
        for user in user_query:
            if role_checker(user, messages.ROLENAME_FOR_ADMIN):
                alle_admins.append(user)

        return render_template("dashboards/dashboard.html", user=len(alle_user), admins=len(alle_admins))
    else:
        return render_template("base/error.html", header=messages.ERROR_HEADER, error_message=messages.ACCESS_DENIED)


#################################################################################


#################################################################################
#################################   MENUE 2   ###################################
#################################################################################
@app.route("/menu2")
@login_required
def show_menu2():
    if role_checker(current_user, admin):
        return render_template("dashboards/menu2.html")
    else:
        return render_template("base/error.html", header=messages.ERROR_HEADER, error_message=messages.ACCESS_DENIED)


#################################################################################


#################################################################################
#########################   BENUTZERPROFIL ANZEIGEN   ###########################
#################################################################################
@app.route("/profil/<int:user_id>", methods=['GET', 'POST'])
@login_required
def show_profile(user_id):
    if user_id == current_user.id or role_checker(current_user, admin):
        user = User.query.get(user_id)
        id = user.id
        name = user.username
        roles = get_roles(user)
        email = user.email
        firstname = user.first_name
        lastname = user.last_name

        userform = model.UserForm()
        userform.id.data = id
        userform.id.label.text = "Id"

        userform.username.data = name
        userform.username.label.text = messages.LABEL_FOR_USERNAME

        userform.email.data = email
        userform.email.label.text = messages.LABEL_FOR_EMAIL

        userform.first_name.data = firstname
        userform.first_name.label.text = messages.LABEL_FOR_FIRST_NAME

        userform.last_name.data = lastname
        userform.last_name.label.text = messages.LABEL_FOR_LAST_NAME

        userform.submit1.label.text = messages.LABEL_FOR_UPDATE_USERPROFILE_BUTTON

        userform.roles = roles

        if userform.validate_on_submit() and userform.submit1.data:
            user1 = user
            user1.email = request.form['email']
            user1.first_name = request.form['first_name']
            user1.last_name = request.form['last_name']
            db.session.commit()
            flash(messages.UPDATE_USERPROFILE_SUCCESS)
            return redirect(url_for('show_profile', user_id=id))

        form = model.ChangePasswordForm()
        form.password.label.text = messages.LABEL_FOR_PASSWORD
        form.confirm.label.text = messages.LABEL_FOR_PASSWORD_CONFIRM
        form.submit.label.text = messages.LABEL_FOR_CHANGE_PASSWORD_BUTTON

        if form.validate_on_submit() and form.submit.data:
            if form.password.data == form.confirm.data:
                pwd = generate_password_hash(form.password.data)
                user2 = user
                user2.password = pwd
                db.session.commit()
                flash(messages.PASSWORD_CHANGE_SUCCESS)
                return redirect(url_for('show_profile', user_id=id))
            else:
                flash(messages.PASSWORD_CHANGE_FAILED)
                return redirect(url_for('show_profile', user_id=id))

        return render_template("profile/profile.html", userform=userform, form=form, name=name, roles=roles, email=email,
                               firstname=firstname, lastname=lastname)
    else:
        return render_template("base/error.html", header=messages.ERROR_HEADER, error_message=messages.ACCESS_DENIED)
    #################################################################################


#################################################################################
################################   ADMINBEREICH   ###############################
#################################################################################

############################   BENUTZER ANLEGEN   ##############################
@app.route('/admin/register', methods=['GET', 'POST'])
@login_required
def register():
    if role_checker(current_user, admin):
        form = model.RegistrationForm()
        form.email.label.text = messages.LABEL_FOR_EMAIL
        form.username.label.text = messages.LABEL_FOR_USERNAME
        form.password.label.text = messages.LABEL_FOR_PASSWORD

        if form.validate_on_submit():
            new_user = User(
                username=form.username.data,
                email=form.email.data,
                email_confirmed_at=datetime.datetime.utcnow(),
                password=generate_password_hash(form.password.data),
            )
            user_name = new_user.username
            user_email = new_user.email
            with app.app_context():
                db.session.add(new_user)
                db.session.commit()
            flash(messages.USER_ADDED.format(user_name, user_email))
            return redirect(url_for('register'))
        return render_template('admin/register_user.html', form=form)
    else:
        return render_template("base/error.html", header=messages.ERROR_HEADER, error_message=messages.ACCESS_DENIED)

############################   BENUTZER BEARBEITEN   ##############################
@app.route('/admin/update_user', methods=['GET', 'POST'])
@login_required
def show_update_user():
    if role_checker(current_user, admin):
        all_users = User.query.order_by(User.username)
        user_list = []
        for u in all_users:
            username = u.username
            email = u.email
            firstname = u.first_name
            lastname = u.last_name
            roles = get_roles(u)
            id = u.id
            user_list.append([username, email, firstname, lastname, roles, id])
        return render_template("admin/update_user.html", user_and_role_list=user_list)
    else:
        return render_template("base/error.html", header=messages.ERROR_HEADER, error_message=messages.ACCESS_DENIED)


############################   BENUTZER LÖSCHEN   ##############################
@app.route('/admin/delete/<int:user_id>', methods=['GET', 'POST'])
@login_required
def show_delete_user(user_id):
    if role_checker(current_user, admin):
        user_to_delete = User.query.get(user_id)
        print(user_to_delete.id)
        print(current_user.id)
        if user_to_delete.id != current_user.id:
            try:
                db.session.delete(user_to_delete)
                db.session.commit()
                flash(messages.USER_DELETE_SUCCESS)
                return redirect(url_for('show_update_user'))

            except:
                return render_template("base/error.html", header=messages.ERROR_HEADER,
                                       error_message=messages.USER_DELETE_FAILED)
        else:
            return render_template("base/error.html", header=messages.ERROR_HEADER,
                                   error_message=messages.USER_DELETE_FAILED_OWN_USER)
    else:
        return render_template("base/error.html", header=messages.ERROR_HEADER, error_message=messages.ACCESS_DENIED)


###########################   BERECHTIGUNGSÜBERSICHT   ###########################
@app.route('/admin/usermanagement', methods=['GET', 'POST'])
@login_required
def show_usermanagement():
    if role_checker(current_user, admin):
        # hole alle Rollen aus Datenbank
        all_roles = Role.query.order_by(Role.id)
        role_list = []
        for role in all_roles:
            role_list.append(role.name)

        # hole alle User und ihre Rollen aus der Datenbank
        all_users = User.query.order_by(User.username)
        user_and_roles_list = []
        for user in all_users:
            roles = get_roles(user)
            user_roles = []
            for role in role_list:
                if role in roles:
                    user_roles.append([role, "checked"])
                else:
                    user_roles.append([role, ""])
            user_and_roles_list.append([user.username, user_roles, user.id])

        return render_template('admin/usermanagement.html', role_list=role_list, user_and_roles_list=user_and_roles_list)
    else:
        return render_template("base/error.html", header=messages.ERROR_HEADER, error_message=messages.ACCESS_DENIED)


######################   BENUTZERBERECHTIGUNGEN ANPASSEN   ##########################
@app.route('/admin/usermanagement/userroles/<int:id>', methods=['GET', 'POST'])
@login_required
def update_user_roles(id):
    admin = messages.ROLENAME_FOR_ADMIN # keine Ahnung warum ich das hier nochmal referenzieren muss
    if role_checker(current_user, admin):
        # form = model.UserRolesForm()
        role_list = []
        user = User.query.get(id)
        roles = get_roles(user)
        all_roles = Role.query.order_by(Role.id)
        for role in all_roles:
            if role.name in roles:
                role_list.append([role.name, "checked"])
            else:
                role_list.append([role.name, ""])

        if request.method == 'POST':
            admin = request.form.get('Admin')
            read = request.form.get('Read')
            delete = request.form.get('Delete')
            change = request.form.get('Change')
            create = request.form.get('Create')
            new_roles = [admin, read, delete, change, create]

            # delete all roles
            roles_of_user = UserRoles.query.filter_by(user_id=user.id)
            for i in roles_of_user:
                db.session.delete(i)
                db.session.commit()

            # add new roles
            for role in new_roles:
                if role != None:
                    userrole = UserRoles()
                    test = Role.query.filter_by(name=role)
                    for i in test:
                        userrole.role_id = i.id
                        userrole.user_id = id
                        db.session.add(userrole)
                        db.session.commit()

            return redirect(url_for('show_usermanagement'))

        return render_template('admin/userroles.html', username=user.username, role_list=role_list)  # , form=form)
    else:
        return render_template("base/error.html", header=messages.ERROR_HEADER, error_message=messages.ACCESS_DENIED)


#################################################################################


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5500, debug=True)
