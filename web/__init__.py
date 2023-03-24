from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_ldap3_login import LDAP3LoginManager

# init SQLAlchemy so we can use it later in our models
db = SQLAlchemy()
users = {}

def create_app():
    app = Flask(__name__)

    app.config['SECRET_KEY'] = 'SAGGAF1245'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'

    app.config['LDAP_HOST'] = '172.30.0.215'


    # Base DN of your directory
    app.config['LDAP_BASE_DN'] = 'DC=testdnp,DC=go,DC=th'

    # Users DN to be prepended to the Base DN
    app.config['LDAP_USER_DN'] = 'ou=TOR,ou=DNP'

    # Groups DN to be prepended to the Base DN
    # app.config['LDAP_GROUP_DN'] = 'ou=User DNP,ou=DNP'

    # The RDN attribute for your user schema on LDAP
    app.config['LDAP_USER_RDN_ATTR'] = 'cn'

    # The Attribute you want users to authenticate to LDAP with.
    app.config['LDAP_USER_LOGIN_ATTR'] = 'cn'

    # The Username to bind to LDAP with
    app.config['LDAP_BIND_USER_DN'] = 'itadmin'

    # The Password to bind to LDAP with
    app.config['LDAP_BIND_USER_PASSWORD'] = 'Siemens#123'

    db.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    ldap_manager = LDAP3LoginManager()
    ldap_manager.init_app(app)

    from .models import User

    @login_manager.user_loader
    def load_user(id):
        if id in users:
            return users[id]
        return None

    @ldap_manager.save_user
    def save_user(dn, username, data, memberships):
        user = User(dn, username, data)
        users[dn] = user
        print(users)
        return user
    
    # blueprint for auth routes in our app
    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    # blueprint for non-auth parts of app
    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    
    return app
