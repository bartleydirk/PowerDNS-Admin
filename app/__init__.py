"""
Application for managing Power Dns via API protocol.

Flask application built to use Sqlalchemy internally and the pdns api
to make changes to pdns
"""
import os
from distutils.version import StrictVersion

from ConfigParser import RawConfigParser
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from werkzeug.contrib.fixers import ProxyFix
from flask import Flask, request, session, redirect, url_for


# pylint: disable=C0103,C0413
app = Flask(__name__)
app.config.from_object('config')
app.wsgi_app = ProxyFix(app.wsgi_app)

login_manager = LoginManager()
login_manager.init_app(app)
db = SQLAlchemy(app)

if 'LDAP_TYPE' in app.config.keys():
    LDAP_URI = app.config['LDAP_URI']
    LDAP_USERNAME = app.config['LDAP_USERNAME']
    LDAP_PASSWORD = app.config['LDAP_PASSWORD']
    LDAP_SEARCH_BASE = app.config['LDAP_SEARCH_BASE']
    LDAP_TYPE = app.config['LDAP_TYPE']
    LDAP_FILTER = app.config['LDAP_FILTER']
    LDAP_USERNAMEFIELD = app.config['LDAP_USERNAMEFIELD']
else:
    LDAP_TYPE = False

if 'PRETTY_IPV6_PTR' in app.config.keys():
    # import dns.inet
    # import dns.name
    PRETTY_IPV6_PTR = app.config['PRETTY_IPV6_PTR']
else:
    PRETTY_IPV6_PTR = False

PDNS_STATS_URL = app.config['PDNS_STATS_URL']
PDNS_API_KEY = app.config['PDNS_API_KEY']
PDNS_VERSION = app.config['PDNS_VERSION']

NEW_SCHEMA = bool(StrictVersion(PDNS_VERSION) >= StrictVersion('4.0.0'))


from app.lib import utils
from app.lib.log import logger
LOGGING = logger('MODEL', app.config['LOG_LEVEL'], app.config['LOG_FILE']).config()
API_EXTENDED_URL = utils.pdns_api_extended_uri(PDNS_VERSION)


class PdnsParser(RawConfigParser):
    """A class to inherit from RawConfigParser.

    Created to have safe methods to get values
    So that the config file can not have the value and there will be a default
    """

    def safe_get(self, section, option, default=None):
        """Safe Get Method."""
        retval = None
        if self.has_option(section, option):
            retval = self.get(section, option)
        else:
            retval = default
        return retval

    def safe_getboolean(self, section, option, default=False):
        """Safe Get a boolean value Method."""
        retval = None
        if self.has_option(section, option):
            retval = self.getboolean(section, option)
        else:
            retval = default
        return retval


def get_version(infile):
    """We wanna return the value in the constant dictionary."""
    # exepth = os.path.dirname(os.path.realpath(__file__))
    pth = os.path.join(os.path.dirname(__file__), '..')
    cnfgfle = '%s/versions.cfg' % os.path.abspath(pth)
    confg = PdnsParser()
    confg.read(cnfgfle)
    return confg.safe_get('vers', infile, 1)


@app.context_processor
def utility_processor():
    """Method for easing browser loading of changed css and js files."""
    def url_for_static(file_name):
        """Method to return the url for a static file and appends a version parameter if one exists."""
        basename = os.path.basename(file_name)
        version = get_version(basename)
        if version:
            return url_for('static', filename=file_name, ver=version)
        return url_for('static', filename=file_name)
    return dict(url_for_static=url_for_static)


def enable_github_oauth(GITHUB_ENABLE):
    """Enable Github Authorization."""
    # pylint: disable=W0612
    if not GITHUB_ENABLE:
        return None, None
    from flask_oauthlib.client import OAuth
    oauth_ = OAuth(app)
    github_ = oauth_.remote_app(
        'github',
        consumer_key=app.config['GITHUB_OAUTH_KEY'],
        consumer_secret=app.config['GITHUB_OAUTH_SECRET'],
        request_token_params={'scope': app.config['GITHUB_OAUTH_SCOPE']},
        base_url=app.config['GITHUB_OAUTH_URL'],
        request_token_url=None,
        access_token_method='POST',
        access_token_url=app.config['GITHUB_OAUTH_TOKEN'],
        authorize_url=app.config['GITHUB_OAUTH_AUTHORIZE']
    )

    @app.route('/user/authorized')
    def authorized():
        """Test if the user is autorized, redirect if not."""
        session['github_oauthredir'] = url_for('.authorized', _external=True)
        resp = github_.authorized_response()
        if resp is None:
            return 'Access denied: reason=%s error=%s' % (
                request.args['error'],
                request.args['error_description']
            )
        session['github_token'] = (resp['access_token'], '')
        return redirect(url_for('.login'))

    @github.tokengetter
    def get_github_oauth_token():
        """Helper to get token."""
        return session.get('github_token')

    return oauth_, github_


oauth, github = enable_github_oauth(app.config.get('GITHUB_OAUTH_ENABLE'))
from app import base, models, views, history, api
