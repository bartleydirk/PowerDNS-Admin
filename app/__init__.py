"""
Application for managing Power Dns via API protocol
"""

import os
from distutils.version import StrictVersion

from ConfigParser import RawConfigParser
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from werkzeug.contrib.fixers import ProxyFix
from flask import Flask, request, session, redirect, url_for

from app import base, views, models, history
from .base import PDNS_VERSION

# pylint: disable=C0103
app = Flask(__name__)
app.config.from_object('config')
app.wsgi_app = ProxyFix(app.wsgi_app)

login_manager = LoginManager()
login_manager.init_app(app)
db = SQLAlchemy(app)
NEW_SCHEMA = bool(StrictVersion(PDNS_VERSION) >= StrictVersion('4.0.0'))


class PdnsParser(RawConfigParser):
    """
    A class to inherit from RawConfigParser and have safe methods to get values
    So that the config file can not have the value and there will be a default
    """
    def safe_get(self, section, option, default=None):
        """ Safe Get Method """
        retval = None
        if self.has_option(section, option):
            retval = self.get(section, option)
        else:
            retval = default
        return retval

    def safe_getboolean(self, section, option, default=False):
        """ Safe Get a boolean value Method """
        retval = None
        if self.has_option(section, option):
            retval = self.getboolean(section, option)
        else:
            retval = default
        return retval


def get_version(infile):
    """ We wanna return the value in the constant dictionary """
    # exepth = os.path.dirname(os.path.realpath(__file__))
    pth = os.path.join(os.path.dirname(__file__), '..')
    cnfgfle = '%s/versions.cfg' % os.path.abspath(pth)
    confg = PdnsParser()
    confg.read(cnfgfle)
    return confg.safe_get('vers', infile, 1)


@app.context_processor
def utility_processor():
    """Method for easing browser loading of changed css and js files"""
    def url_for_static(file_name):
        """ Returns the url for a static file and appends a version parameter if one exists """
        basename = os.path.basename(file_name)
        version = get_version(basename)
        if version:
            return url_for('static', filename=file_name, ver=version)
        return url_for('static', filename=file_name)
    return dict(url_for_static=url_for_static)


def enable_github_oauth(GITHUB_ENABLE):
    """Enable Github Authorization"""
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
        """Is the user autorized, redirect if not"""
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
        """Helper to get token"""
        return session.get('github_token')

    return oauth_, github_


oauth, github = enable_github_oauth(app.config.get('GITHUB_OAUTH_ENABLE'))
