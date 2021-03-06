"""Views for the Power DNS Admin application."""
# pylint: disable=E1101,E0611,E0401
import base64
import json
import os
import traceback
import re
from distutils.util import strtobool
from functools import wraps
from io import BytesIO

import jinja2
import qrcode as qrc
import qrcode.image.svg as qrc_svg

from flask_login import login_user, logout_user, current_user, login_required
from werkzeug import secure_filename
from werkzeug.security import gen_salt
from flask import g, request, make_response, jsonify, render_template, session, redirect, url_for, \
    send_from_directory, abort

from app import app, login_manager, github, db, NEW_SCHEMA  # , LOGGING
from app.lib import utils
from app.models import User, Domain, History, Setting, DomainSetting
from app.base import Record, Server, Anonymous, booleanval, allowed_domains, is_allowed_domain, DisplayUserAcls, \
    query_acldomains_fromuser


jinja2.filters.FILTERS['display_record_name'] = utils.display_record_name
jinja2.filters.FILTERS['display_master_name'] = utils.display_master_name
jinja2.filters.FILTERS['display_second_to_time'] = utils.display_time
jinja2.filters.FILTERS['email_to_gravatar_url'] = utils.email_to_gravatar_url
# pylint: disable=C0103,W0703,R1705


@app.context_processor
def inject_fullscreen_layout_setting():
    """Inject Fullscreen Layout."""
    fullscreen_layout_setting = Setting.query.filter(Setting.name == 'fullscreen_layout').first()
    return dict(fullscreen_layout_setting=strtobool(fullscreen_layout_setting.value))


@app.context_processor
def inject_record_helper_setting():
    """Inject Record Helper."""
    record_helper_setting = Setting.query.filter(Setting.name == 'record_helper').first()
    return dict(record_helper_setting=strtobool(record_helper_setting.value))


@app.context_processor
def inject_login_ldap_first_setting():
    """Inject Login Ldap."""
    login_ldap_first_setting = Setting.query.filter(Setting.name == 'login_ldap_first').first()
    return dict(login_ldap_first_setting=strtobool(login_ldap_first_setting.value))


@app.context_processor
def inject_default_record_table_size_setting():
    """Inject Default Record Table Size."""
    default_record_table_size_setting = Setting.query.filter(Setting.name == 'default_record_table_size').first()
    return dict(default_record_table_size_setting=default_record_table_size_setting.value)


@app.context_processor
def inject_default_domain_table_size_setting():
    """Inject Default Domain Table Size."""
    default_domain_table_size_setting = Setting.query.filter(Setting.name == 'default_domain_table_size').first()
    return dict(default_domain_table_size_setting=default_domain_table_size_setting.value)


@app.context_processor
def inject_auto_ptr_setting():
    """Inject Auto Ptr."""
    auto_ptr_setting = Setting.query.filter(Setting.name == 'auto_ptr').first()
    return dict(auto_ptr_setting=strtobool(auto_ptr_setting.value))


# START USER AUTHENTICATION HANDLER
@app.before_request
def before_request():
    """check site maintenance mode first."""
    # pylint: disable=R1710
    maintenance = Setting.query.filter(Setting.name == 'maintenance').first()
    if maintenance and maintenance.value == 'True':
        retval = render_template('maintenance.html')
        return retval

    # check if user is anonymous
    g.user = current_user
    login_manager.anonymous_user = Anonymous
    return None


@login_manager.user_loader
def load_user(id_):
    """The current user."""
    return User.query.get(int(id_))


def dyndns_login_required(f):
    """Dynamic dns login required."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        """Decorated function."""
        if current_user.is_authenticated is False:
            return render_template('dyndns.html', response='badauth'), 200
        return f(*args, **kwargs)
    return decorated_function


@login_manager.request_loader
def login_via_authorization_header(request_):
    """Flask Method Defining behavior."""
    auth_header = request_.headers.get('Authorization')
    if auth_header:
        auth_header = auth_header.replace('Basic ', '', 1)
        try:
            auth_header = base64.b64decode(auth_header)
            username, password = auth_header.split(":")
        except TypeError, err:
            # pylint: disable=E1126
            error_ = err.message['desc'] if 'desc' in err.message else err
            return error_
        user = User(username=username, password=password, plain_text_password=password)
        try:
            if not user.is_validate(method='LOCAL'):
                return None
            else:
                login_user(user, remember=False)
                return user
        except Exception:
            return None
    return None

# END USER AUTHENTICATION HANDLER


# START CUSTOMIZE DECORATORS
def admin_role_required(f):
    """An admin role is required."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        """Decorated Function."""
        if g.user.role.name != 'Administrator':
            return redirect(url_for('error', code=401))
        return f(*args, **kwargs)
    return decorated_function


def domain_permission_required(f):
    """Permission to the domain is required."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        """Decorated Function."""
        if g.user.role.name == 'Administrator':
            return f(*args, **kwargs)
        if 'domain_name' in kwargs:
            domain_name = kwargs['domain_name']
            if is_allowed_domain(domain_name, current_user.id, checkrole=False):
                return f(*args, **kwargs)
            else:
                return redirect(url_for('error', code=401))
        else:
            return f(*args, **kwargs)
        return f(*args, **kwargs)
    return decorated_function
# END CUSTOMIZE DECORATORS


# START VIEWS
@app.errorhandler(400)
def http_bad_request(_):
    """Bad Request handler."""
    return redirect(url_for('error', code=400))


@app.errorhandler(401)
def http_unauthorized(_):
    """Unauthorized handler."""
    return redirect(url_for('error', code=401))


@app.errorhandler(404)
def http_internal_server_error(_):
    """Server Error Handler."""
    return redirect(url_for('error', code=404))


@app.errorhandler(500)
def http_page_not_found(_):
    """Page Not Found Handler."""
    return redirect(url_for('error', code=500))


@app.route('/error/<string:code>')
def error(code, msg=None):
    """Error handler."""
    supported_code = ('400', '401', '404', '500')
    if code in supported_code:
        return render_template('errors/%s.html' % code, msg=msg), int(code)
    else:
        return render_template('errors/404.html'), 404


@app.route('/register', methods=['GET'])
def register():
    """Register if allowed."""
    SIGNUP_ENABLED = app.config['SIGNUP_ENABLED']
    if SIGNUP_ENABLED:
        return render_template('register.html')
    else:
        return render_template('errors/404.html'), 404


@app.route('/github/login')
def github_login():
    """Github Login."""
    if not app.config.get('GITHUB_OAUTH_ENABLE'):
        return abort(400)
    return github.authorize(callback=url_for('authorized', _external=True))


@app.route('/login', methods=['GET', 'POST'])
@login_manager.unauthorized_handler
def login():
    """Login Route."""
    # these parameters will be needed in multiple paths
    # pylint: disable=R0912,E1126,R0914,R0911
    LDAP_ENABLED = True if 'LDAP_TYPE' in app.config.keys() else False
    LOGIN_TITLE = app.config['LOGIN_TITLE'] if 'LOGIN_TITLE' in app.config.keys() else ''
    BASIC_ENABLED = app.config['BASIC_ENABLED']
    SIGNUP_ENABLED = app.config['SIGNUP_ENABLED']
    GITHUB_ENABLE = app.config.get('GITHUB_OAUTH_ENABLE')

    if g.user is not None and current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if 'github_token' in session:
        me = github.get('user')
        user_info = me.data
        user = User.query.filter_by(username=user_info['name']).first()
        if not user:
            # create user
            user = User(username=user_info['name'],
                        plain_text_password=gen_salt(7),
                        email=user_info['email'])
            user.create_local_user()

        session['user_id'] = user.id
        login_user(user, remember=False)
        return redirect(url_for('index'))

    if request.method == 'GET':
        return render_template('login.html',
                               github_enabled=GITHUB_ENABLE,
                               ldap_enabled=LDAP_ENABLED, login_title=LOGIN_TITLE,
                               basic_enabled=BASIC_ENABLED, signup_enabled=SIGNUP_ENABLED)

    # process login
    username = request.form['username']
    password = request.form['password']
    otp_token = request.form.get('otptoken')
    auth_method = request.form.get('auth_method', 'LOCAL')

    # addition fields for registration case
    firstname = request.form.get('firstname')
    lastname = request.form.get('lastname')
    email = request.form.get('email')
    rpassword = request.form.get('rpassword')

    if None in [firstname, lastname, email]:
        # login case
        remember_me = False
        if 'remember' in request.form:
            remember_me = True

        user = User(username=username, password=password, plain_text_password=password)

        # pylint: disable=E1126
        try:
            auth = user.is_validate(method=auth_method)
            if not auth:
                return render_template('login.html', error='Invalid credentials', ldap_enabled=LDAP_ENABLED,
                                       login_title=LOGIN_TITLE, basic_enabled=BASIC_ENABLED,
                                       signup_enabled=SIGNUP_ENABLED)
        except Exception, e:
            err_ = e.message['desc'] if 'desc' in e.message else e
            return render_template('login.html', error=err_, ldap_enabled=LDAP_ENABLED, login_title=LOGIN_TITLE,
                                   basic_enabled=BASIC_ENABLED, signup_enabled=SIGNUP_ENABLED)

        # check if user enabled OPT authentication
        if user.otp_secret:
            if otp_token:
                good_token = user.verify_totp(otp_token)
                if not good_token:
                    return render_template('login.html', error='Invalid credentials', ldap_enabled=LDAP_ENABLED,
                                           login_title=LOGIN_TITLE, basic_enabled=BASIC_ENABLED,
                                           signup_enabled=SIGNUP_ENABLED)
            else:
                return render_template('login.html', error='Token required', ldap_enabled=LDAP_ENABLED,
                                       login_title=LOGIN_TITLE, basic_enabled=BASIC_ENABLED,
                                       signup_enabled=SIGNUP_ENABLED)

        login_user(user, remember=remember_me)
        return redirect(request.args.get('next') or url_for('index'))
    else:
        # registration case
        user = User(username=username, plain_text_password=password, firstname=firstname, lastname=lastname,
                    email=email)

        # TO DO: Move this into the JavaScript
        # validate password and password confirmation
        if password != rpassword:
            error_ = "Passsword and confirmation do not match"
            return render_template('register.html', error=error_)

        try:
            result = user.create_local_user()
            if result:
                return render_template('login.html', username=username, password=password, ldap_enabled=LDAP_ENABLED,
                                       login_title=LOGIN_TITLE, basic_enabled=BASIC_ENABLED,
                                       signup_enabled=SIGNUP_ENABLED)
            else:
                return render_template('register.html', error=result)
        except Exception, e:
            return render_template('register.html', error=e.message['desc'] if 'desc' in e.message else e)


@app.route('/logout')
def logout():
    """Logout Flask Route."""
    session.pop('user_id', None)
    session.pop('github_token', None)
    logout_user()
    return redirect(url_for('login'))


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    """View for the dashboard."""
    # make sure local domain table is up to date with pdns
    Domain().update()
    domains = allowed_domains()

    # stats for dashboard
    domain_count = Domain.query.count()
    user_count = User.query.count()
    history_number = History.query.count()
    history = History.query.order_by(History.created_on.desc()).limit(4)
    server = Server(server_id='localhost')
    statistics = server.get_statistic()
    if statistics:
        # pylint: disable=W0110
        uptime = filter(lambda uptime: uptime['name'] == 'uptime', statistics)[0]['value']
    else:
        uptime = 0
    return render_template('dashboard.html', domains=domains, domain_count=domain_count, user_count=user_count,
                           history_number=history_number, uptime=uptime, histories=history)


# pylint: disable=W0621
@app.route('/domain/<path:domain_name>', methods=['GET', 'POST'])
@app.route('/domain', methods=['GET', 'POST'])
@login_required
@domain_permission_required
def domain(domain_name):
    """Domain Route, Listing the records."""
    # pylint: disable=R0914,R0912
    rec = Record()
    domain = Domain.query.filter(Domain.name == domain_name).first()
    if domain:
        # query domain info from PowerDNS API
        zone_info = rec.get_record_data(domain.name)
        if zone_info:
            jrecords = zone_info['records']
        else:
            # can not get any record, API server might be down
            return redirect(url_for('error', code=500))

        records = []
        # TO DO: This should be done in the "model" instead of "view"
        if NEW_SCHEMA:
            for jr in jrecords:
                if jr['type'] in app.config['RECORDS_ALLOW_EDIT']:
                    for subrecord in jr['records']:
                        record = Record(name=jr['name'], type=jr['type'],
                                        status='Disabled' if subrecord['disabled'] else 'Active',
                                        ttl=jr['ttl'], data=subrecord['content'])
                        records.append(record)
        else:
            for jr in jrecords:
                if jr['type'] in app.config['RECORDS_ALLOW_EDIT']:
                    record = Record(name=jr['name'], type=jr['type'],
                                    status='Disabled' if jr['disabled'] else 'Active',
                                    ttl=jr['ttl'], data=jr['content'])
                    records.append(record)
        if not re.search(r'ip6\.arpa|in-addr\.arpa$', domain_name):
            editable_records = app.config['RECORDS_ALLOW_EDIT']
        else:
            editable_records = ['PTR']
        sqry = db.session.query(Domain.id)\
                 .filter(Domain.name == domain.name)\
                 .first()
        hqry = db.session.query(db.func.REPLACE(History.name, r"\.$", "").label('name'),
                                db.func.count().label('count'))\
                 .filter(History.domain == sqry)\
                 .group_by(History.name)\
                 .all()
        lastdot = re.compile(r'\.$')
        hdict = {}
        for item in hqry:
            if item.name:
                name = lastdot.sub('', item.name)
                hdict[name] = item.count
        return render_template('domain.html', domain=domain, records=records, editable_records=editable_records,
                               hdict=hdict, rrsetid=rec.rrsetid)
    else:
        return redirect(url_for('error no domain', code=404))


@app.route('/admin/domain/add', methods=['GET', 'POST'])
@login_required
@admin_role_required
def domain_add():
    """Route to add a Domain."""
    # pylint: disable=R0914,R0912,
    # here here here
    if request.method == 'POST':
        try:
            domain_name = request.form.getlist('domain_name')[0]
            domain_type = request.form.getlist('radio_type')[0]
            soa_edit_api = request.form.getlist('radio_type_soa_edit_api')[0]

            if ' ' in domain_name or not domain_name or not domain_type:
                return render_template('errors/400.html', msg="Please correct your input"), 400

            if domain_type == 'slave':
                if request.form.getlist('domain_master_address'):
                    domain_master_string = request.form.getlist('domain_master_address')[0]
                    domain_master_string = domain_master_string.replace(' ', '')
                    domain_master_ips = domain_master_string.split(',')
            else:
                domain_master_ips = []
            d = Domain()
            result = d.add(domain_name=domain_name, domain_type=domain_type, soa_edit_api=soa_edit_api,
                           domain_master_ips=domain_master_ips)

            # The soa record will show a.misconfigured.powerdns.server
            rec = Record()
            recs = rec.get_record_data('pop')
            soacontent = None
            nsrecords = None
            nscontent = None
            for item in recs['records']:
                if item['name'] == 'pop' and item['type'] == 'SOA':
                    soacontent = item['content']
                if item['type'] == 'NS':
                    nsrecords = item['records']
                    nscontent = item['content']

            if soacontent:
                soarec = Record(name=domain_name, type='SOA', ttl=3600)
                soarec.update(domain_name, soacontent, username=current_user.username)
            if nsrecords and nscontent:
                for nsrec in nsrecords:
                    nsrec_ = Record(name=domain_name, type='NS', ttl=3600)
                    nsrec_.update(domain_name, nsrec['content'], username=current_user.username)
            # end update the record using pop as a base
            if result['status'] == 'ok':
                history = History(msg='Add domain %s' % domain_name,
                                  detail=str({'domain_type': domain_type, 'domain_master_ips': domain_master_ips}),
                                  created_by=current_user.username)
                history.add()
                return redirect(url_for('dashboard'))
            else:
                return render_template('errors/400.html', msg=result['msg']), 400
        except Exception:
            return redirect(url_for('error', code=500))
    return render_template('domain_add.html')


@app.route('/admin/domain/<string:domain_name>/delete', methods=['GET'])
@login_required
@admin_role_required
def domain_delete(domain_name):
    """Route to delete a domain."""
    d = Domain()
    result = d.delete(domain_name)

    if result['status'] == 'error':
        return redirect(url_for('error', code=500))

    history = History(msg='Delete domain %s' % domain_name, created_by=current_user.username)
    history.add()

    return redirect(url_for('dashboard'))


@app.route('/admin/domain/<string:domain_name>/manage', methods=['GET', 'POST'])
@login_required
@admin_role_required
def domain_management(domain_name):
    """Route to manage domain attributes."""
    if request.method == 'GET':
        domain = Domain.query.filter(Domain.name == domain_name).first()
        if not domain:
            return redirect(url_for('error', code=404))
        users = User.query.all()

        # get list of user ids to initilize selection data
        d = Domain(name=domain_name)
        domain_user_ids = d.get_user()

        return render_template('domain_management.html', domain=domain, users=users, domain_user_ids=domain_user_ids)

    if request.method == 'POST':
        # username in right column
        new_user_list = request.form.getlist('domain_multi_user[]')

        # get list of user ids to compare
        d = Domain(name=domain_name)
        domain_user_ids = d.get_user()

        # grant/revoke user privielges
        d.grant_privielges(new_user_list)

        history = History(msg='Change domain %s access control' % domain_name,
                          detail=str({'user_has_access': new_user_list}), created_by=current_user.username)
        history.add()

        return redirect(url_for('domain_management', domain_name=domain_name))

    return None


@app.route('/domain/<string:domain_name>/apply', methods=['POST'], strict_slashes=False)
@login_required
def record_apply(domain_name):
    """Apply Record.

    example jdata: {u'record_ttl': u'1800', u'record_type': u'CNAME', u'record_name': u'test4',
                    u'record_status': u'Active', u'record_data': u'duykhanh.me'}
    """
    # TO DO: filter removed records / name modified records.
    try:
        pdata = request.form.get('postdata')
        rrsetid = request.form.get('rrsetid', None)
        jdata = json.loads(pdata)
        # LOGGING.info('record_apply rrsetid %s ', pformat(jdata))
        rec = Record(rrsetid=rrsetid)
        result = rec.apply(domain_name, jdata)
        if result['status'] == 'ok':
            return make_response(jsonify(result), 200)
        else:
            return make_response(jsonify(result), 400)
    except Exception:
        print traceback.format_exc()
        return make_response(jsonify({'status': 'error', 'msg': 'Error when applying new changes'}), 500)


@app.route('/domain/<string:domain_name>/update', methods=['POST'], strict_slashes=False)
@login_required
def record_update(domain_name):
    """Route is used for domain work, Slave Zone only."""
    #  Pulling the records update from its Master
    try:
        pdata = request.data
        jdata = json.loads(pdata)

        domain_name = jdata['domain']
        d = Domain()
        result = d.update_from_master(domain_name)
        if result['status'] == 'ok':
            return make_response(jsonify({'status': 'ok', 'msg': result['msg']}), 200)
        else:
            return make_response(jsonify({'status': 'error', 'msg': result['msg']}), 500)
    except Exception:
        print traceback.format_exc()
        return make_response(jsonify({'status': 'error', 'msg': 'Error when reocrd_updating new changes'}), 500)


@app.route('/domain/<string:domain_name>/record/<string:record_name>/type/<string:record_type>/delete', methods=['GET'])
@login_required
@admin_role_required
def record_delete(domain_name, record_name, record_type):
    """View to delete a record."""
    try:
        r = Record(name=record_name, type=record_type)
        result = r.delete(domain=domain_name)
        if result['status'] == 'error':
            print result['msg']
    except Exception:
        print traceback.format_exc()
        return redirect(url_for('error', code=500)), 500
    return redirect(url_for('domain', domain_name=domain_name))


@app.route('/domain/<string:domain_name>/dnssec', methods=['GET'])
@login_required
def domain_dnssec(domain_name):
    """View to return dnssec."""
    domain = Domain()
    dnssec = domain.get_domain_dnssec(domain_name)
    return make_response(jsonify(dnssec), 200)


@app.route('/domain/<string:domain_name>/managesetting', methods=['GET', 'POST'])
@login_required
@admin_role_required
def admin_setdomainsetting(domain_name):
    """View Set Admin domain settings."""
    if request.method == 'POST':
        #
        # post data should in format
        # {'action': 'set_setting', 'setting': 'default_action, 'value': 'True'}
        #
        try:
            pdata = request.data
            jdata = json.loads(pdata)
            data = jdata['data']
            if jdata['action'] == 'set_setting':
                new_setting = data['setting']
                new_value = str(data['value'])
                domain = Domain.query.filter(Domain.name == domain_name).first()
                setting = DomainSetting.query.filter(DomainSetting.domain == domain)\
                                       .filter(DomainSetting.setting == new_setting)\
                                       .first()

                if setting:
                    if setting.set(new_value):
                        history = History(msg='Setting %s changed value to %s for %s'
                                          % (new_setting, new_value, domain.name),
                                          created_by=current_user.username)
                        history.add()
                        retval = make_response(jsonify({'status': 'ok', 'msg': 'Setting updated.'}))
                    else:
                        retval = make_response(jsonify({'status': 'error', 'msg': 'Unable to set value of setting.'}))
                else:
                    if domain.add_setting(new_setting, new_value):
                        history = History(msg='New setting %s with value %s for %s has been created'
                                          % (new_setting, new_value, domain.name), created_by=current_user.username)
                        history.add()
                        retval = make_response(jsonify({'status': 'ok', 'msg': 'New setting created and updated.'}))
                    else:
                        retval = make_response(jsonify({'status': 'error', 'msg': 'Unable to create new setting.'}))
            else:
                retval = make_response(jsonify({'status': 'error', 'msg': 'Action not supported.'}), 400)
        except Exception:
            print traceback.format_exc()
            retval = make_response(jsonify({'status': 'error',
                                            'msg': 'There is something wrong, please contact Administrator.'}), 400)
    return retval


@app.route('/admin', methods=['GET', 'POST'])
@login_required
@admin_role_required
def admin():
    """Admin View."""
    domains = Domain.query.all()
    users = User.query.all()

    server = Server(server_id='localhost')
    configs = server.get_config()
    statistics = server.get_statistic()
    history_number = History.query.count()

    if statistics:
        # pylint: disable=W0110
        uptime = filter(lambda uptime: uptime['name'] == 'uptime', statistics)[0]['value']
    else:
        uptime = 0

    return render_template('admin.html', domains=domains, users=users, configs=configs, statistics=statistics,
                           uptime=uptime, history_number=history_number)


@app.route('/admin/user/create', methods=['GET', 'POST'])
@login_required
@admin_role_required
def admin_createuser():
    """View to create a user."""
    if request.method == 'GET':
        retval = render_template('admin_createuser.html')

    elif request.method == 'POST':
        fdata = request.form

        user = User(username=fdata['username'], plain_text_password=fdata['password'], firstname=fdata['firstname'],
                    lastname=fdata['lastname'], email=fdata['email'])

        if fdata['password'] == "":
            return render_template('admin_createuser.html', user=user, blank_password=True)

        result = user.create_local_user()

        if result == 'Email already existed':
            retval = render_template('admin_createuser.html', user=user, duplicate_email=True)

        elif result == 'Username already existed':
            retval = render_template('admin_createuser.html', user=user, duplicate_username=True)

        else:
            retval = redirect(url_for('admin_manageuser'))
    return retval


@app.route('/admin/manageuser', methods=['GET', 'POST'])
@login_required
@admin_role_required
def admin_manageuser():
    """View to manage a user."""
    # pylint: disable=R0912,R0914
    retval = None
    if request.method == 'GET':
        # query all users
        users = db.session.query(User)\
                  .order_by(User.username)

        # use an instance of DisplayUserAcls to help with displaying what groups users are members of
        dua = DisplayUserAcls()

        retval = render_template('admin_manageuser.html', users=users, dua=dua)

    if request.method == 'POST':
        #
        # post data should in format
        # {'action': 'delete_user', 'data': 'username'}
        #
        try:
            action = request.form['action']
            username = request.form['username']
            if action == 'delete_user':
                user = User(username=username)
                result = user.delete()
                if result:
                    history = History(msg='Delete username %s' % username, created_by=current_user.username)
                    history.add()
                    retval = make_response(jsonify({'status': 'ok', 'msg': 'User has been removed.'}), 200)
                else:
                    retval = make_response(jsonify({'status': 'error', 'msg': 'Cannot remove user.'}), 500)

            elif action == 'revoke_user_privielges':
                user = User(username=username)
                result = user.revoke_privilege()
                if result:
                    history = History(msg='Revoke %s user privielges' % username, created_by=current_user.username)
                    history.add()
                    retval = make_response(jsonify({'status': 'ok', 'msg': 'Revoked user privielges.'}), 200)
                else:
                    retval = make_response(jsonify({'status': 'error', 'msg': 'Cannot revoke user privilege.'}), 500)

            elif action == 'set_admin':
                is_admin = request.form['is_admin']
                user = User(username=username)
                result = user.set_admin(booleanval(is_admin))
                if result:
                    history = History(msg='Change user role of %s' % username, created_by=current_user.username)
                    history.add()
                    retval = make_response(jsonify({'status': 'ok', 'msg': 'Changed user role successfully.'}), 200)
                else:
                    retval = make_response(jsonify({'status': 'error', 'msg': 'Cannot change user role.'}), 500)
            else:
                retval = make_response(jsonify({'status': 'error', 'msg': 'Action not supported.'}), 400)
        except Exception:
            print traceback.format_exc()
            retval = make_response(jsonify({'status': 'error',
                                            'msg': 'There is something wrong, please contact Administrator.'}), 400)
    return retval


@app.route('/admin/settings', methods=['GET'])
@login_required
@admin_role_required
def admin_settings():
    """View to return admin settings page."""
    if request.method == 'GET':
        settings = Setting.query.filter(Setting.name != 'maintenance')
        return render_template('admin_settings.html', settings=settings)
    return None


@app.route('/admin/setting/toggle', methods=['POST'])
@login_required
@admin_role_required
def admin_settings_toggle():
    """View to toggle an admin setting."""
    setting = request.form.get('setting')
    result = Setting().toggle(setting)
    if result:
        return make_response(jsonify({'status': 'ok', 'msg': 'Toggled setting successfully.'}), 200)
    else:
        return make_response(jsonify({'status': 'error', 'msg': 'Unable to toggle setting.'}), 500)


@app.route('/admin/setting/edit', methods=['POST'])
@login_required
@admin_role_required
def admin_settings_edit():
    """View to Edit Settings."""
    setting = request.form.get('setting')
    new_value = request.form.get('value')
    result = Setting().set(setting, new_value)
    if result:
        return make_response(jsonify({'status': 'ok', 'msg': 'Modified setting successfully.'}), 200)
    else:
        return make_response(jsonify({'status': 'error', 'msg': 'Unable to modify setting.'}), 500)


@app.route('/user/profile', methods=['GET', 'POST'])
@login_required
def user_profile():
    """View to edit user profile."""
    if request.method == 'GET':
        return render_template('user_profile.html')
    if request.method == 'POST':
        # get new profile info
        firstname = request.form['firstname'] if 'firstname' in request.form else ''
        lastname = request.form['lastname'] if 'lastname' in request.form else ''
        email = request.form['email'] if 'email' in request.form else ''
        new_password = request.form['password'] if 'password' in request.form else ''

        # json data
        if request.data:
            jdata = json.loads(request.data)
            data = jdata['data']
            if jdata['action'] == 'enable_otp':
                enable_otp = data['enable_otp']
                user = User(username=current_user.username)
                user.update_profile(enable_otp=enable_otp)
                return make_response(jsonify({'status': 'ok',
                                              'msg': 'Change OTP Authentication successfully Status: %s' % enable_otp}),
                                     200)

        # get new avatar
        save_file_name = None
        if 'file' in request.files:
            file_ = request.files['file']
            if file_:
                filename = secure_filename(file_.filename)
                file_extension = filename.rsplit('.', 1)[1]

                if file_extension.lower() in ['jpg', 'jpeg', 'png']:
                    save_file_name = current_user.username + '.' + file_extension
                    file_.save(os.path.join(app.config['UPLOAD_DIR'], 'avatar', save_file_name))

        # update user profile
        user = User(username=current_user.username, plain_text_password=new_password, firstname=firstname,
                    lastname=lastname, email=email, avatar=save_file_name, reload_info=False)
        user.update_profile()

        return render_template('user_profile.html')
    return None


@app.route('/user/avatar/<string:filename>')
def user_avatar(filename):
    """View to manage avatar."""
    return send_from_directory(os.path.join(app.config['UPLOAD_DIR'], 'avatar'), filename)


@app.route('/qrcode')
@login_required
def qrcode():
    """View to manage qrcode."""
    if not current_user:
        return redirect(url_for('index'))

    # render qrcode for FreeTOTP
    img = qrc.make(current_user.get_totp_uri(), image_factory=qrc_svg.SvgImage)
    stream = BytesIO()
    img.save(stream)
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@app.route('/nic/checkip.html', methods=['GET', 'POST'])
def dyndns_checkip():
    """route covers the default ddclient 'web' setting for the checkip service."""
    return render_template('dyndns.html', response=request.environ.get('HTTP_X_REAL_IP', request.remote_addr))


@app.route('/nic/update', methods=['GET', 'POST'])
@dyndns_login_required
def dyndns_update():
    """Dynamic Dns Update."""
    # pylint: disable=R0912,R0914
    # dyndns protocol response codes in use are:
    # good: update successful
    # nochg: IP address already set to update address
    # nohost: hostname does not exist for this user account
    # 911: server error
    # have to use 200 HTTP return codes because ddclient does not read the return string if the code is other than 200
    # reference: https://help.dyn.com/remote-access-api/perform-update/
    # reference: https://help.dyn.com/remote-access-api/return-codes/
    hostname = request.args.get('hostname')
    myip = request.args.get('myip')

    try:
        # get all domains owned by the current user
        domains = User(id=current_user.id).get_domain()
    except Exception:
        return render_template('dyndns.html', response='911'), 200

    domain = None
    domain_segments = hostname.split('.')
    for _ in range(len(domain_segments)):
        domain_segments.pop(0)
        full_domain = '.'.join(domain_segments)
        potential_domain = Domain.query.filter(Domain.name == full_domain).first()
        if potential_domain in domains:
            domain = potential_domain
            break

    if not domain:
        history = History(msg="DynDNS update: attempted update of %s but it does not exist for this user" % hostname,
                          created_by=current_user.username)
        history.add()
        return render_template('dyndns.html', response='nohost'), 200

    r = Record()
    r.name = hostname
    # check if the user requested record exists within this domain
    retval = None
    if r.exists(domain.name) and r.is_allowed:
        if r.data == myip:
            # record content did not change, return 'nochg'
            history = History(msg="DynDNS update: attempted update of %s but record did not change" % hostname,
                              created_by=current_user.username)
            history.add()
            retval = render_template('dyndns.html', response='nochg'), 200
        else:
            oldip = r.data
            result = r.update(domain.name, myip, username=current_user.username)
            if result['status'] == 'ok':
                msg = 'DynDNS update: updated record %s in zone %s, it changed from %s to %s' % \
                    (hostname, domain.name, oldip, myip)
                history = History(msg=msg, created_by=current_user.username)
                history.add()
                retval = render_template('dyndns.html', response='good'), 200
            else:
                retval = render_template('dyndns.html', response='911'), 200
    elif r.is_allowed:
        ondemand_creation = DomainSetting.query.filter(DomainSetting.domain == domain) \
                                               .filter(DomainSetting.setting == 'create_via_dyndns') \
                                               .first()
        if not ondemand_creation and strtobool(ondemand_creation.value):
            record = Record(name=hostname, type='A', data=myip, status=False, ttl=3600)
            result = record.add(domain.name)
            if result['status'] == 'ok':
                msg = 'DynDNS update: created record %s in zone %s, it now represents %s' % \
                    (hostname, domain.name, myip)
                history = History(msg=msg, detail=str(result), created_by=current_user.username)
                history.add()
                retval = render_template('dyndns.html', response='good'), 200
    if retval:
        return retval
    msg = "DynDNS update: attempted update of %s but it does not exist for this user" % hostname
    history = History(msg=msg, created_by=current_user.username)
    history.add()
    return render_template('dyndns.html', response='nohost'), 200


@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    """Index page, redirect to dashboard."""
    return redirect(url_for('dashboard'))


@app.route('/testme', methods=['GET', 'POST'])
def testme():
    """A Testing only route, to see if a change to acl logic has desired effect, which is no effect."""
    qry = db.session.query(User)
    test = {}
    for user in qry:
        qry2 = query_acldomains_fromuser(user.id)
        lst = []
        for item in qry2:
            lst.append(item.domain_id)
        test[user.id] = str(lst)
    return jsonify(test=test)
