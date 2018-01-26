"""
module to contain sqlalchemy models
"""

import os
import base64
import urlparse
import traceback
import re

from datetime import datetime
from distutils.util import strtobool

import pyotp
import ldap
import bcrypt

from sqlalchemy.dialects.mysql import JSON

from app import db
from app.lib import utils
from app import PDNS_STATS_URL, LDAP_URI, LDAP_USERNAME, LDAP_PASSWORD, LDAP_TYPE, LDAP_USERNAMEFIELD, LOGGING, \
    LDAP_FILTER, LDAP_SEARCH_BASE, PDNS_API_KEY, API_EXTENDED_URL, NEW_SCHEMA


# pylint: disable=W0703,R1705

class User(db.Model):
    """sqlalchmy model for a user"""
    # pylint: disable=C0103
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    password = db.Column(db.String(64))
    firstname = db.Column(db.String(64))
    lastname = db.Column(db.String(64))
    email = db.Column(db.String(128))
    avatar = db.Column(db.String(128))
    otp_secret = db.Column(db.String(16))
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))

    # pylint: disable=R0913,W0622
    def __init__(self, id=None, username=None, password=None, plain_text_password=None, firstname=None, lastname=None,
                 role_id=None, email=None, avatar=None, otp_secret=None, reload_info=True):
        self.id = id
        self.username = username
        self.password = password
        self.plain_text_password = plain_text_password
        self.firstname = firstname
        self.lastname = lastname
        self.role_id = role_id
        self.email = email
        self.avatar = avatar
        self.otp_secret = otp_secret

        if reload_info:
            user_info = self.get_user_info_by_id() if id else self.get_user_info_by_username()

            if user_info:
                self.id = user_info.id
                self.username = user_info.username
                self.firstname = user_info.firstname
                self.lastname = user_info.lastname
                self.email = user_info.email
                self.role_id = user_info.role_id
                self.otp_secret = user_info.otp_secret

    @classmethod
    def is_authenticated(cls):
        """Is the user authenticated"""
        return True

    @classmethod
    def is_active(cls):
        """Is the user active"""
        return True

    @classmethod
    def is_anonymous(cls):
        """Is the user anonymous"""
        return False

    def get_id(self):
        """Get the identifier helper function"""
        try:
            return unicode(self.id)  # python 2
        except NameError:
            return str(self.id)  # python 3

    def __repr__(self):
        return '<User %r>' % (self.username)

    def get_totp_uri(self):
        """Auth uri"""
        return 'otpauth://totp/PowerDNS-Admin:%s?secret=%s&issuer=PowerDNS-Admin' % (self.username, self.otp_secret)

    def verify_totp(self, token):
        """Veiry Token"""
        totp = pyotp.TOTP(self.otp_secret)
        return totp.verify(int(token))

    def get_hashed_password(self, plain_text_password=None):
        """Hashed password get"""
        # Hash a password for the first time
        #   (Using bcrypt, the salt is saved into the hash itself)
        pw = plain_text_password if plain_text_password else self.plain_text_password
        return bcrypt.hashpw(pw.encode('utf-8'), bcrypt.gensalt())

    def check_password(self, hashed_password):
        """Validate password"""
        # Check hased password. Useing bcrypt, the salt is saved into the hash itself
        return bcrypt.checkpw(self.plain_text_password.encode('utf-8'), hashed_password.encode('utf-8'))

    def get_user_info_by_id(self):
        """Retrieve a user by id"""
        user_info = User.query.get(int(self.id))
        return user_info

    def get_user_info_by_username(self):
        """Retrieve a user by name"""
        user_info = User.query.filter(User.username == self.username).first()
        return user_info

    @classmethod
    def ldap_search(cls, searchFilter, baseDN):
        """Search ldap"""
        searchScope = ldap.SCOPE_SUBTREE
        retrieveAttributes = None

        try:
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
            ldp = ldap.initialize(LDAP_URI)
            ldp.set_option(ldap.OPT_REFERRALS, 0)
            ldp.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
            ldp.set_option(ldap.OPT_X_TLS, ldap.OPT_X_TLS_DEMAND)
            ldp.set_option(ldap.OPT_X_TLS_DEMAND, True)
            ldp.set_option(ldap.OPT_DEBUG_LEVEL, 255)
            ldp.protocol_version = ldap.VERSION3

            ldp.simple_bind_s(LDAP_USERNAME, LDAP_PASSWORD)
            ldap_result_id = ldp.search(baseDN, searchScope, searchFilter, retrieveAttributes)
            result_set = []
            while 1:
                result_type, result_data = ldp.result(ldap_result_id, 0)
                if result_data == []:
                    break
                else:
                    if result_type == ldap.RES_SEARCH_ENTRY:
                        result_set.append(result_data)
            return result_set

        except ldap.LDAPError as err:
            LOGGING.error(err)
            raise Exception('Ldap error!')

    # pylint: disable=R0911
    def is_validate(self, method):
        """
        Validate user credential
        """
        if method == 'LOCAL':
            user_info = User.query.filter(User.username == self.username).first()

            if user_info:
                if user_info.password and self.check_password(user_info.password):
                    LOGGING.info('User "%s" logged in successfully', self.username)
                    return True
                LOGGING.error('User "%s" input a wrong password', self.username)
                return False

            LOGGING.warning('User "%s" does not exist', self.username)
            return False

        if method == 'LDAP':
            if not LDAP_TYPE:
                LOGGING.error('LDAP authentication is disabled')
                return False

            searchFilter = "(&(objectcategory=person)(samaccountname=%s))" % self.username
            if LDAP_TYPE == 'ldap':
                searchFilter = "(&(%s=%s)%s)" % (LDAP_USERNAMEFIELD, self.username, LDAP_FILTER)
                LOGGING.info('Ldap searchFilter "%s"', searchFilter)

            result = self.ldap_search(searchFilter, LDAP_SEARCH_BASE)
            if not result:
                LOGGING.warning('User "%s" does not exist', self.username)
                return False

            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
            ldp = ldap.initialize(LDAP_URI)
            ldp.set_option(ldap.OPT_REFERRALS, 0)
            ldp.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
            ldp.set_option(ldap.OPT_X_TLS, ldap. OPT_X_TLS_DEMAND)
            ldp.set_option(ldap.OPT_X_TLS_DEMAND, True)
            ldp.set_option(ldap.OPT_DEBUG_LEVEL, 255)
            ldp.protocol_version = ldap.VERSION3

            try:
                ldap_username = result[0][0][0]
                ldp.simple_bind_s(ldap_username, self.password)
                LOGGING.info('User "%s" logged in successfully', self.username)
            except Exception:
                LOGGING.error('User "%s" input a wrong password', self.username)
                return False

            # create user if not exist in the db
            if not User.query.filter(User.username == self.username).first():
                try:
                    # try to get user's firstname & lastname from LDAP
                    # this might be changed in the future
                    self.firstname = result[0][0][1]['givenName'][0]
                    self.lastname = result[0][0][1]['sn'][0]
                    self.email = result[0][0][1]['mail'][0]
                except Exception:
                    self.firstname = self.username
                    self.lastname = ''

                # first register user will be in Administrator role
                self.role_id = Role.query.filter_by(name='User').first().id
                if User.query.count() == 0:
                    self.role_id = Role.query.filter_by(name='Administrator').first().id

                self.create_user()
                LOGGING.info('Created user "%s" in the DB', self.username)

            return True

        LOGGING.error('Unsupported authentication method')
        return False

    def create_user(self):
        """
        If user logged in successfully via LDAP in the first time
        We will create a local user (in DB) in order to manage user
        profile such as name, roles,...
        """

        # Set an invalid password hash for non local users
        self.password = '*'
        db.session.add(self)
        db.session.commit()

    def create_local_user(self):
        """
        Create local user witch stores username / password in the DB
        """
        # check if username existed
        user = User.query.filter(User.username == self.username).first()
        if user:
            return 'Username already existed'

        # check if email existed
        user = User.query.filter(User.email == self.email).first()
        if user:
            return 'Email already existed'

        # first register user will be in Administrator role
        self.role_id = Role.query.filter_by(name='User').first().id
        if User.query.count() == 0:
            self.role_id = Role.query.filter_by(name='Administrator').first().id
        self.password = self.get_hashed_password(self.plain_text_password)

        db.session.add(self)
        db.session.commit()
        return True

    def update_profile(self, enable_otp=None):
        """
        Update user profile
        """

        user = User.query.filter(User.username == self.username).first()
        if not user:
            return False

        user.firstname = self.firstname if self.firstname else user.firstname
        user.lastname = self.lastname if self.lastname else user.lastname
        user.email = self.email if self.email else user.email
        user.password = self.get_hashed_password(self.plain_text_password) if self.plain_text_password \
            else user.password
        user.avatar = self.avatar if self.avatar else user.avatar

        user.otp_secret = ""
        if enable_otp is True:
            # generate the opt secret key
            user.otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')

        try:
            db.session.add(user)
            db.session.commit()
            return True
        except Exception:
            db.session.rollback()
            return False

    def get_domain(self):
        """
        Get domains which user has permission to
        access
        """
        user_domains = []
        query = db.session.query(User, DomainUser, Domain) \
                  .filter(User.id == self.id) \
                  .filter(User.id == DomainUser.user_id) \
                  .filter(Domain.id == DomainUser.domain_id).all()
        for q in query:
            user_domains.append(q[2])
        return user_domains

    def delete(self):
        """
        Delete a user
        """
        # revoke all user privileges first
        self.revoke_privilege()

        try:
            User.query.filter(User.username == self.username).delete()
            db.session.commit()
            return True
        except Exception:
            db.session.rollback()
            LOGGING.error('Cannot delete user %s from DB', self.username)
            return False

    def revoke_privilege(self):
        """
        Revoke all privielges from a user
        """
        user = User.query.filter(User.username == self.username).first()

        if user:
            user_id = user.id
            try:
                DomainUser.query.filter(DomainUser.user_id == user_id).delete()
                db.session.commit()
                return True
            except Exception:
                db.session.rollback()
                LOGGING.error('Cannot revoke user %s privielges.', self.username)
                return False
        return False

    def set_admin(self, is_admin):
        """
        Set role for a user:
            is_admin == True  => Administrator
            is_admin == False => User
        """
        user_role_name = 'Administrator' if is_admin else 'User'
        role = Role.query.filter(Role.name == user_role_name).first()

        try:
            if role:
                user = User.query.filter(User.username == self.username).first()
                user.role_id = role.id
                db.session.commit()
                return True
            else:
                return False
        except Exception:
            db.session.roleback()
            LOGGING.error('Cannot change user role in DB')
            LOGGING.debug(traceback.format_exc())
            return False


class Role(db.Model):
    """Model for roles defining privileges"""
    # pylint: disable=C0103,R0903
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), index=True, unique=True)
    description = db.Column(db.String(128))
    users = db.relationship('User', backref='role', lazy='dynamic')

    # pylint: disable=W0622
    def __init__(self, id=None, name=None, description=None):
        self.id = id
        self.name = name
        self.description = description

    def __repr__(self):
        return '<Role %r>' % (self.name)


class DomainSetting(db.Model):
    """Model for roles defining privileges"""
    # pylint: disable=C0103,R0903
    __tablename__ = 'domain_setting'
    id = db.Column(db.Integer, primary_key=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'))
    domain = db.relationship('Domain', back_populates='settings')
    setting = db.Column(db.String(255), nullable=False)
    value = db.Column(db.String(255))

    # pylint: disable=W0622
    def __init__(self, id=None, setting=None, value=None):
        self.id = id
        self.setting = setting
        self.value = value

    def __repr__(self):
        return '<DomainSetting %r for %d>' % (self.setting, self.domain.name)

    def __eq__(self, other):
        return self.setting == other.setting

    def set(self, value):
        """Set data to Database"""
        try:
            self.value = value
            db.session.commit()
            return True
        except Exception:
            LOGGING.error('Unable to set DomainSetting value')
            LOGGING.debug(traceback.format_exc())
            db.session.rollback()
            return False


class Domain(db.Model):
    """Model for Domain, database copy of what gets pulled from pdns via api"""
    # pylint: disable=C0103,R0913
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), index=True, unique=True)
    master = db.Column(db.String(128))
    type = db.Column(db.String(6), nullable=False)
    serial = db.Column(db.Integer)
    notified_serial = db.Column(db.Integer)
    last_check = db.Column(db.Integer)
    dnssec = db.Column(db.Integer)
    settings = db.relationship('DomainSetting', back_populates='domain')

    # pylint: disable=W0622
    def __init__(self, id=None, name=None, master=None, type='NATIVE', serial=None, notified_serial=None,
                 last_check=None, dnssec=None):
        self.id = id
        self.name = name
        self.master = master
        self.type = type
        self.serial = serial
        self.notified_serial = notified_serial
        self.last_check = last_check
        self.dnssec = dnssec

    def __repr__(self):
        return '<Domain %r>' % (self.name)

    def add_setting(self, setting, value):
        """Add a setting"""
        try:
            self.settings.append(DomainSetting(setting=setting, value=value))
            db.session.commit()
            return True
        except Exception as err:
            LOGGING.error('Can not create setting %s for domain %s. %s', setting, self.name, str(err))
            return False

    @classmethod
    def get_domains(cls):
        """
        Get all domains which has in PowerDNS
        jdata example:
            [
              {
                "id": "example.org.",
                "url": "/servers/localhost/zones/example.org.",
                "name": "example.org",
                "kind": "Native",
                "dnssec": false,
                "account": "",
                "masters": [],
                "serial": 2015101501,
                "notified_serial": 0,
                "last_check": 0
              }
            ]
        """
        headers = {}
        headers['X-API-Key'] = PDNS_API_KEY
        jdata = utils.fetch_json(urlparse.urljoin(PDNS_STATS_URL, API_EXTENDED_URL + '/servers/localhost/zones'),
                                 headers=headers)
        return jdata

    @classmethod
    def get_id_by_name(cls, name):
        """
        Return domain id
        """
        try:
            domain = Domain.query.filter(Domain.name == name).first()
            return domain.id
        except Exception:
            return None

    @classmethod
    def update(cls):
        """
        Fetch zones (domains) from PowerDNS and update into DB
        """
        # pylint: disable=R0915
        db_domain = Domain.query.all()
        list_db_domain = [d.name for d in db_domain]
        dict_db_domain = dict((x.name, x) for x in db_domain)

        headers = {}
        headers['X-API-Key'] = PDNS_API_KEY
        try:
            jdata = utils.fetch_json(urlparse.urljoin(PDNS_STATS_URL, API_EXTENDED_URL + '/servers/localhost/zones'),
                                     headers=headers)
            list_jdomain = [d['name'].rstrip('.') for d in jdata]
            try:
                # domains should remove from db since it doesn't exist in powerdns anymore
                should_removed_db_domain = list(set(list_db_domain).difference(list_jdomain))
                for d in should_removed_db_domain:
                    # revoke permission before delete domain
                    domain = Domain.query.filter(Domain.name == d).first()
                    domain_user = DomainUser.query.filter(DomainUser.domain_id == domain.id)
                    if domain_user:
                        domain_user.delete()
                        db.session.commit()
                    domain_setting = DomainSetting.query.filter(DomainSetting.domain_id == domain.id)
                    if domain_setting:
                        domain_setting.delete()
                        db.session.commit()

                    # then remove domain
                    Domain.query.filter(Domain.name == d).delete()
                    db.session.commit()
            except Exception:
                LOGGING.error('Can not delete domain from DB')
                LOGGING.debug(traceback.format_exc())
                db.session.rollback()

            # update/add new domain
            for data in jdata:
                d = dict_db_domain.get(data['name'].rstrip('.'), None)
                changed = False
                if d:
                    # existing domain, only update if something actually has changed
                    tst1 = 1 if data['last_check'] else 0
                    # pylint: disable=R0916
                    if (d.master != str(data['masters']) or d.type != data['kind'] or
                            d.serial != data['serial'] or d.notified_serial != data['notified_serial'] or
                            d.last_check != tst1 or d.dnssec != data['dnssec']):

                        d.master = str(data['masters'])
                        d.type = data['kind']
                        d.serial = data['serial']
                        d.notified_serial = data['notified_serial']
                        d.last_check = 1 if data['last_check'] else 0
                        d.dnssec = 1 if data['dnssec'] else 0
                        changed = True

                else:
                    # add new domain
                    d = Domain()
                    d.name = data['name'].rstrip('.')
                    d.master = str(data['masters'])
                    d.type = data['kind']
                    d.serial = data['serial']
                    d.notified_serial = data['notified_serial']
                    d.last_check = data['last_check']
                    d.dnssec = 1 if data['dnssec'] else 0
                    db.session.add(d)
                    changed = True
                if changed:
                    try:
                        db.session.commit()
                    except Exception:
                        db.session.rollback()
            return {'status': 'ok', 'msg': 'Domain table has been updated successfully'}
        except Exception as err:
            LOGGING.error('Can not update domain table. %s', str(err))
            return {'status': 'error', 'msg': 'Can not update domain table'}

    @classmethod
    def add(cls, domain_name, domain_type, soa_edit_api, domain_ns=None, domain_master_ips=None):
        """
        Add a domain to power dns
        """
        if not domain_ns:
            domain_ns = []
        if not domain_master_ips:
            domain_master_ips = []
        headers = {}
        headers['X-API-Key'] = PDNS_API_KEY

        if NEW_SCHEMA:
            domain_name = domain_name + '.'
            domain_ns = [ns + '.' for ns in domain_ns]

        if soa_edit_api == 'OFF':
            post_data = {"name": domain_name,
                         "kind": domain_type,
                         "masters": domain_master_ips,
                         "nameservers": domain_ns, }
        else:
            post_data = {"name": domain_name,
                         "kind": domain_type,
                         "masters": domain_master_ips,
                         "nameservers": domain_ns,
                         "soa_edit_api": soa_edit_api}

        try:
            jdata = utils.fetch_json(urlparse.urljoin(PDNS_STATS_URL, API_EXTENDED_URL + '/servers/localhost/zones'),
                                     headers=headers, method='POST', data=post_data)
            if 'error' in jdata.keys():
                LOGGING.error(jdata['error'])
                return {'status': 'error', 'msg': jdata['error']}
            else:
                LOGGING.info('Added domain %s successfully', domain_name)
                return {'status': 'ok', 'msg': 'Added domain successfully'}
        except Exception as err:
            LOGGING.error('Cannot add domain %s', domain_name)
            traceback.format_exc()
            LOGGING.debug(str(err))
            return {'status': 'error', 'msg': 'Cannot add this domain.'}

    def create_reverse_domain(self, domain_name, domain_reverse_name):
        """
        Check the existing reverse lookup domain,
        if not exists create a new one automatically
        """
        domain_obj = Domain.query.filter(Domain.name == domain_name).first()
        domain_auto_ptr = DomainSetting.query.filter(DomainSetting.domain == domain_obj) \
                                             .filter(DomainSetting.setting == 'auto_ptr').first()
        domain_auto_ptr = strtobool(domain_auto_ptr.value) if domain_auto_ptr else False
        system_auto_ptr = Setting.query.filter(Setting.name == 'auto_ptr').first()
        system_auto_ptr = strtobool(system_auto_ptr.value)
        self.name = domain_name
        domain_id = self.get_id_by_name(domain_reverse_name)
        if domain_id is None and (system_auto_ptr or domain_auto_ptr):
            result = self.add(domain_reverse_name, 'Master', 'INCEPTION-INCREMENT', '', '')
            self.update()
            if result['status'] == 'ok':
                history = History(msg='Add reverse lookup domain %s' % domain_reverse_name,
                                  detail=str({'domain_type': 'Master', 'domain_master_ips': ''}), created_by='System')
                history.add()
            else:
                return {'status': 'error', 'msg': 'Adding reverse lookup domain failed'}
            domain_user_ids = self.get_user()
            domain_users = []
            u = User()
            for uid in domain_user_ids:
                u.id = uid
                tmp = u.get_user_info_by_id()
                domain_users.append(tmp.username)
            if domain_users:
                self.name = domain_reverse_name
                self.grant_privielges(domain_users)
                return {'status': 'ok', 'msg': 'New reverse lookup domain created with granted privilages'}
            return {'status': 'ok', 'msg': 'New reverse lookup domain created without users'}
        return {'status': 'ok', 'msg': 'Reverse lookup domain already exists'}

    def get_reverse_domain_name(self, reverse_host_address):
        """Get Reverse Domain Name"""
        c = 1
        if re.search('ip6.arpa', reverse_host_address):
            for i in range(1, 32, 1):
                address = re.search(r'((([a-f0-9]\.){' + str(i) + r'})(?P<ipname>.+6.arpa)\.?)', reverse_host_address)
                if self.get_id_by_name(address.group('ipname')) is not None:
                    c = i
                    break
            return re.search(r'((([a-f0-9]\.){' + str(c) + r'})(?P<ipname>.+6.arpa)\.?)',
                             reverse_host_address).group('ipname')
        else:
            for i in range(1, 4, 1):
                address = re.search(r'((([0-9]+\.){' + str(i) + r'})(?P<ipname>.+r.arpa)\.?)', reverse_host_address)
                if self.get_id_by_name(address.group('ipname')) is not None:
                    c = i
                    break
            return re.search(r'((([0-9]+\.){' + str(c) + r'})(?P<ipname>.+r.arpa)\.?)',
                             reverse_host_address).group('ipname')

    @classmethod
    def delete(cls, domain_name):
        """
        Delete a single domain name from powerdns
        """
        headers = {}
        headers['X-API-Key'] = PDNS_API_KEY
        try:
            url = urlparse.urljoin(PDNS_STATS_URL, API_EXTENDED_URL + '/servers/localhost/zones/%s' % domain_name)
            utils.fetch_json(url, headers=headers, method='DELETE')
            LOGGING.info('Delete domain %s successfully', domain_name)
            return {'status': 'ok', 'msg': 'Delete domain successfully'}
        except Exception as e:
            tbck = traceback.format_exc()
            LOGGING.error('Cannot delete domain %s', domain_name)
            LOGGING.debug(str(e))
            LOGGING.debug(str(tbck))
            return {'status': 'error', 'msg': 'Cannot delete domain'}

    def get_user(self):
        """
        Get users (id) who have access to this domain name
        """
        user_ids = []
        query = db.session.query(DomainUser, Domain) \
                  .filter(User.id == DomainUser.user_id) \
                  .filter(Domain.id == DomainUser.domain_id) \
                  .filter(Domain.name == self.name) \
                  .all()
        for q in query:
            user_ids.append(q[0].user_id)
        return user_ids

    def grant_privielges(self, new_user_list):
        """
        Reconfigure domain_user table
        """

        domain_id = self.get_id_by_name(self.name)

        domain_user_ids = self.get_user()

        if new_user_list:
            new_user_ids = [u.id for u in User.query.filter(User.username.in_(new_user_list)).all()]
        else:
            new_user_ids = []

        removed_ids = list(set(domain_user_ids).difference(new_user_ids))
        added_ids = list(set(new_user_ids).difference(domain_user_ids))

        try:
            for uid in removed_ids:
                DomainUser.query.filter(DomainUser.user_id == uid).filter(DomainUser.domain_id == domain_id).delete()
                db.session.commit()
        except Exception:
            db.session.rollback()
            LOGGING.error('Cannot revoke user privielges on domain %s', self.name)

        try:
            for uid in added_ids:
                du = DomainUser(domain_id, uid)
                db.session.add(du)
                db.session.commit()
        except Exception:
            db.session.rollback()
            LOGGING.error('Cannot grant user privielges to domain %s', self.name)

    @classmethod
    def update_from_master(cls, domain_name):
        """
        Update records from Master DNS server
        """
        domain = Domain.query.filter(Domain.name == domain_name).first()
        if domain:
            headers = {}
            headers['X-API-Key'] = PDNS_API_KEY
            try:
                url = urlparse.urljoin(PDNS_STATS_URL,
                                       API_EXTENDED_URL + '/servers/localhost/zones/%s/axfr-retrieve' % domain)
                utils.fetch_json(url, headers=headers, method='PUT')
                return {'status': 'ok', 'msg': 'Update from Master successfully'}
            except Exception:
                return {'status': 'error', 'msg': 'There was something wrong, please contact administrator'}
        else:
            return {'status': 'error', 'msg': 'This domain doesnot exist'}

    @classmethod
    def get_domain_dnssec(cls, domain_name):
        """
        Get domain DNSSEC information
        """
        domain = Domain.query.filter(Domain.name == domain_name).first()
        if domain:
            headers = {}
            headers['X-API-Key'] = PDNS_API_KEY
            try:
                url = urlparse.urljoin(PDNS_STATS_URL,
                                       API_EXTENDED_URL + '/servers/localhost/zones/%s/cryptokeys' % domain.name)
                jdata = utils.fetch_json(url, headers=headers, method='GET')
                if 'error' in jdata:
                    return {'status': 'error', 'msg': 'DNSSEC is not enabled for this domain'}
                else:
                    return {'status': 'ok', 'dnssec': jdata}
            except Exception:
                return {'status': 'error', 'msg': 'There was something wrong, please contact administrator'}
        else:
            return {'status': 'error', 'msg': 'This domain doesnot exist'}


class DomainUser(db.Model):
    """Domain User Model"""
    # pylint: disable=C0103,R0903
    __tablename__ = 'domain_user'
    id = db.Column(db.Integer, primary_key=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __init__(self, domain_id, user_id):
        self.domain_id = domain_id
        self.user_id = user_id

    def __repr__(self):
        return '<Domain_User %r %r>' % (self.domain_id, self.user_id)


class History(db.Model):
    """SQLAlchemy model for the history database table"""
    # pylint: disable=C0103
    id = db.Column(db.Integer, primary_key=True)
    msg = db.Column(db.String(256))
    detail = db.Column(db.Text().with_variant(db.Text(length=2 ** 24 - 2), 'mysql'))
    created_by = db.Column(db.String(128))
    created_on = db.Column(db.DateTime, default=datetime.utcnow)
    name = db.Column(db.String(255))
    changetype = db.Column(db.String(32))
    fromdata = db.Column(JSON)
    todata = db.Column(JSON)
    domain = db.Column(db.Integer)

    # pylint: disable=R0913,W0622
    def __init__(self, id=None, msg=None, detail=None, created_by=None, name=None, changetype=None, fromdata=None,
                 todata=None, domain=None):
        domainid = None
        if domain:
            mdl = db.session.query(Domain.id)\
                    .filter(Domain.name == domain)\
                    .first()
            domainid = None
            if mdl:
                domainid = mdl.id
        if not changetype and 'changetype' in todata:
            changetype = todata['changetype']
        if not name and 'name' in todata:
            name = todata['name']

        self.id = id
        self.msg = msg
        self.detail = detail
        self.created_by = created_by
        self.name = name
        self.changetype = changetype
        self.fromdata = fromdata
        self.todata = todata
        self.domain = domainid

    def __repr__(self):
        return '<History %r>' % (self.msg)

    def add(self):
        """
        Add an event to history table
        """
        h = History()
        h.msg = self.msg
        h.detail = self.detail
        h.created_by = self.created_by
        db.session.add(h)
        db.session.commit()

    @classmethod
    def remove_all(cls):
        """
        Remove all history from DB
        """
        try:
            db.session.query(History).delete()
            db.session.commit()
            LOGGING.info("Removed all history")
            return True
        except Exception:
            db.session.rollback()
            LOGGING.error("Cannot remove history")
            LOGGING.debug(traceback.format_exc())
            return False


class Rrset(db.Model):
    """SQLAlchemy model for the history database table"""
    rrsetid = db.Column(db.Integer, primary_key=True)
    rrsets = db.Column(db.JSON)
    tstmp = db.Column(db.DateTime, default=datetime.utcnow)

    # pylint: disable=R0913,W0622,R0903
    def __init__(self, rrsets=None):
        self.rrsets = rrsets
        self.tstmp = datetime.utcnow()
        self.rrsetid = None


class Setting(db.Model):
    """SQLAlchemy Model for the setting table in the database"""
    # pylint: disable=C0103
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))
    value = db.Column(db.String(256))

    # pylint: disable=R0913,W0622
    def __init__(self, id=None, name=None, value=None):
        self.id = id
        self.name = name
        self.value = value

    @classmethod
    def set_mainteance(cls, mode):
        """
        mode = True/False
        """
        mode = str(mode)
        maintenance = Setting.query.filter(Setting.name == 'maintenance').first()
        try:
            if maintenance:
                if maintenance.value != mode:
                    maintenance.value = mode
                    db.session.commit()
                return True
            else:
                s = Setting(name='maintenance', value=mode)
                db.session.add(s)
                db.session.commit()
                return True
        except Exception:
            LOGGING.error('Cannot set maintenance to %s', mode)
            LOGGING.debug(traceback.format_exc())
            db.session.rollback()
            return False

    @classmethod
    def toggle(cls, setting):
        """Toggle Setting"""
        setting = str(setting)
        current_setting = Setting.query.filter(Setting.name == setting).first()
        try:
            if current_setting:
                if current_setting.value == "True":
                    current_setting.value = "False"
                else:
                    current_setting.value = "True"
                db.session.commit()
                return True
            else:
                LOGGING.error('Setting %s does not exist', setting)
                return False
        except Exception:
            LOGGING.error('Cannot toggle setting %s', setting)
            LOGGING.debug(traceback.format_exec())
            db.session.rollback()
            return False

    @classmethod
    def set(cls, setting, value):
        """Set Setting"""
        setting = str(setting)
        new_value = str(value)
        current_setting = Setting.query.filter(Setting.name == setting).first()
        try:
            if current_setting:
                current_setting.value = new_value
                db.session.commit()
                return True
            else:
                LOGGING.error('Setting %s does not exist', setting)
                return False
        except Exception:
            LOGGING.error('Cannot edit setting %s', setting)
            LOGGING.debug(traceback.format_exec())
            db.session.rollback()
            return False
