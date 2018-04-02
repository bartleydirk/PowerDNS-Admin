"""Views for the Power DNS Admin application."""

import json
import os
# import sys
import base64
from pprint import pformat
# pylint: disable=E0611
from flask import request, jsonify
from admin_api.crypt import Keypair  # , limitlines
# pylint: disable=E0401
from models import User

from app import app, db
from app.models import Domain
# from app.models import User, Domain, History, Setting, DomainSetting
# pylint: disable=E0401,E0001
from .base import Record
import dns.reversename

DBGREQUEST = False
DBGDATA = False
DBGHDR = False
SHOWLOG = True

LOGFILE = '%s/afile.log' % os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
# show("log file is %s" % (LOGFILE), 10)


def show(message, level=5):
    """Solve a wierd pylint issue, and make it easy to silence the output."""
    message = "PowerDNSAdmin api -> %s" % (message)
    log_fv = open(LOGFILE, 'a')
    log_fv.write('%s\n' % message)
    log_fv.close()
    if SHOWLOG:
        if level > 5:
            print(message)


def get_domain_fromname(name):
    name_split = name.split('.')
    name_split.reverse()
    test = ''
    for item in name_split:
        if item != '':
            if test == '':
                test = "%s" % (item)
            else:
                test = "%s.%s" % (item, test)
            # show("get_domain_fromname of testing is :%s" % (test), level=6)
            mdl = db.session.query(Domain)\
                    .filter(Domain.name == test)\
                    .first()
            if mdl:
                return mdl.name
    return None


def getconfigfile():
    """Get the config file consistently."""
    exepath = os.path.dirname(os.path.realpath(__file__))
    oneup = os.path.abspath(os.path.join(exepath, ".."))
    cnfgfile = '%s/%s' % (oneup, 'serverkeys.cfg')
    show("server keys cfg file is %s" % (cnfgfile))
    return cnfgfile


def getheadervalue(headers, value):
    """Pull a value out of request.headers, a list of tuples of length 2."""
    retval = None
    for tup in headers:
        if tup[0].upper() == value.upper():
            retval = tup[1]
    if DBGHDR:
        show('getheadervalue -> %s is %s' % (value, retval))
    return retval


def token_verify():
    """Verify Token."""
    # get the headers we can from the client
    username = getheadervalue(request.headers, 'X-API-User')
    encryptedtoken = getheadervalue(request.headers, 'X-API-Key')
    show("token_verify -> encryptedtoken = %s" % (encryptedtoken), level=6)
    signature = getheadervalue(request.headers, 'X-API-Signature')
    show("token_verify -> signature = %s" % (signature), level=6)

    cnfgfile = getconfigfile()
    server_keypair = Keypair(cnfgfile=cnfgfile)
    client_keypair = Keypair(cnfgfile=cnfgfile, username=username)
    # show(server_keypair)
    token_fromclient = server_keypair.decrypt(encryptedtoken)
    show("token_verify -> token_fromclient     = '%s'" % (token_fromclient))
    show("token_verify -> server_keypair.token = '%s'" % (client_keypair.token))
    retval = False
    if token_fromclient == client_keypair.token:
        verified = client_keypair.verify(encryptedtoken, signature)
        if verified:
            retval = True
    show("token_verify -> returning = %s" % (retval))
    return retval


@app.route('/checkkeys', methods=['GET', 'POST', 'PATCH'])
def checkkeys():
    """Check keys."""
    show("Begin checkkeys route #########################################\n\n")
    # get the headers we can from the client
    username = getheadervalue(request.headers, 'X-API-User')
    client_pubkey = base64.b64decode(getheadervalue(request.headers, 'X-API-Pubkey'))
    client_uuid = base64.b64decode(getheadervalue(request.headers, 'X-API-clientuuid'))
    # show("checkkeys showing client_keypair client_uuid\n%s pubkey %s" % (client_uuid, limitlines(client_pubkey)))
    show("checkkeys showing client_keypair client_uuid %s" % (client_uuid))

    # server_pubkey_onclient = base64.b64decode(getheadervalue(request.headers, 'X-API-Serverpubkey'))
    server_uuid_onclient = base64.b64decode(getheadervalue(request.headers, 'X-API-Serveruuid'))
    show("checkkeys showing server_uuid_onclient %s" % (server_uuid_onclient))
    # show("checkkeys showing server_pubkey_onclient server_uuid_onclient %s\npubkey %s" %
    #     (server_uuid_onclient, limitlines(server_pubkey_onclient)))

    cnfgfile = getconfigfile()
    # this will generate new server keys if does not exist
    server_keypair = Keypair(cnfgfile=cnfgfile)
    show('checkkeys server_keypair.uuid "%s"' % (server_keypair.uuid))

    # this will not generate new keys
    client_keypair = Keypair(cnfgfile=cnfgfile, username=username)
    show("checkkeys showing client_keypair.uuid %s" % (client_keypair.uuid))
    show(client_keypair)

    if server_uuid_onclient == server_keypair.uuid and client_uuid == client_keypair.uuid:
        retval = jsonify(status='ok')
    else:
        client_keypair = Keypair(cnfgfile=cnfgfile, username=username, pubkeystring=client_pubkey, uuid_=client_uuid)
        # show(client_keypair)
        pubkey, uuid_ = server_keypair.get_pub_key()
        show('checkkeys pubkey "%s", uuid %s' % (pubkey, uuid_))
        server_pubkey = base64.b64encode(pubkey)
        server_uuid = base64.b64encode(uuid_)

        # the public key was passed in the constructor, and this method saves client pubkey as well
        client_keypair.saveclientonserver()
        retval = jsonify(status='serverkey', server_pubkey=server_pubkey, server_uuid=server_uuid)
    return retval


@app.route('/token_check', methods=['GET', 'POST', 'PATCH'])
def token_check():
    """Exchange keys."""
    show("Begin token_check route #########################################\n\n")
    # os.unlink(LOGFILE)
    encryptedtoken = None
    if token_verify():
        status = 'Token Success'
        # generate and save a token in the cfg file
        username = getheadervalue(request.headers, 'X-API-User')
        show('token_check username "%s"' % (username))
        client_keypair = Keypair(cnfgfile=getconfigfile(), username=username)
        token_ = client_keypair.gentoken()
        encryptedtoken = client_keypair.encrypt(token_)

        client_keypair.saveclientonserver(token_=token_)
    else:
        status = 'Token Fail'
    return jsonify(status=status, encryptedtoken=encryptedtoken)


@app.route('/token_request', methods=['GET', 'POST', 'PATCH'])
def token_request():
    """Exchange keys."""
    show("Begin token route #########################################\n\n")
    # get the headers we can from the client
    username = getheadervalue(request.headers, 'X-API-User')
    encryptedpassword = getheadervalue(request.headers, 'X-API-Password')
    show("token -> encryptedpassword = %s" % (encryptedpassword))

    cnfgfile = getconfigfile()
    server_keypair = Keypair(cnfgfile=cnfgfile)
    client_keypair = Keypair(cnfgfile=cnfgfile, username=username)
    show(server_keypair)
    password = server_keypair.decrypt(encryptedpassword)
    show("token -> password = %s" % (password))

    user = db.session.query(User) \
             .filter(User.username == username) \
             .first()
    user.plain_text_password = password
    encryptedtoken = ''
    if user.password and user.check_password(user.password):
        status = 'Password Success'
        # generate and save a token in the cfg file
        token_ = client_keypair.gentoken()
        encryptedtoken = client_keypair.encrypt(token_)

        client_keypair.saveclientonserver(token_=token_)
    else:
        status = 'Password Fail'

    return jsonify(status=status, encryptedtoken=encryptedtoken)


@app.route('/addhost', methods=['GET', 'POST', 'PATCH'])
def addhost():
    """Let us test the api from a brower so I can debug the damn thing."""
    # first authenticate
    show("Begin api route #########################################\n\n")
    retval = 'begin'
    if not token_verify():
        return jsonify(retval='No Token')
    username = getheadervalue(request.headers, 'X-API-User')
    addresult = {}

    recorddata = json.loads(request.data)
    show("print of recorddata is :\n%s" % (recorddata), level=6)
    if 'name' in recorddata and 'content' in recorddata:
        show("pformat of recorddata is :\n%s" % (pformat(recorddata, indent=4)), level=6)
        name = recorddata['name']
        show("name is :%s" % (name), level=6)
        domainname = get_domain_fromname(name)
        # show("type of recorddata is :\n%s" % (type(recorddata)), level=6)
        # , type_='A', ttl=86400, disabled=False
        # pdnsdata = build_rrset(name=recorddata['name'], ipaddr=recorddata['ipaddr'])
        # show("print of pdnsdata is :\n%s" % (pformat(pdnsdata, indent=4)), level=6)
        # , rrsetid=None)
        ttl = 86400
        if 'ttl' in recorddata:
            ttl = int(recorddata['ttl'])
        rectype = 'A'
        if 'rectype' in recorddata:
            rectype = recorddata['rectype']

        show("name be is %s" % name, level=6)
        show("content be is %s" % (recorddata['content']), level=6)
        rec = Record(name=name, type=rectype, status=False, ttl=ttl, data=recorddata['content'])
        addresult = rec.add(domainname, username)

        if rectype == 'A':
            show("name is %s" % name, level=6)
            show("content is %s" % (recorddata['content']), level=6)
            # r_name = dns.reversename.to_address(recorddata['content'])
            reverse_host_address = dns.reversename.from_address(recorddata['content']).to_text()
            show("r_name is %s" % (reverse_host_address), level=6)
            if True:
                revrec = Record(name=reverse_host_address, type='PTR', status=False, ttl=86400, data=name)
                dom_ = Domain()
                domain_reverse_name = dom_.get_reverse_domain_name(reverse_host_address)
                revresult = revrec.update(domain_reverse_name, name, isreverse=True)
                if 'status' in revresult:
                    addresult['revstatus'] = revresult['status']
                if 'msg' in revresult:
                    addresult['revmsg'] = revresult['msg']

    return jsonify(retval=retval, **addresult)


@app.route('/delrec', methods=['GET', 'POST', 'PATCH'])
def delrec():
    """Let us test the api from a brower so I can debug the damn thing."""
    # first authenticate
    show("Begin api route #########################################\n\n")
    deleteresult = {}
    retval = 'begin'
    if not token_verify():
        retval = jsonify(retval='No Token')
    username = getheadervalue(request.headers, 'X-API-User')

    recorddata = json.loads(request.data)
    show("print of recorddata is :\n%s" % (recorddata), level=6)
    if 'name' in recorddata:
        show("pformat of recorddata is :\n%s" % (pformat(recorddata, indent=4)), level=6)
        name = recorddata['name']
        show("name is :%s" % (name), level=6)
        domainname = get_domain_fromname(name)

        if 'ttl' in recorddata:
            ttl = int(recorddata['ttl'])

        rectype = 'A'
        if 'rectype' in recorddata:
            rectype = recorddata['rectype']

        rec = Record(name=name, type=rectype, status=False)
        deleteresult = rec.delete(domainname, username=username)

    return jsonify(retval=retval, **deleteresult)


@app.route('/fixrev', methods=['GET', 'POST', 'PATCH'])
def fixrev():
    """Let us test the api from a brower so I can debug the damn thing."""
    # first authenticate
    show("Begin api route #########################################\n\n")
    retval = 'begin'
    updateresult = {}
    if not token_verify():
        retval = jsonify(retval='No Token')
    username = getheadervalue(request.headers, 'X-API-User')
    dom_ = Domain()

    recorddata = json.loads(request.data)
    show("fixrev print of recorddata is :\n%s" % (recorddata), level=6)
    if retval == 'begin' and 'hostname' in recorddata and 'revname' in recorddata:
        show("fixrev pformat of recorddata is :\n%s" % (pformat(recorddata, indent=4)), level=6)
        hostname = recorddata['hostname'] + '.'
        revname = recorddata['revname']
        revnamewdot = recorddata['revname'] + '.'

        domain_reverse_name = dom_.get_reverse_domain_name(revname)
        show("fixrev name is :%s revname is %s domain_reverse_name %s" %
             (hostname, revname, domain_reverse_name), level=6)

        mdl = db.session.query(Domain)\
                .filter(Domain.name == domain_reverse_name)\
                .first()
        if not mdl:
            show("fixrev domain_reverse_name %s DOES NOT EXIST" % (domain_reverse_name), level=6)
            dom_ = Domain()
            domain = 'pop'
            dom_.create_reverse_domain(domain, domain_reverse_name)
            # return jsonify(retval='No Domain %s' % (domain_reverse_name))

        rec = Record(name=revnamewdot, type='PTR', status=False, ttl=86400, data=hostname)
        updateresult = rec.update(domain_reverse_name, hostname, isreverse=True)

    return jsonify(retval=retval, **updateresult)
