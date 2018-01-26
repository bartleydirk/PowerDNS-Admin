"""Views for the Power DNS Admin application."""

import json
import os
# import sys
import base64
from pprint import pprint
from flask import request, jsonify
from admin_api.crypt import Keypair
from models import User

from app import app, db
# from app.models import User, Domain, History, Setting, DomainSetting
# pylint: disable=E0401,E0001
from .base import Record

DBGREQUEST = False
DBGDATA = False
DBGHDR = False


def getheadervalue(headers, value):
    """Pull a value out of request.headers, a list of tuples of length 2."""
    retval = None
    for tup in headers:
        if tup[0].upper() == value.upper():
            retval = tup[1]
    if DBGHDR:
        show('getheadervalue -> %s is %s' % (value, retval))
    return retval


def show(val):
    """Solve a wierd pylint issue, and make it easy to silence the output."""
    print(val)


def getconfigfile():
    """Get the config file consistently."""
    exepath = os.path.dirname(os.path.realpath(__file__))
    oneup = os.path.abspath(os.path.join(exepath, ".."))
    cnfgfile = '%s/%s' % (oneup, 'serverkeys.cfg')
    show("server keys cfg file is %s" % (cnfgfile))
    return cnfgfile


@app.route('/exchangekeys', methods=['GET', 'POST', 'PATCH'])
def exchangekeys():
    """Exchange keys."""
    show("Begin exchange route #########################################\n\n")
    # get the headers we can from the client
    username = getheadervalue(request.headers, 'X-API-User')
    client_pubkey = base64.b64decode(getheadervalue(request.headers, 'X-API-Pubkey'))
    pprint(request.headers)
    client_uuid = base64.b64decode(getheadervalue(request.headers, 'X-API-clientuuid'))

    cnfgfile = getconfigfile()
    server_keypair = Keypair(cnfgfile=cnfgfile)
    client_keypair = Keypair(cnfgfile=cnfgfile, username=username, pubkeystring=client_pubkey, uuid=client_uuid)

    print "exchangekeys showing client_keypair pubkey %s username %s" % (client_pubkey, username)
    show(client_keypair)
    pubkey, uuid_ = server_keypair.get_pub_key()
    show('exchangekeys pubkey "%s", uuid %s' % (pubkey, uuid_))
    server_pubkey = base64.b64encode(pubkey)
    server_uuid = base64.b64encode(uuid_)

    # the public key was passed in the constructor, and this method saves client pubkey as well
    client_keypair.saveclientonserver()
    return jsonify(status='serverkey', server_pubkey=server_pubkey, server_uuid=server_uuid)


@app.route('/token', methods=['GET', 'POST', 'PATCH'])
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

    user = db.session.query(User)\
             .filter(User.username == username)\
             .first()
    user.plain_text_password = password
    encryptedtoken = ''
    if user.password and user.check_password(user.password):
        status = 'Password Success'
        # generate and save a token in the cfg file
        token = client_keypair.gentoken()
        encryptedtoken = client_keypair.encrypt(token)

        client_keypair.saveclientonserver(token=token)
    else:
        status = 'Password Fail'

    return jsonify(status=status, encryptedtoken=encryptedtoken)


@app.route('/api', methods=['GET', 'POST', 'PATCH'])
def api():
    """Let us test the api from a brower so I can debug the damn thing."""
    # first authenticate
    show("Begin api route #########################################\n\n")

    # get the headers we can from the client
    apikey = getheadervalue(request.headers, 'X-API-Key')
    show('X-API-Key is %s' % (apikey))
    username = getheadervalue(request.headers, 'X-API-User')
    show('X-API-User is %s' % (username))
    b64 = getheadervalue(request.headers, 'X-API-Pubkey')
    client_pubkey = base64.b64decode(b64)
    show('X-API-Pubkey is %s' % (client_pubkey))

    # cnfgfile = getconfigfile()
    # server_keypair = Keypair(cnfgfile=cnfgfile)
    # client_keypair = Keypair(cnfgfile=cnfgfile, username=username, pubkeystring=client_pubkey)

    rec = Record()
    if DBGREQUEST:
        show("\n\n\n\n\nForm")
        pprint(request.form)
        show("\nValues")
        pprint(request.values)
        show("\nRequest Data")
        pprint(request.data)

    data = json.loads(request.data)
    netdata = {'rrsets': data}
    if DBGDATA:
        show('request.data is type %s' % (type(data)))
        show("print of netdata is :\n%s" % (data))
        pprint(data)
        show("\n\n")
        show("print of netdata is :\n%s" % (netdata))
        pprint(netdata)
        show("netdata is :\n%s" % (netdata))

    retval = rec.api_serverconnect('spotx.tv', netdata)
    return jsonify(retval=retval)
