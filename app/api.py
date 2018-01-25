"""Views for the Power DNS Admin application."""

import json
import os
# import sys
import base64
from pprint import pprint
from flask import request, jsonify
from admin_api.crypt import Keypair

from app import app
# from app.models import User, Domain, History, Setting, DomainSetting
# pylint: disable=E0401
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
    return retval


def show(val):
    """Solve a wierd pylint issue, and make it easy to silence the output."""
    print(val)


@app.route('/api', methods=['GET', 'POST', 'PATCH'])
# @login_required
def api():
    """Let us test the api from a brower so I can debug the damn thing."""
    # first authenticate
    show("Begin run #########################################\n\n")

    # get the headers we can from the client
    apikey = getheadervalue(request.headers, 'X-API-Key')
    show('X-API-Key is %s' % (apikey))
    username = getheadervalue(request.headers, 'X-API-User')
    show('X-API-User is %s' % (username))
    b64 = getheadervalue(request.headers, 'X-API-Pubkey')
    user_pubkey = base64.b64decode(b64)
    show('X-API-Pubkey is %s' % (user_pubkey))

    exepath = os.path.dirname(os.path.realpath(__file__))
    oneup = os.path.abspath(os.path.join(exepath, ".."))
    cnfgfile = '%s/%s' % (oneup, 'serverkeys.cfg')
    show("server keys cfg file is %s" % (cnfgfile))

    server_keypair = Keypair(cnfgfile=cnfgfile)
    # data_ = server_keypair.encrypt('Hello There')
    # show('The decrypted string is %s' % (server_keypair.decrypt(data_)))

    client_keypair = Keypair(cnfgfile=cnfgfile, username=username, pubkeystring=user_pubkey)

    if apikey == 'sendserverkey':
        # there is no api key, the client needs one, we have the client public
        # encrypt a token, after getting the password
        token = server_keypair.createclienttoken(newtoken=True, username=username)
        server_pubkey = base64.b64encode(server_keypair.get_pub_key())
        # setfromserver is a misnomer not save as serverkeys !!!!!
        show(client_keypair)
        client_keypair.saveclientonserver(token=token, username=username)
        return jsonify(status='serverkey', server_pubkey=server_pubkey, token=token)

    # show('test random is %s' % (base64.b64encode(test))

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
