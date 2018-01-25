"""Views for the Power DNS Admin application."""

import json
import os
import sys
import base64
from pprint import pprint
from flask import request, jsonify
from admin_api.crypt import Keypair

from app import app
# from app.models import User, Domain, History, Setting, DomainSetting
from app.base import Record

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


@app.route('/api', methods=['GET', 'POST', 'PATCH'])
# @login_required
def api():
    """Let us test the api from a brower so I can debug the damn thing."""
    # first authenticate
    print "Begin run #########################################\n\n"

    apikey = getheadervalue(request.headers, 'X-API-Key')
    print 'X-API-Key is %s' % (apikey)
    username = getheadervalue(request.headers, 'X-API-User')
    print 'X-API-User is %s' % (username)
    b64 = getheadervalue(request.headers, 'X-API-Pubkey')
    user_pubkey = base64.b64decode(b64)
    print 'X-API-Pubkey is %s' % (user_pubkey)

    exepath = os.path.dirname(os.path.realpath(__file__))
    oneup = os.path.abspath(os.path.join(exepath, ".."))
    cnfgfile = '%s/%s' % (oneup, 'serverkeys.cfg')
    print "server keys cfg file is %s" % (cnfgfile)

    server_keypair = Keypair(cnfgfile=cnfgfile, keyname='serverkeys')
    # data_ = server_keypair.encrypt('Hello There')
    # print 'The decrypted string is %s' % (server_keypair.decrypt(data_))

    client_keypair = Keypair(cnfgfile=cnfgfile, keyname='user_%s' % username)

    if apikey == 'sendserverkey':
        # there is no api key, the client needs one, we have the client public
        # encrypt a token, after getting the password
        token = server_keypair.createclienttoken(newtoken=True, username=username)
        server_pubkey = base64.b64encode(server_keypair.get_pub_key())
        return jsonify(status='serverkey', server_pubkey=server_pubkey, token=token)

    #print 'test random is %s' % (base64.b64encode(test))

    rec = Record()
    if DBGREQUEST:
        print "\n\n\n\n\nForm"
        pprint(request.form)
        print "\nValues"
        pprint(request.values)

        print "\nRequest Data"
        pprint(request.data)

    data = json.loads(request.data)
    netdata = {'rrsets': data}
    if DBGDATA:
        print 'request.data is type %s' % (type(data))
        print "pprint of netdata is :\n%s" % data
        pprint(data)
        print "\n\n"
        print "pprint of netdata is :\n%s" % netdata
        pprint(netdata)
        print "netdata is :\n%s" % netdata

    retval = rec.api_serverconnect('spotx.tv', netdata)
    return jsonify(retval=retval)
