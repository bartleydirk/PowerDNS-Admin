"""
Views for the Power DNS Admin application
"""

import json
from pprint import pprint
from flask import request, jsonify

from app import app
# from app.models import User, Domain, History, Setting, DomainSetting
from app.base import Record

DBGREQUEST = False
DBGDATA = False
DBGHDR = False


@app.route('/apitest', methods=['GET', 'POST', 'PATCH'])
# @login_required
def apitest():
    """Lets test the api from a brower so I can debug the damn thing."""
    rec = Record()
    if DBGREQUEST:
        print "\n\n\n\n\nForm"
        pprint(request.form)
        print "\nValues"
        pprint(request.values)
        print "Begin run #########################################\n\n"
        print "\nRequest Data"
        pprint(request.data)

    if DBGHDR:
        print "\nheaders.keys"
        pprint(request.headers.keys())
        print "\nheaders"
        pprint(request.headers)
        if 'X-API-KEY' in (key.upper() for key in request.headers.keys()):
            print "API found"
        else:
            print "API NOT found"

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
