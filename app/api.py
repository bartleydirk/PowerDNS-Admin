"""
Views for the Power DNS Admin application
"""

import base64
import json
import os
import traceback
import urlparse
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

from app import app, login_manager, github, db, NEW_SCHEMA
from app.lib import utils
from app.models import User, Domain, History, Setting, DomainSetting
from app.base import Record, Server, Anonymous

from app import app, db, PDNS_STATS_URL, LOGGING, PDNS_API_KEY, API_EXTENDED_URL, NEW_SCHEMA, PRETTY_IPV6_PTR

from pprint import pprint

# pylint: disable=C0103,W0703,R1705,W0621

@app.route('/apitest', methods=['GET', 'POST', 'PATCH'])
#@login_required
def apitest():
    """Lets test the api from a brower so I can debug the damn thing."""
    rec = Record()
    #print "\n\n\n\n\nForm"
    #pprint(request.form)
    #print "\nValues"
    #pprint(request.values)
    print "Begin run #########################################\n\n"
    print "\nRequest Data"
    pprint(request.data)

    #print "\nheaders.keys"
    #pprint(request.headers.keys())
    #print "\nheaders"
    pprint(request.headers)
    if 'X-API-KEY' in (key.upper() for key in request.headers.keys()):
        print "API found"
    else:
        print "API NOT found"

    data = json.loads(request.data)
    print 'request.data is type %s' % (type(data))
    print "pprint of netdata is :\n%s" % data
    pprint(data)

    print "\n\n\n"
    netdata = {'rrsets': data}
    print "pprint of netdata is :\n%s" % netdata
    pprint(netdata)
    print "netdata is :\n%s" % netdata

    retval = rec.api_serverconnect('spotx.tv', netdata)
    return jsonify(retval=retval)
