"""History View."""

from flask_login import current_user, login_required
from flask import request, render_template, make_response, jsonify
from app import app, db
# pylint: disable=E0401,E1101
from app.models import History, Domain
# from distutils.util import strtobool


# @admin_role_required
@app.route('/history', methods=['GET', 'POST'])
@login_required
def admin_history():
    """A method to act as route for rendering history page."""
    retval = None
    if request.method == 'POST':
        history = History()
        result = history.remove_all()
        if result:
            history = History(msg='Remove all histories', created_by=current_user.username)
            history.add()

            retval = make_response(jsonify({'status': 'ok', 'msg': 'Changed user role successfully.'}), 200)
        else:
            retval = make_response(jsonify({'status': 'error', 'msg': 'Can not remove histories.'}), 500)

    if request.method == 'GET':
        domain = request.values.get('domain')
        name = request.values.get('name')
        histories = db.session.query(History.id, History.created_by, History.msg,
                                     db.func.CONVERT_TZ(History.created_on, '+00:00', '-07:00').label('created_on'),
                                     History.name, History.changetype, Domain.name.label('domainname'))\
                      .outerjoin(Domain, Domain.id == History.domain)\
                      .order_by(db.desc(History.id))
        if name:
            histories = histories.filter(History.name == '%s.' % (name))
        if domain:
            sqry = db.session.query(Domain.id)\
                     .filter(Domain.name == domain)\
                     .first()
            histories = histories.filter(History.domain == sqry)
        histories = histories.all()
        retval = render_template('admin_history.html', histories=histories)
    return retval


@app.route('/history_info', methods=['POST'])
@login_required
def history_info():
    """A method to behave as route for ajax data in history."""
    ident = request.form.get('historyid')
    # pylint: disable=W0702
    try:
        identifier = int(ident)
    except:
        return jsonify({'status': 'error', 'msg': 'Can not convert ident to integer.'})

    mdl = db.session.query(History)\
            .filter(History.id == identifier)\
            .first()

    retval = {}
    if mdl.fromdata:
        retval['fromdata'] = mdl.fromdata
    if mdl.todata:
        retval['todata'] = mdl.todata
    if mdl.domain:
        retval['domain'] = mdl.domain
    if mdl.changetype:
        retval['changetype'] = mdl.changetype
    if mdl.name:
        retval['name'] = mdl.name

    retval['created_by'] = mdl.created_by
    retval['created_on'] = mdl.created_on
    retval['detail'] = mdl.detail
    retval['detail'] = mdl.detail
    retval['msg'] = mdl.msg

    return jsonify({'status': 'ok', 'retval': retval})
