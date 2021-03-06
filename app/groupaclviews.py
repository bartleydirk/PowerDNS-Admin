"""Views for the Power DNS Admin application."""
# pylint: disable=E1101,E0611,E0401

import re
from flask_login import login_required
from flask import request, render_template, jsonify

from app import app, db
from app.models import User, UserGroup, UserGroupUser, Domain, DomainGroup, DomainGroupDomain, DomainGroupUserGroup
from app.base import intsafe
from app.views import admin_role_required


@app.route('/admin/usergroup/list', methods=['GET', 'POST'])
@login_required
@admin_role_required
def usergroup_list():
    """View to manage a user."""
    # pylint: disable=R0912,R0914
    retval = None
    if request.method == 'GET':
        usergroups = db.session.query(UserGroup)\
                       .order_by(UserGroup.name)
        retval = render_template('groupacl/usergroup_list.html', usergroups=usergroups)
    return retval


def usergroup_render(tmplate, usergrp_id):
    """View to create a user."""
    usergroup = db.session.query(UserGroup)\
                  .filter(UserGroup.id == usergrp_id)\
                  .first()

    if usergroup:
        # list of users for the members ui
        users = db.session.query(User)\
                  .order_by(User.username)\
                  .all()
        # list of current members for the ui
        ugusers = db.session.query(UserGroupUser)\
                    .filter(UserGroupUser.usergroup_id == usergrp_id)\
                    .order_by(UserGroupUser.user_id)\
                    .all()
        # I want to pass a integer list not a sqlachemy list.
        ugus = [item.user_id for item in ugusers]

        dgugs_lst = db.session.query(DomainGroupUserGroup)\
                      .filter(DomainGroupUserGroup.usergroup_id == usergrp_id)
        dgrps_in = [dgug.domaingroup_id for dgug in dgugs_lst]
        domgrps = db.session.query(DomainGroup)\
                    .order_by(DomainGroup.name)

    else:
        users = []
        ugus = []
        domgrps = []
        dgrps_in = []

    return render_template(tmplate, usergroup=usergroup, users=users, ugus=ugus, domgrps=domgrps, dgrps_in=dgrps_in)


@app.route('/admin/usergroup/manage', methods=['GET', 'POST'])
@login_required
@admin_role_required
def usergroup_maintain():
    """View for maintaining user groups."""
    # pylint: disable=R0914,R0912,R0915
    user_grp_id = intsafe(request.form.get('id', 0))
    action = request.form.get('action', None)

    retval = ''
    if user_grp_id == 0 and request.method == 'POST':
        # this is a create
        name = request.form.get('name', '')
        description = request.form.get('description', '')
        usergroup = UserGroup(name, description)
        db.session.add(usergroup)
        db.session.commit()
        retval = usergroup_render('groupacl/usergroup_maintain_reload.html', usergroup.id)

    elif request.method == 'GET':
        user_grp_id = intsafe(request.args.get('id', 0))
        retval = usergroup_render('groupacl/usergroup_maintain.html', user_grp_id)

    elif request.method == 'POST' and action == 'info':
        usergroup = db.session.query(UserGroup)\
                      .filter(UserGroup.id == user_grp_id)\
                      .first()
        if usergroup:
            usergroup.name = request.form.get('name', '')
            usergroup.description = request.form.get('description', '')
            db.session.commit()
            retval = usergroup_render('groupacl/usergroup_maintain_reload.html', user_grp_id)
    elif request.method == 'POST' and action == 'members':
        members_tobe = [intsafe(uident) for uident in request.form.getlist('group_users[]')]
        mem_obj_list = db.session.query(UserGroupUser)\
                         .filter(UserGroupUser.usergroup_id == user_grp_id)\
                         .all()
        memmap = {}
        members_current = []
        for (pos, member) in enumerate(mem_obj_list):
            members_current.append(member.user_id)
            memmap[member.user_id] = pos

        for uid in members_tobe:
            if uid not in members_current:
                newmember = UserGroupUser(user_grp_id, uid)
                db.session.add(newmember)

        for uid in members_current:
            if uid not in members_tobe:
                db.session.delete(mem_obj_list[memmap[uid]])
        db.session.commit()

        retval = usergroup_render('groupacl/usergroup_maintain_reload.html', user_grp_id)

    elif request.method == 'POST' and action == 'delete':
        mem_obj_list = db.session.query(UserGroupUser)\
                         .filter(UserGroupUser.usergroup_id == user_grp_id)
        for ugu in mem_obj_list:
            db.session.delete(ugu)
        usergroup = db.session.query(UserGroup)\
                      .filter(UserGroup.id == user_grp_id)\
                      .first()
        db.session.delete(usergroup)
        db.session.commit()
        retval = ''

    elif request.method == 'POST' and action == 'associated':
        assosciated_tobe = [intsafe(dom_grpid) for dom_grpid in request.form.getlist('group_associated[]')]
        assoc_obj_list = db.session.query(DomainGroupUserGroup)\
                           .filter(DomainGroupUserGroup.usergroup_id == user_grp_id)\
                           .all()
        memmap = {}
        assosciated_current = []
        for (pos, dgug_obj) in enumerate(assoc_obj_list):
            assosciated_current.append(dgug_obj.domaingroup_id)
            memmap[dgug_obj.domaingroup_id] = pos

        # with list of associated_current and map to object
        for dom_grp_id in assosciated_tobe:
            if dom_grp_id not in assosciated_current:
                new_dgug_obj = DomainGroupUserGroup(user_grp_id, dom_grp_id)
                db.session.add(new_dgug_obj)

        for dom_grp_id in assosciated_current:
            if dom_grp_id not in assosciated_tobe:
                db.session.delete(assoc_obj_list[memmap[dom_grp_id]])
        db.session.commit()

        retval = usergroup_render('groupacl/usergroup_maintain_reload.html', user_grp_id)

    return retval


#  Domain Groups Begin ###############


@app.route('/admin/domaingroup/list', methods=['GET', 'POST'])
@login_required
@admin_role_required
def domaingroup_list():
    """View to manage a Domain."""
    # pylint: disable=R0912,R0914
    retval = None
    if request.method == 'GET':
        domaingroups = db.session.query(DomainGroup)\
                         .order_by(DomainGroup.name)
        retval = render_template('groupacl/domaingroup_list.html', domaingroups=domaingroups)
    return retval


def domaingroup_render(tmplate, dgdid):
    """View to create a Domain."""
    domaingroup = db.session.query(DomainGroup)\
                    .filter(DomainGroup.id == dgdid)\
                    .first()

    if domaingroup:
        # list of domains for the members ui
        domains = db.session.query(Domain)\
                    .order_by(Domain.name)\
                    .all()
        # list of current members for the ui
        dgdsers = db.session.query(DomainGroupDomain)\
                    .filter(DomainGroupDomain.domaingroup_id == dgdid)\
                    .order_by(DomainGroupDomain.domain_id)\
                    .all()
        # I want to pass a integer list not a sqlachemy list.
        dgds = [item.domain_id for item in dgdsers]

        dgugs_lst = db.session.query(DomainGroupUserGroup)\
                      .filter(DomainGroupUserGroup.domaingroup_id == dgdid)
        usrgrps_in = [dgug.usergroup_id for dgug in dgugs_lst]
        usr_grps = db.session.query(UserGroup)\
                     .order_by(UserGroup.name)
        #pprint(asdf)

    else:
        domains = []
        dgds = []
        usrgrps_in = []
        usr_grps = []

    return render_template(tmplate, domaingroup=domaingroup, domains=domains, dgds=dgds, usr_grps=usr_grps,
                           usrgrps_in=usrgrps_in)


@app.route('/admin/domaingroup/manage', methods=['GET', 'POST'])
@login_required
@admin_role_required
def domaingroup_maintain():
    """View for maintaining domain groups."""
    # pylint: disable=R0914,R0912,R0915
    domn_grp_id = intsafe(request.form.get('id', 0))
    action = request.form.get('action', None)

    retval = ''
    if domn_grp_id == 0 and request.method == 'POST':
        # this is a create
        name = request.form.get('name', '')
        description = request.form.get('description', '')
        domaingroup = DomainGroup(name, description)
        db.session.add(domaingroup)
        db.session.commit()
        retval = domaingroup_render('groupacl/domaingroup_maintain_reload.html', domaingroup.id)

    elif request.method == 'GET':
        domn_grp_id = intsafe(request.args.get('id', 0))
        retval = domaingroup_render('groupacl/domaingroup_maintain.html', domn_grp_id)

    elif request.method == 'POST' and action == 'info':
        domaingroup = db.session.query(DomainGroup)\
                        .filter(DomainGroup.id == domn_grp_id)\
                        .first()
        if domaingroup:
            domaingroup.name = request.form.get('name', '')
            domaingroup.description = request.form.get('description', '')
            db.session.commit()
            retval = domaingroup_render('groupacl/domaingroup_maintain_reload.html', domn_grp_id)
    elif request.method == 'POST' and action == 'members':
        members_tobe = [intsafe(domain_id) for domain_id in request.form.getlist('group_domains[]')]
        # query for list of objects that indicate domains belong to this domain group
        dgd_ingroup = db.session.query(DomainGroupDomain)\
                        .filter(DomainGroupDomain.domaingroup_id == domn_grp_id)\
                        .all()
        memmap = {}
        members_current = []
        for (pos, member) in enumerate(dgd_ingroup):
            members_current.append(member.domain_id)
            memmap[member.domain_id] = pos

        # add members that need to be
        for dmn_id in members_tobe:
            if dmn_id not in members_current:
                newmember = DomainGroupDomain(domn_grp_id, dmn_id)
                db.session.add(newmember)

        # remove members that need to be
        for dmn_id in members_current:
            if dmn_id not in members_tobe:
                db.session.delete(dgd_ingroup[memmap[dmn_id]])
        db.session.commit()

        retval = domaingroup_render('groupacl/domaingroup_maintain_reload.html', domn_grp_id)

    elif request.method == 'POST' and action == 'delete':
        dgd_ingroup = db.session.query(DomainGroupDomain)\
                        .filter(DomainGroupDomain.domaingroup_id == domn_grp_id)
        for dgd in dgd_ingroup:
            db.session.delete(dgd)
        domaingroup = db.session.query(DomainGroup)\
                        .filter(DomainGroup.id == domn_grp_id)\
                        .first()
        db.session.delete(domaingroup)
        db.session.commit()
        retval = ''

    elif request.method == 'POST' and action == 'associated':
        assosciated_tobe = [intsafe(usrgrp_id) for usrgrp_id in request.form.getlist('group_associated[]')]
        assoc_obj_list = db.session.query(DomainGroupUserGroup)\
                           .filter(DomainGroupUserGroup.domaingroup_id == domn_grp_id)\
                           .all()
        memmap = {}
        assosciated_current = []
        for (pos, dgug_obj) in enumerate(assoc_obj_list):
            assosciated_current.append(dgug_obj.usergroup_id)
            memmap[dgug_obj.usergroup_id] = pos

        # with list of associated_current and map to object
        for usr_grp_id in assosciated_tobe:
            if usr_grp_id not in assosciated_current:
                new_dgug_obj = DomainGroupUserGroup(usr_grp_id, domn_grp_id)
                db.session.add(new_dgug_obj)

        for usr_grp_id in assosciated_current:
            if usr_grp_id not in assosciated_tobe:
                db.session.delete(assoc_obj_list[memmap[usr_grp_id]])
        db.session.commit()

        retval = domaingroup_render('groupacl/domaingroup_maintain_reload.html', domn_grp_id)

    return retval


def domaingroup_check(domaingroup_id, domain_id):
    """Add new member to doamin group if not already there."""
    qry = db.session.query(DomainGroupDomain)\
            .filter(DomainGroupDomain.domain_id == domain_id)\
            .filter(DomainGroupDomain.domaingroup_id == domaingroup_id)\
            .all()
    if not qry:
        dgd = DomainGroupDomain(domaingroup_id, domain_id)
        db.session.add(dgd)
        db.session.commit()
    # DomainGroupDomain domaingroup_id, domain_id


@app.route('/setdomaingroups', methods=['GET', 'POST'])
def setdomaingroups():
    """A Testing only route, to see if a change to acl logic has desired effect, which is no effect."""
    re_inaddrarpa = re.compile(r'\.in-addr\.arpa$')
    re_one92 = re.compile(r'\.168\.192\.in-addr\.arpa$')
    re_ten = re.compile(r'\.10\.in-addr\.arpa$')
    re_one72a = re.compile(r'\.1[6-9]\.172\.in-addr\.arpa$')
    re_one72b = re.compile(r'\.2[0-9]\.172\.in-addr\.arpa$')
    re_one72c = re.compile(r'\.3[0-1]\.172\.in-addr\.arpa$')
    re_pop = re.compile(r'pop$')
    re_lod = re.compile(r'lod$')
    Domain().update()
    lst = []
    qry = db.session.query(Domain)
    #DomainGroupDomain domaingroup_id, domain_id
    for domain in qry:
        isreverse = False
        isprivate = False
        if re_inaddrarpa.search(domain.name):
            isreverse = True
        if re_one92.search(domain.name) or re_ten.search(domain.name) or re_one72a.search(domain.name) \
                or re_one72b.search(domain.name) or re_one72c.search(domain.name):
            isprivate = True
        if isreverse and not isprivate:
            # public reverse 6
            domaingroup_check(6, domain.id)
        elif isreverse:
            # private reverse
            domaingroup_check(2, domain.id)
        elif re_pop.search(domain.name) or re_lod.search(domain.name):
            # private forward
            domaingroup_check(4, domain.id)
        else:
            # public forward 5
            domaingroup_check(5, domain.id)
            lst.append("%s %s" % (domain.name, isreverse))
    return jsonify(lst=lst)
