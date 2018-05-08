"""Views for the Power DNS Admin application."""

# pylint: disable=E1101,R0903
# from flask_login import current_user
from wtforms import fields, form
from flask_login import login_required
from flask import render_template, request
from app import app, db
# the direct to the pdns database tables
from app.models import Domains, Records


class DomainsForm(form.Form):
    """Form For Domain Inquiry Page."""

    domainlike = fields.TextField('Domain Like', default='')
    forrev = fields.SelectField('For or Rev', default='e',
                                choices=[('f', 'Forward'), ('r', 'Reverse'), ('e', 'Either')])


def domain_query(dbg=False):
    """View test 2nd database."""
    frm = DomainsForm(request.form)
    if dbg:
        print('asdf')
    sqry = db.session.query(Records.domain_id, db.func.count().label('rec_count'))\
             .group_by(Records.domain_id)\
             .subquery('sqry')

    domains = db.session.query(Domains.name, Domains.id, Domains.type, Domains.master, Domains.notified_serial,
                               sqry.c.rec_count)\
                .join(sqry, sqry.c.domain_id == Domains.id)
    if frm.domainlike.data != '':
        domains = domains.filter(Domains.name.like('%%%s%%' % (frm.domainlike.data)))
    if frm.forrev.data == 'r':
        domains = domains.filter(Domains.name.like('%%in-addr.arpa'))
    elif frm.forrev.data == 'f':
        domains = domains.filter(db.not_(Domains.name.like('%%in-addr.arpa')))
    domains = domains.order_by(Domains.name)
    return (frm, domains)


@app.route('/query_domain', methods=['GET', 'POST'])
@login_required
def query_domain():
    """View Domain table direct from the database with 2nd bind."""
    (frm, domains) = domain_query()
    return render_template('query/domain.html', frm=frm, domains=domains)


@app.route('/query_domain_reload', methods=['GET', 'POST'])
@login_required
def query_domain_reload():
    """Route to reload the table without reloading the page."""
    (frm, domains) = domain_query(dbg=False)
    return render_template('query/domain_reload.html', frm=frm, domains=domains)


class DropDownChoices(object):
    """A class to be a reusable code base for developing dropdowns."""

    @classmethod
    def domain(cls, noany=False):
        """A dropdown domain."""
        doms = db.session.query(Domains.name, Domains.id).order_by(Domains.name)
        choices = [(dmn.id, dmn.name) for dmn in doms]
        if not noany:
            choices.insert(0, [u'any', u'Any'])
        return choices


class RecordsForm(form.Form):
    """Form For Domain Inquiry Page."""

    recordlike = fields.TextField('Record Like', default='')
    recordalsolike = fields.TextField('Record Also Like', default='')
    contentlike = fields.TextField('Content Like', default='')
    contentalsolike = fields.TextField('Content Also Like', default='')
    forrev = fields.SelectField('For or Rev', default='e',
                                choices=[('f', 'Forward'), ('r', 'Reverse'), ('e', 'Either')])
    domain = fields.SelectField('Domain', default='any')
    type_ = fields.SelectField('Record Type', default='any',
                               choices=[('any', 'Any'), ('A', 'A'), ('PTR', 'PTR'), ('CNAME', 'CNAME'), ('MX', 'MX'),
                                        ('NS', 'NS'), ('SOA', 'SOA'), ('SRV', 'SRV'), ('TXT', 'TXT')])
    limit = fields.IntegerField('Limit', default=200)


def records_query(dbg=False):
    """View test 2nd database."""
    ddc = DropDownChoices()
    frm = RecordsForm(request.form)
    frm.domain.choices = ddc.domain()
    if dbg:
        print('asdf')
    records = db.session.query(Records.name, Records.id, Records.type, Records.domain_id, Records.type, Records.content,
                               Records.ttl, Records.prio, Records.change_date, Records.disabled, Records.ordername,
                               Records.auth, Domains.name.label('dname'))\
                .join(Domains, Domains.id == Records.domain_id)
    if frm.recordlike.data != '':
        records = records.filter(Records.name.like('%%%s%%' % (frm.recordlike.data)))
    if frm.recordalsolike.data != '':
        records = records.filter(Records.name.like('%%%s%%' % (frm.recordalsolike.data)))
    if frm.contentlike.data != '':
        records = records.filter(Records.content.like('%%%s%%' % (frm.contentlike.data)))
    if frm.contentalsolike.data != '':
        records = records.filter(Records.content.like('%%%s%%' % (frm.contentalsolike.data)))
    if frm.forrev.data == 'r':
        records = records.filter(Domains.name.like('%%in-addr.arpa'))
    elif frm.forrev.data == 'f':
        records = records.filter(db.not_(Domains.name.like('%%in-addr.arpa')))
    if frm.domain.data != 'any':
        records = records.filter(Records.domain_id == frm.domain.data)
    if frm.type_.data != 'any':
        records = records.filter(Records.type == frm.type_.data)
    records = records.order_by(Records.name)
    if frm.limit.data:
        records = records.limit(frm.limit.data)

    return (frm, records)


@app.route('/query_records', methods=['GET', 'POST'])
@login_required
def query_records():
    """View Domain table direct from the database with 2nd bind."""
    (frm, records) = records_query()
    return render_template('query/records.html', frm=frm, records=records)


@app.route('/query_records_reload', methods=['GET', 'POST'])
@login_required
def query_records_reload():
    """Route to reload the table without reloading the page."""
    (frm, records) = records_query(dbg=False)
    return render_template('query/records_reload.html', frm=frm, records=records)
