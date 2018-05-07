"""Base Classes."""

import itertools
# pylint: disable=E0401
import urlparse
import re
import traceback
import json
from pprint import pformat

# pylint: disable=E0611
from distutils.util import strtobool

from flask_login import AnonymousUserMixin, current_user
import dns.reversename
from app import app, db, PDNS_STATS_URL, LOGGING, PDNS_API_KEY, API_EXTENDED_URL, NEW_SCHEMA, PRETTY_IPV6_PTR
# pylint: disable=E0611
from app.lib import utils
from .models import History, Domain, DomainSetting, Setting, Rrset, UserGroup, UserGroupUser, DomainGroup, \
    DomainGroupDomain, DomainGroupUserGroup, DomainUser
# pylint: disable=W0703,R1705,E1101


def booleanval(val):
    """Function to return boolean."""
    # pylint: disable=R1703
    if val in ['true', '1', 't', 'y', 'yes', 'Y', 'T', True, 'True']:
        return True
    else:
        return False


def intsafe(inval):
    """Turn a value into a integer without epic fail."""
    # pylint: disable=R1703
    val = inval
    try:
        test = val.split('.')
        if len(test) > 1:
            val = test[0]
    except Exception:
        pass
    try:
        val = int(val)
    except Exception:
        val = 0
    return val


def query_acldomains_fromuser(userid):
    """Build a query for finding domains from known user."""
    dgqry = db.session.query(DomainGroupDomain.domain_id)\
              .join(DomainGroupUserGroup, DomainGroupUserGroup.domaingroup_id == DomainGroupDomain.domaingroup_id)\
              .join(UserGroupUser, UserGroupUser.usergroup_id == DomainGroupUserGroup.usergroup_id)\
              .filter(UserGroupUser.user_id == userid)
    return dgqry
    

def allowed_domains():
    """Build a query to populate domains with user and group acls considered."""
    if current_user.role.name == 'Administrator':
        netqry = db.session.query(Domain).all()
    else:
        duqry = db.session.query(Domain.id) \
                  .join(DomainUser)\
                  .filter(DomainUser.user_id == current_user.id)\
                  .subquery('duqry')
        dgqry = query_acldomains_fromuser(current_user.id)
        dgqry = dgqry.subquery('dgqry')
        netqry = db.session.query(Domain)\
                   .filter(db.or_(Domain.id.in_(dgqry), Domain.id.in_(duqry)))\
                   .all()
    return netqry


def is_allowed_domain(domainname, current_user_id, checkrole=True):
    """Build a query to populate domains with user and group acls considered."""
    domidqry = db.session.query(Domain.id)\
                 .filter(Domain.name == domainname)\
                 .first()
    retval = True
    if domidqry:
        if checkrole:
            duqry = db.session.query(Domain.id) \
                      .join(DomainUser)\
                      .filter(DomainUser.user_id == current_user_id)\
                      .subquery('duqry')
        dgqry = query_acldomains_fromuser(current_user_id)
        dgqry = dgqry.subquery('dgqry')
    
        netqry = db.session.query(Domain.id)
        if checkrole:
            netqry = netqry.filter(db.or_(Domain.id.in_(dgqry), Domain.id.in_(duqry)))
        else:
            netqry = netqry.filter(Domain.id.in_(dgqry))
        netqry = netqry.filter(Domain.id == domidqry.id)\
                       .all()
        if netqry:
            retval = True
        else:
            retval = False

    return retval

class DisplayUserAcls(object):
    """Helper class for displaying what user groups and domain groups they are members of."""

    def __init__(self):
        """Perform queries and manipulate for easy retrival from template."""
        ugroups_qry = db.session.query(UserGroup)
        self.ugroups_dct = {}
        for item in ugroups_qry:
            self.ugroups_dct[item.id] = item

        dgroups_qry = db.session.query(DomainGroup)
        self.dgroups_dct = {}
        for item in dgroups_qry:
            self.dgroups_dct[item.id] = item

        qry = db.session.query(UserGroupUser).all()
        self.ugu_dict = {}
        for item in qry:
            if item.user_id not in self.ugu_dict:
                self.ugu_dict[item.user_id] = [item.usergroup_id]
            else:
                self.ugu_dict[item.user_id].append(item.usergroup_id)

        usr_domainqry = db.session.query(UserGroupUser.user_id, DomainGroupUserGroup.domaingroup_id)\
                          .join(DomainGroupUserGroup, DomainGroupUserGroup.usergroup_id == UserGroupUser.usergroup_id)\
                          .order_by(UserGroupUser.user_id)
        self.userdomain_dct = {}
        for item in usr_domainqry:
            if item.user_id not in self.userdomain_dct:
                self.userdomain_dct[item.user_id] = [item.domaingroup_id]
            else:
                self.userdomain_dct[item.user_id].append(item.domaingroup_id)

    def usergroups(self, user_id):
        """Return User groups the passed user belongs to."""
        retval = []
        if user_id in self.ugu_dict:
            for usergroup_id in self.ugu_dict[user_id]:
                retval.append(self.ugroups_dct[usergroup_id])
        return retval

    def domaingroups(self, user_id):
        """Return Domain groups the passed user belongs to."""
        retval = []
        if user_id in self.userdomain_dct:
            for domaingroup_id in self.userdomain_dct[user_id]:
                retval.append(self.dgroups_dct[domaingroup_id])
        return retval


class Anonymous(AnonymousUserMixin):
    """Class for Anonomous User."""

    # pylint: disable=R0903
    def __init__(self):
        """Set the username to Anonymous, it's a flask thing."""
        self.username = 'Anonymous'


class Record(object):
    """
    Record object, Not a model.

    Object used to communicate with PowerDNS API
    """

    # pylint: disable=C0103,R0913,W0622,r0902
    def __init__(self, name=None, type=None, status=False, ttl=None, data=None, rrsetid=None):
        """Initialize values for class Record."""
        self.name = name
        self.type = type
        self.status = status
        self.ttl = ttl
        self.data = data
        self.current_records = []
        self.priority = None
        self.unique_key = None
        self.rrsetid = rrsetid
        self.records_delete = []
        self.net_final = []
        self.fnl_recs = []

    def get_record_data(self, domain, fetchonly=False):
        """Query domain's DNS records via API."""
        # if we already know the rrset id, means we need to pull it from the database when we got it before.
        if self.rrsetid:
            rrsetid = int(self.rrsetid)
            rrset_record = db.session.query(Rrset)\
                             .filter(Rrset.rrsetid == rrsetid)\
                             .first()
            return {'records': rrset_record.rrsets}
        headers = {}
        headers['X-API-Key'] = PDNS_API_KEY
        try:
            jdata = utils.fetch_json(urlparse.urljoin(PDNS_STATS_URL,
                                                      API_EXTENDED_URL + '/servers/localhost/zones/%s' % domain),
                                     headers=headers)
        except Exception:
            LOGGING.error("Cannot fetch domain's record data from remote powerdns api")
            return False

        if NEW_SCHEMA and not fetchonly:
            rrsets = jdata['rrsets']
            for rrset in rrsets:
                r_name = rrset['name'].rstrip('.')
                if PRETTY_IPV6_PTR:  # only if activated
                    if rrset['type'] == 'PTR':  # only ptr
                        if 'ip6.arpa' in r_name:  # only if v6-ptr
                            r_name = dns.reversename.to_address(dns.name.from_text(r_name))

                rrset['name'] = r_name
                rrset['content'] = rrset['records'][0]['content']
                rrset['disabled'] = rrset['records'][0]['disabled']
            rrset_ = Rrset(rrsets=rrsets)
            db.session.add(rrset_)
            db.session.commit()
            self.rrsetid = rrset_.rrsetid
            return {'records': rrsets}

        return jdata

    def add(self, domain, created_by=None):
        """Add a record to domains."""
        # validate record first
        rec = self.get_record_data(domain)
        # pylint: disable=W0110
        records = rec['records']
        check = filter(lambda check: check['name'] == self.name, records)
        if check:
            # pylint: disable=E1136
            rec = check[0]
            if rec['type'] in ('A', 'AAAA', 'CNAME'):
                return {'status': 'error', 'msg': 'Record already exists with type "A", "AAAA" or "CNAME"'}

        # continue if the record is ready to be added
        headers = {}
        headers['X-API-Key'] = PDNS_API_KEY

        if NEW_SCHEMA:
            data = {"rrsets": [{"name": self.name.rstrip('.') + '.',
                                "type": self.type,
                                "changetype": "REPLACE",
                                "ttl": self.ttl,
                                "records": [{"content": self.data,
                                             "disabled": self.status, }]}]}
        else:
            data = {"rrsets": [{"name": self.name,
                                "type": self.type,
                                "changetype": "REPLACE",
                                "records": [{"content": self.data,
                                             "disabled": self.status,
                                             "name": self.name,
                                             "ttl": self.ttl,
                                             "type": self.type}]}]}

        try:
            url = urlparse.urljoin(PDNS_STATS_URL, API_EXTENDED_URL + '/servers/localhost/zones/%s' % domain)
            LOGGING.debug('add data to pdns server %s', data)
            current = self.getcurrent_onrecord(domain)
            LOGGING.debug('rec.add() current "%s" "%s" "%s"', current, domain, self.name)
            jdata = utils.fetch_json(url, headers=headers, method='PATCH', data=data)
            LOGGING.debug('fetch_json result %s', jdata)
            self.history_write(domain, current, data['rrsets'], 'REPLACE', name=self.name, created_by=created_by)
            return {'status': 'ok', 'msg': 'Record was added successfully'}
        except Exception as e:
            LOGGING.error("Cannot add record %s/%s/%s to domain %s. DETAIL: %s",
                          self.name, self.type, self.data, domain, str(e))
            return {'status': 'error', 'msg': 'There was something wrong in Add, please contact administrator'}

    def compare(self, domain_name, new_records):
        """Compare new records with current powerdns record data.

        Input is a list of hashes (records)
        """
        # get list of current records we have in powerdns
        self.current_records = self.get_record_data(domain_name)['records']

        # convert them to list of list (just has [name, type]) instead of list of hash
        # to compare easier
        list_current_records = [[x['name'], x['type']] for x in self.current_records]
        list_new_records = [[x['name'], x['type']] for x in new_records]

        # get list of deleted records
        # they are the records which exist in list_current_records but not in list_new_records
        list_deleted_records = [x for x in list_current_records if x not in list_new_records]

        # convert back to list of hash
        deleted_records = [x for x in self.current_records
                           if [x['name'], x['type']] in list_deleted_records and
                           x['type'] in app.config['RECORDS_ALLOW_EDIT']]

        # return a tuple
        return deleted_records, new_records

    def apply(self, domain, post_records):
        """Apply record changes to domain."""
        # pylint: disable=R0912,R0915,R0914
        LOGGING.info('apply() domain is %s', (domain))
        records = []
        for r in post_records:
            r_name = domain if r['record_name'] in ['@', ''] else r['record_name'] + '.' + domain
            r_type = r['record_type']
            if PRETTY_IPV6_PTR:  # only if activated
                if NEW_SCHEMA:  # only if new schema
                    if r_type == 'PTR':  # only ptr
                        if ':' in r['record_name']:  # dirty ipv6 check
                            r_name = r['record_name']

            record = {"name": r_name,
                      "type": r_type,
                      "content": r['record_data'],
                      "disabled": True if r['record_status'] == 'Disabled' else False,
                      "ttl": int(r['record_ttl']) if r['record_ttl'] else 3600, }
            records.append(record)

        deleted_records, new_records = self.compare(domain, records)

        self.records_delete = []
        for r in deleted_records:
            r_name = r['name'].rstrip('.') + '.' if NEW_SCHEMA else r['name']
            r_type = r['type']
            if PRETTY_IPV6_PTR:  # only if activated
                if NEW_SCHEMA:  # only if new schema
                    if r_type == 'PTR':  # only ptr
                        if ':' in r['name']:  # dirty ipv6 check
                            r_name = dns.reversename.from_address(r['name']).to_text()

            record = {"name": r_name,
                      "type": r_type,
                      "changetype": "DELETE",
                      "records": [], }
            self.records_delete.append(record)

        # postdata_for_delete = {"rrsets": self.records_delete}

        records = []
        for r in new_records:
            if NEW_SCHEMA:
                r_name = r['name'].rstrip('.') + '.'
                r_type = r['type']
                if PRETTY_IPV6_PTR:  # only if activated
                    if r_type == 'PTR':  # only ptr
                        if ':' in r['name']:  # dirty ipv6 check
                            r_name = r['name']

                record = {"name": r_name,
                          "type": r_type,
                          "changetype": "REPLACE",
                          "ttl": r['ttl'],
                          "records": [{"content": r['content'],
                                       "disabled": r['disabled'], }]}
            else:
                # priority field for pdns 3.4.1.
                # https://doc.powerdns.com/md/authoritative/upgrading/
                record = {"name": r['name'],
                          "type": r['type'],
                          "changetype": "REPLACE",
                          "records": [{"content": r['content'],
                                       "disabled": r['disabled'],
                                       "name": r['name'],
                                       "ttl": r['ttl'],
                                       "type": r['type'],
                                       "priority": 10, }]}

            records.append(record)

        # Adjustment to add multiple records which described in
        # https://github.com/ngoduykhanh/PowerDNS-Admin/issues/5#issuecomment-181637576
        self.fnl_recs = []
        records = sorted(records, key=lambda item: (item["name"], item["type"], item["changetype"]))
        for key, group in itertools.groupby(records, lambda item: (item["name"], item["type"], item["changetype"])):
            if NEW_SCHEMA:
                r_name = key[0]
                r_type = key[1]
                r_changetype = key[2]

                if PRETTY_IPV6_PTR:  # only if activated
                    if r_type == 'PTR':  # only ptr
                        if ':' in r_name:  # dirty ipv6 check
                            r_name = dns.reversename.from_address(r_name).to_text()

                new_record = {"name": r_name,
                              "type": r_type,
                              "changetype": r_changetype,
                              "ttl": None,
                              "records": [], }
                for item in group:
                    temp_content = item['records'][0]['content']
                    temp_disabled = item['records'][0]['disabled']
                    if key[1] in ['MX', 'CNAME', 'SRV', 'NS']:
                        if temp_content.strip()[-1:] != '.':
                            temp_content += '.'

                    if new_record['ttl'] is None:
                        new_record['ttl'] = item['ttl']
                    new_record['records'].append({
                        "content": temp_content,
                        "disabled": temp_disabled
                    })
                self.fnl_recs.append(new_record)

            else:

                self.fnl_recs.append({"name": key[0],
                                      "type": key[1],
                                      "changetype": key[2],
                                      "records": [{"content": item['records'][0]['content'],
                                                   "disabled": item['records'][0]['disabled'],
                                                   "name": key[0],
                                                   "ttl": item['records'][0]['ttl'],
                                                   "type": key[1],
                                                   "priority": 10, } for item in group]})
        self.final_records_limit()
        postdata_for_changes = {"rrsets": self.net_final}
        LOGGING.info('apply() postdata_for_changes is %s', (json.dumps(postdata_for_changes)))

        try:
            headers = {}
            headers['X-API-Key'] = PDNS_API_KEY
            url = urlparse.urljoin(PDNS_STATS_URL, API_EXTENDED_URL + '/servers/localhost/zones/%s' % domain)
            # utils.fetch_json(url, headers=headers, method='PATCH', data=postdata_for_delete)
            jdata2 = utils.fetch_json(url, headers=headers, method='PATCH', data=postdata_for_changes)

            if 'error' in jdata2.keys():
                LOGGING.error('Cannot apply record changes.')
                LOGGING.debug(jdata2['error'])
                return {'status': 'error', 'msg': jdata2['error']}
            else:
                # should this get postdata_for_changes ??? instead of the deprecated new_records, deleted_records
                # postdata_for_changes is final_records_limit
                if not re.search('in-addr.arpa', domain):
                    self.auto_ptr(domain)

                LOGGING.debug("update dyndns data: %s", postdata_for_changes)
                LOGGING.debug("update dyndns url: %s", url)

                LOGGING.info('Record was applied successfully.')
                self.history_log_apply(domain)
                return {'status': 'ok', 'msg': 'Record was applied successfully'}

        except Exception as error:
            LOGGING.error("Cannot apply record changes to domain %s. DETAIL: %s", str(error), domain)
            return {'status': 'error', 'msg': 'There was something wrong, please contact administrator'}

    def history_log_apply(self, domain_name):
        """Write history Record to database."""
        for key in self.unique_key:
            testme = self.unique_key[key]
            if not testme['same']:
                if testme['change_type'] == 'ADD':
                    current = None
                    changetype = 'ADD'
                    final = self.fnl_recs[testme['final_records']]
                elif testme['change_type'] == 'DELETE':
                    current = None
                    changetype = 'DELETE'
                    final = self.fnl_recs[testme['delete_records']]
                else:
                    current = self.current_records[testme['current_records']]
                    changetype = 'REPLACE'
                    final = self.fnl_recs[testme['final_records']]
                self.history_write(domain_name, current, final, changetype)

    @classmethod
    def history_write(cls, domain_name, fromdata, todata, changetype, name=None, detail=None, created_by=None):
        """Write the history record."""
        if not created_by:
            created_by = current_user.username
        if not detail:
            detail = ''
        if not fromdata:
            fromdata = ''
        history = History(msg='Apply record change to domain %s' % domain_name, name=name, domain=domain_name,
                          detail=detail, created_by=created_by, fromdata=fromdata, todata=todata,
                          changetype=changetype)
        db.session.add(history)
        db.session.commit()

    def final_records_limit(self):
        """limit the number of replace changes, for LOGGING."""
        # pylint: disable=R0912,R0915,R0914
        # a key to unique identify all records wether added, deleted or modified
        self.unique_key = {}
        notcurrent = []
        re_endindot = re.compile(r'\.$')
        typeavoid = ['SOA', 'NS']
        for position, item in enumerate(self.fnl_recs):
            if item['type'] not in typeavoid:
                key = (item['name'], item['type'])
                self.unique_key[key] = {'final_records': position, 'same': False}
        for position, item in enumerate(self.records_delete):
            if item['type'] not in typeavoid:
                key = (item['name'], item['type'])
                self.unique_key[key] = {'delete_records': position, 'same': False}
        for position, item in enumerate(self.current_records):
            if item['type'] not in typeavoid:
                name = item['name']
                if not re_endindot.search(name):
                    name = '%s.' % (name)
                key = (name, item['type'])
                if key in self.unique_key:
                    self.unique_key[key]['current_records'] = position
                else:
                    notcurrent.append(key)
                    self.unique_key[key] = {'current_records': position, 'same': False}

        # Now we know the list of all records modified, and we know what position they are in the lists of
        # self.current_records and self.fnl_recs

        samecnt = 0
        lencnt = 0
        ttlcnt = 0
        discnt = 0
        reccnt = 0
        for key in self.unique_key:
            # now for this record we can find if it is the same or edited
            testme = self.unique_key[key]
            if 'current_records' not in testme and 'final_records' in testme and 'delete_records' not in testme:
                # this is an add, does not matter if it is the same
                testme['change_type'] = 'ADD'
            elif 'current_records' in testme and 'final_records' not in testme and 'delete_records' in testme:
                # this is a delete, does not matter if it is the same
                testme['change_type'] = 'DELETE'
            elif 'current_records' in testme and 'final_records' in testme and 'delete_records' not in testme:
                testme['change_type'] = 'REPLACE'
                current = self.current_records[testme['current_records']]
                final = self.fnl_recs[testme['final_records']]
                same = True
                # test for the number of records
                if len(current['records']) != len(final['records']):
                    same = False
                    lencnt += 1
                # test for the content being the same
                for currec in current['records']:
                    isinfinal = False
                    for finrec in final['records']:
                        if currec['content'] == finrec['content']:
                            isinfinal = True
                    if not isinfinal:
                        same = False
                        reccnt += 1
                # test for the ttl being the same
                if current['ttl'] != final['ttl']:
                    same = False
                    ttlcnt += 1
                # test for disabled being the same
                if final['records'] and current['disabled'] != final['records'][0]['disabled']:
                    same = False
                    discnt += 1
                if same:
                    samecnt += 1
                testme['same'] = same

        self.net_final = []
        for key in self.unique_key:
            testme = self.unique_key[key]
            if testme['same'] is False:
                if testme['change_type'] == 'DELETE':
                    self.net_final.append(self.records_delete[testme['delete_records']])
                else:
                    self.net_final.append(self.fnl_recs[testme['final_records']])
        return

    def auto_ptr(self, domain):
        """Add auto-ptr records."""
        retval = None

        domain_obj = Domain.query.filter(Domain.name == domain).first()
        domain_auto_ptr = DomainSetting.query.filter(DomainSetting.domain == domain_obj) \
                                             .filter(DomainSetting.setting == 'auto_ptr') \
                                             .first()
        domain_auto_ptr = strtobool(domain_auto_ptr.value) if domain_auto_ptr else False

        system_auto_ptr = Setting.query.filter(Setting.name == 'auto_ptr').first()
        system_auto_ptr = strtobool(system_auto_ptr.value)

        if system_auto_ptr or domain_auto_ptr:
            dom_ = Domain()
            for key in self.unique_key:
                testme = self.unique_key[key]
                if testme['same'] is False:
                    current = None
                    if 'current_records' in testme:
                        current = self.current_records[testme['current_records']]
                    # LOGGING.info('current is %s' % (current))
                    if current['type'] == 'A':
                        if testme['change_type'] == 'DELETE':
                            r_content = current['content']
                            reverse_host_address = dns.reversename.from_address(r_content).to_text()
                            domain_reverse_name = dom_.get_reverse_domain_name(reverse_host_address)
                            self.name = reverse_host_address
                            self.type = 'PTR'
                            self.data = r_content
                            self.delete(domain_reverse_name)
                        else:
                            r_content = current['content']
                            reverse_host_address = dns.reversename.from_address(r_content).to_text()
                            domain_reverse_name = dom_.get_reverse_domain_name(reverse_host_address)
                            dom_.create_reverse_domain(domain, domain_reverse_name)

        return retval

    def delete(self, domain):  # , username=None):
        """Delete a record from domain."""
        headers = {}
        headers['X-API-Key'] = PDNS_API_KEY
        data = {"rrsets": [{"name": self.name.rstrip('.') + '.',
                            "type": self.type,
                            "changetype": "DELETE",
                            "records": [], }]}
        try:
            url = urlparse.urljoin(PDNS_STATS_URL, API_EXTENDED_URL + '/servers/localhost/zones/%s' % domain)
            jdata = utils.fetch_json(url, headers=headers, method='PATCH', data=data)
            LOGGING.debug(jdata)
            return {'status': 'ok', 'msg': 'Record was removed successfully'}
        except Exception:
            LOGGING.error("Cannot remove record %s/%s/%s from domain %s", self.name, self.type, self.data, domain)
            return {'status': 'error', 'msg': 'There was something wrong in delete, please contact administrator'}

    def is_allowed(self):
        """Check if record is allowed to edit/removed."""
        return self.type in app.config['RECORDS_ALLOW_EDIT']

    def exists(self, domain):
        """Check if record is present within domain records.

        and if it's present set self to found record
        """
        jdata = self.get_record_data(domain)
        jrecords = jdata['records']

        for jr in jrecords:
            if jr['name'] == self.name:
                self.name = jr['name']
                self.type = jr['type']
                self.status = jr['disabled']
                self.ttl = jr['ttl']
                self.data = jr['content']
                self.priority = 10
                return True
        return False

    def update(self, domain, content, username):
        """Update single record."""
        headers = {}
        headers['X-API-Key'] = PDNS_API_KEY

        if NEW_SCHEMA:
            data = {"rrsets": [{"name": self.name,
                                "type": self.type,
                                "ttl": self.ttl,
                                "changetype": "REPLACE",
                                "records": [{"content": content,
                                             "disabled": self.status, }]}]}
        else:
            data = {"rrsets": [{"name": self.name,
                                "type": self.type,
                                "changetype": "REPLACE",
                                "records": [{"content": content,
                                             "disabled": self.status,
                                             "name": self.name,
                                             "ttl": self.ttl,
                                             "type": self.type,
                                             "priority": 10, }]}]}
        try:
            url = urlparse.urljoin(PDNS_STATS_URL, API_EXTENDED_URL + '/servers/localhost/zones/%s' % domain)
            # LOGGING.debug("update dyndns data: %s", data)
            # LOGGING.debug("update dyndns domain: %s", domain)
            current = self.getcurrent_onrecord(domain)
            utils.fetch_json(url, headers=headers, method='PATCH', data=data)
            self.history_write(domain, current, data, 'REPLACE', name=self.name, created_by=username)
            LOGGING.debug("update dyndns data: %s", data)
            # LOGGING.debug("update dyndns url: %s", url)
            return {'status': 'ok', 'msg': 'Record was updated successfully'}
        except Exception as e:
            LOGGING.error("Cannot add record %s/%s/%s to domain %s. DETAIL: %s",
                          self.name, self.type, self.data, domain, str(e))
            return {'status': 'error', 'msg': 'There was something wrong in update, please contact administrator'}

    def getcurrent_onrecord(self, domain):
        """For history, we want the current status of a name."""
        # self.name is required to be the name we are looking for
        retval = dict()
        LOGGING.debug('getcurrent_onrecord() domain "%s" "%s"', domain, self.name)
        jdata = self.get_record_data(domain, fetchonly=True)
        rrsets = None
        if 'rrsets' in jdata:
            rrsets = jdata['rrsets']
            findme = self.name
        if 'records' in jdata:
            rrsets = jdata['records']
            re_endindot = re.compile(r'\.$')
            findme = re_endindot.sub('', self.name)
        LOGGING.debug("getcurrent_onrecord findme : %s self.name %s", findme, self.name)
        cnter = None
        if rrsets:
            LOGGING.debug("getcurrent_onrecord iterating to find of name : %s", findme)
            for cnter, item in enumerate(rrsets):
                if item['name'] == findme:
                    retval = item
        LOGGING.debug("getcurrent_onrecord returning : %s searching for %s in %s records", pformat(retval),
                      self.name, cnter)
        return retval


class Server(object):
    """This is not a model, it's just an object.

    Assigned data from PowerDNS API
    """

    def __init__(self, server_id=None, server_config=None):
        """Initialize Values."""
        self.server_id = server_id
        self.server_config = server_config

    def get_config(self):
        """Get server config."""
        headers = {}
        headers['X-API-Key'] = PDNS_API_KEY

        try:
            url = urlparse.urljoin(PDNS_STATS_URL, API_EXTENDED_URL + '/servers/%s/config' % self.server_id)
            jdata = utils.fetch_json(url, headers=headers, method='GET')
            return jdata
        except Exception:
            LOGGING.error("Can not get server configuration.")
            LOGGING.debug(traceback.format_exc())
            return []

    def get_statistic(self):
        """Get server statistics."""
        headers = {}
        headers['X-API-Key'] = PDNS_API_KEY

        try:
            url = urlparse.urljoin(PDNS_STATS_URL, API_EXTENDED_URL + '/servers/%s/statistics' % self.server_id)
            jdata = utils.fetch_json(url, headers=headers, method='GET')
            return jdata
        except Exception:
            LOGGING.error("Can not get server statistics.")
            LOGGING.debug(traceback.format_exc())
            return []
