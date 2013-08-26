#!/usr/bin/env python

from ldns import ldns_resolver
import ldns
import random

def sanitize_name(name):
    if name[-1] == '.':
        return name
    else:
        return '%s.' % name

def get_delegation(zone_name):
    zone_name = sanitize_name(zone_name)
    ref_list = [
            'a.root-servers.net',
            'b.root-servers.net',
            'c.root-servers.net',
            'd.root-servers.net',
            'e.root-servers.net',
            'f.root-servers.net',
            'g.root-servers.net',
            'h.root-servers.net',
            'i.root-servers.net',
            'j.root-servers.net',
            'k.root-servers.net',
            'l.root-servers.net',
            'm.root-servers.net']

    while True:
        nonrec_res = ldns_resolver.new_frm_file()
        nonrec_res.set_recursive(False)

        while nonrec_res.nameserver_count():
            nonrec_res.pop_nameserver()
        ans_pkt = None
        random.shuffle(ref_list)

        for ref in ref_list:
            while nonrec_res.nameserver_count():
                nonrec_res.pop_nameserver()
            addr_list = res.get_addr_by_name(ref)
            for num in range(addr_list.rr_count()):
                addr = addr_list.rr(num)
                if addr.get_type_str() == 'A':
                    nonrec_res.push_nameserver(addr.a_address())
            ans_pkt = nonrec_res.query(zone_name, ldns.LDNS_RR_TYPE_SOA, ldns.LDNS_RR_CLASS_IN)
            print ans_pkt
            if ans_pkt:
                break

        if ans_pkt.reply_type() == ldns.LDNS_PACKET_REFERRAL:
            # We got a referral from the upstream nameserver
            auth_list = ans_pkt.authority()
            add_list = ans_pkt.additional()
            ref_list = []
            for num in range(auth_list.rr_count()):
                ref_list.append(str(auth_list.rr(num).ns_nsdname()))
            if auth_list.owner() == zone_name:
                # we got the final referral :D
                # Save the NS records in the authority section to a global list
                return ref_list
        elif ans_pkt.reply_type() == ldns.LDNS_PACKET_ANSWER:
            # we reached the correct nameserver. This happens when the
            # nameserver for example.com is also authoritative for
            # sub.example.com and .com has send us a referral to example.com
            return ref_list
        elif ans_pkt.reply_type() == ldns.LDNS_PACKET_NODATA:
            # This is possibly not a zone
            return []

def check_delegation(zone_name, ns_list):
    nonrec_res = ldns_resolver.new_frm_file()
    nonrec_res.set_recursive(False)

    for ns in ns_list:
        # Remove all nameservers from the resolver
        while nonrec_res.nameserver_count():
            nonrec_res.pop_nameserver()

# A global DNSSEC resolver... bacause we can
res = ldns_resolver.new_frm_file()
res.push_dnssec_anchor(ldns.ldns_rr.new_frm_str('.    172800  IN  DNSKEY  257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaDX6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpzW5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relSQageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0='))
res.set_dnssec(True)

#from_upstream = get_delegation('ec2.kumina.nl')
from_upstream = get_delegation('dnssec-failed.org')
print from_upstream

# TODO
# - IPv4/IPv6 selection
# - debug output
# - Expected ns RRSets
