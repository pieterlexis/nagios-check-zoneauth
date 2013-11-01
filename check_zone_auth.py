#!/usr/bin/env python

import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import random
import socket
import sys

def ok(msg):
    global zone_name
    print "ZONE %s OK: %s" % (zone_name, msg)
    sys.exit(0)

def critical(msg):
    global zone_name
    print "ZONE %s CRITAL: %s" % (zone_name, msg)
    sys.exit(1)

def warning(msg):
    global zone_name
    print "ZONE %s WARNING: %s" % (zone_name, msg)
    sys.exit(2)

def unknown(msg):
    global zone_name
    print "ZONE %s UNKNOWN: %s" % (zone_name, msg)
    sys.exit(3)

def sanitize_name(name):
    if name[-1] == '.':
        return name
    else:
        return '%s.' % name

def IP_version(address):
    try:
        v4 = socket.inet_pton(socket.AF_INET,ipaddr)
        return 4
    except:
        try:
            v6 = socket.inet_pton(socket.AF_INET6,ipaddr)
            return 6
        except:
            return 0

def get_reply_type(msg):
    """ Returns the reply type of the message
    Code and return values taken from ldns"""

    if not isinstance(msg, dns.message.Message):
        return 'UNKNOWN'

    if msg.rcode == dns.rcode.NXDOMAIN:
        return 'NXDOMAIN'

    if not len(msg.answer) and not len(msg.additional) and len(msg.authority) == 1:
        if msg.authority[0].rdtype == dns.rdatatype.SOA:
            return 'NODATA'

    if not len(msg.answer) and len(msg.authority):
        has_ns = False
        for auth_rrset in msg.authority:
            if auth_rrset.rdtype == dns.rdatatype.NS:
                has_ns = True
                break
        if has_ns:
            return 'REFERRAL'

    # A little sketchy, but if the message is nothing of the above,
    # we'll label it as an answer
    return 'ANSWER'

def get_delegation(zone_name):
    # let's have the root-servers as initial glue :)
    refs = {
        'A.ROOT-SERVERS.NET.': ['198.41.0.4', '2001:503:BA3E::2:30'],
        'B.ROOT-SERVERS.NET.': ['192.228.79.201'],
        'C.ROOT-SERVERS.NET.': ['192.33.4.12'],
        'D.ROOT-SERVERS.NET.': ['199.7.91.13', '2001:500:2D::D'],
        'E.ROOT-SERVERS.NET.': ['192.203.230.10'],
        'F.ROOT-SERVERS.NET.': ['192.5.5.241', '2001:500:2F::F'],
        'G.ROOT-SERVERS.NET.': ['192.112.36.4'],
        'H.ROOT-SERVERS.NET.': ['128.63.2.53', '2001:500:1::803F:235'],
        'I.ROOT-SERVERS.NET.': ['192.36.148.17', '2001:7FE::53'],
        'J.ROOT-SERVERS.NET.': ['192.58.128.30', '2001:503:C27::2:30'],
        'K.ROOT-SERVERS.NET.': ['193.0.14.129', '2001:7FD::1'],
        'L.ROOT-SERVERS.NET.': ['199.7.83.42', '2001:500:3::42'],
        'M.ROOT-SERVERS.NET.': ['202.12.27.33', '2001:DC3::35']
    }

    qmsg = dns.message.make_query(zone_name, dns.rdatatype.SOA)

    while True:
        ans_pkt = None
        ref_list = random.sample(refs, len(refs))

        for ref in ref_list:
            for addr in refs[ref]:
                ans_pkt = dns.query.udp(qmsg, addr, timeout=3)
                if ans_pkt:
                    break

        # Check if the answer-packet is
        # a referral, an answer or NODATA
        reply_type = get_reply_type(ans_pkt)
        if reply_type == 'REFERRAL':
            # We got a referral from the upstream nameserver
            final_ref = False
            refs = {}
            for rrset in ans_pkt.authority:
                if rrset.rdtype == dns.rdatatype.NS:
                    for ns in rrset:
                        refs[str(ns)] = []
                    if str(rrset.name) == zone_name:
                        final_ref = True
            for rrset in ans_pkt.additional:
                # hopefully we got some glue :)
                if rrset.rdtype == dns.rdatatype.AAAA or rrset.rdtype == dns.rdatatype.A:
                    for glue in rrset:
                        refs[str(rrset.name)].append(str(glue))

            if final_ref:
                return refs
            if len(refs):
                # Go to the next iteration
                continue
            else:
                raise error('We got a referral without glue :(')

        elif reply_type == 'ANSWER':
            # we reached the correct nameserver. This happens when the
            # nameserver for example.com is also authoritative for
            # sub.example.com and .com has send us a referral to example.com
            # So return the refs from the 'previous' iteration
            return refs

        elif reply_type == 'NODATA':
            # zonename is most-likely not a zone
            return {}

def check_delegation(zone_name,data,expected_ns_list=None):
    max_serial = 0
    nscount = 0
    wanted_nameservers = []
    if expected_ns_list:
        wanted_nameservers = expected_ns_list
    for nameserver in data:
        for addr in data[nameserver]:
            print data[nameserver][addr]['SOA'].serial


def get_info_from_nameservers(zone_name,refs):
    soa_qmsg = dns.message.make_query(zone_name, dns.rdatatype.SOA)
    ns_qmsg = dns.message.make_query(zone_name, dns.rdatatype.NS)
    ret_data = {}
    for ns in refs:
        ret_data[ns] = {}
        for address in refs[ns]:
            ret_data[ns][address] = {}
            for tries in range(5):
                ret_data[ns][address]['SOA'] = dns.query.udp(soa_qmsg, address, timeout=5)
                if ret_data[ns][address]['SOA']:
                    if get_reply_type(ret_data[ns][address]['SOA']) == 'ANSWER':
                        break
                if tries > 4:
                    unknown('Could not get SOA record from %s at %s' % (ns, address))
            for tries in range(5):
                ret_data[ns][address]['NS'] = dns.query.udp(ns_qmsg, address, timeout=5)
                if ret_data[ns][address]['NS']:
                    break
                if tries > 4:
                    unknown('Could not get NS records from %s at %s' % (ns, address))
    return ret_data

zone_name = 'non-existing-domain.kumina.nl'
zone_name = 'ec2.kumina.nl'
zone_name = 'kumina.nl'
zone_name = sanitize_name(zone_name)
from_upstream = get_delegation(zone_name)

if len(from_upstream):
    if len(from_upstream) == 1:
        # Only one auth is delegated... that is not the right way
        warning('only one authoritative nameserver')
    # We got referrals
    data = get_info_from_nameservers(zone_name, from_upstream)
    print data
    check_delegation(zone_name, data)
else:
    unknown("No nameservers found, is %s a zone?" % zone_name)

# TODO
# - IPv4/IPv6 selection
# - debug output
# - Expected ns RRSets
