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
        v4 = socket.inet_pton(socket.AF_INET,address)
        return 4
    except:
        try:
            v6 = socket.inet_pton(socket.AF_INET6,address)
            return 6
        except:
            return 0

def do_query(qmsg, address, timeout=5, tries=5):
    ip_version = IP_version(address)
    global ip4
    global ip6
    if ip_version == 4 and not ip4:
        return False
    if ip_version == 6 and not ip6:
        return False
    for attempt in range(tries):
        try:
            return dns.query.udp(qmsg, address, timeout=timeout)
        except socket.error as error_msg:
            # If the error is "[Errno 101] Network is unreachable", there is no
            # ip_version connectivity, disable it for the rest of the run
            if str(error_msg) == '[Errno 101] Network is unreachable':
                # TODO use eval() for this
                if ip_version == 4:
                    ip4 = False
                    return False
                if ip_version == 6:
                    ip6 = False
                    return False
            else:
                raise
        except dns.exception.Timeout:
            if attempt == tries:
                raise

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
        for auth_rrset in msg.authority:
            if auth_rrset.rdtype == dns.rdatatype.NS:
                return 'REFERRAL'

    # A little sketchy, but if the message is nothing of the above,
    # we'll label it as an answer
    return 'ANSWER'

def get_delegation():
    global zone_name
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
                ans_pkt = do_query(qmsg, addr)
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

def is_same(items, field=False):
    return all(x == items[0] for x in items)

def check_delegation(data,expected_ns_list=None):
    global zone_name
    # First, check if all nameservers return the same data
    for nameserver in data:
        soa_list = []
        ns_list = []
        for addr in data[nameserver]:
            # Check if the data is for the correct name
            if len(data[nameserver][addr]['SOA'].answer) > 1:
                critical("Nameserver %s on %s returned more than one answer on a SOA query" % (nameserver, addr))

            for answer in data[nameserver][addr]['SOA'].answer:
                if not str(answer.name) == zone_name:
                    critical("Name on SOA record returned by %s on %s is not the zone name (%s vs %s)" % (nameserver, addr, answer.name, zone_name))
            soa_list.append(data[nameserver][addr]['SOA'].answer)

            for answer in data[nameserver][addr]['NS'].answer:
                if not str(answer.name) == zone_name:
                    critical("Name on NS record returned by %s on %s is not the zone name (%s vs %s)"
                            % (nameserver, addr, answer.name, zone_name))
            ns_list.append(data[nameserver][addr]['NS'].answer)

    if is_same(soa_list) and is_same(ns_list):
        if expected_ns_list:
            # check the NS records against the list of wanted nameservers
            for nameserver in data:
                for addr in data[nameserver]:
                    for ans in data[nameserver][addr]['NS'].answer:
                        comp_list = []
                        if ans.rdtype != 2:
                            continue
                        for ns in ans.to_text().split("\n"):
                            comp_list.append(ns.split(' ')[4])
                        if sorted(comp_list) != sorted(expected_ns_list):
                            critical('Got unexpected NS records, expected %s, got %s from %s at %s'
                                    % (','.join(sorted(expected_ns_list)),
                                        ','.join(sorted(comp_list)), nameserver,
                                        addr))
        # If we're here, we got the correct nameservers.
        ok('got %s as nameservers' % ','.join(sorted(comp_list)))
    else:
        if not is_same(soa_list):
            ns_name = []
            ns_addr = []
            soa_ns = []
            soa_serial = []
            for nameserver in data:
                for addr in data[nameserver]:
                    ns_name.append(nameserver)
                    ns_addr.append(addr)
                    soa_serial.append(int(data[nameserver][addr]['SOA'].answer[0].to_text().split(' ')[6]))
                    soa_ns.append(data[nameserver][addr]['SOA'].answer[0].to_text().split(' ')[4])
            if not is_same(soa_serial):
                warning('serials in SOA don\'t match. Got %s' % ', '.join(['%s (%s): %s'
                    % (ns_name[i], ns_addr[i], soa_serial[i]) for i in
                    range(len(ns_name))]))
            if not is_same(soa_ns):
                warning('primary nameservers in SOA don\'t match. Got %s' % ', '.join(['%s (%s): %s'
                    % (ns_name[i], ns_addr[i], soa_ns[i]) for i in
                    range(len(ns_name))]))

        if not is_same(ns_list):
            pass

def get_info_from_nameservers(refs):
    global zone_name
    soa_qmsg = dns.message.make_query(zone_name, dns.rdatatype.SOA)
    ns_qmsg = dns.message.make_query(zone_name, dns.rdatatype.NS)
    global ip4
    global ip6
    ret_data = {}

    for ns in refs:
        ret_data[ns] = {}
        for address in refs[ns]:
            if IP_version(address) == 4 and not ip4:
                continue
            if IP_version(address) == 6 and not ip6:
                continue

            ret_data[ns][address] = {}
            ret_data[ns][address]['SOA'] = do_query(soa_qmsg, address)
            if ret_data[ns][address]['SOA']:
                if get_reply_type(ret_data[ns][address]['SOA']) != 'ANSWER':
                    unknown('Could not get SOA record from %s at %s' % (ns, address))
            else:
                # we got False, so the AF was probably not supported
                del ret_data[ns][address]
                continue
            ret_data[ns][address]['NS'] = do_query(ns_qmsg, address)
            if ret_data[ns][address]['NS']:
                if get_reply_type(ret_data[ns][address]['NS']) != 'ANSWER':
                    unknown('Could not get NS records from %s at %s' % (ns, address))
            else:
                # we got False, so the AF was probably not supported
                del ret_data[ns][address]
                continue
        if ret_data[ns] == {}:
            del ret_data[ns]
    return ret_data

ip4 = True
ip6 = True

# TODO: argparse
#       make the expected set 'safe'
zone_name = 'non-existing-domain.kumina.nl'
zone_name = 'ec2.kumina.nl'
zone_name = 'kumina.nl'
expected = ['ns3.kumina.nl.', 'ns4.kumina.nl.']
zone_name = sanitize_name(zone_name)
from_upstream = get_delegation()

if len(from_upstream):
    if len(from_upstream) == 1:
        # Only one auth is delegated... that is not the right way
        warning('only one authoritative nameserver from upstream: %s' % from_upstream.keys())
    # We got referrals
    if expected:
        if not sorted(from_upstream.keys()) == sorted(expected):
            critical('Got unexpected nameservers from upstream: expected %s, got %s'
                    % (','.join(sorted(expected)), ','.join(from_upstream.keys())))

    data = get_info_from_nameservers(from_upstream)
    check_delegation(data, expected)
else:
    unknown("No nameservers found, is %s a zone?" % zone_name)

# TODO in order of importance
# - IPv4/IPv6 selection
# - debug output
# - Expected ns RRSets
# - TCP fallback + EDNS buffers
# - DNSSEC support
