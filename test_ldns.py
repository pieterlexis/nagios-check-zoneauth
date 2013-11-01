#!/usr/bin/env python
from ldns import ldns_resolver
import sys
import ldns
import random

res = ldns_resolver.new_frm_file()
res.push_dnssec_anchor(ldns.ldns_rr.new_frm_str('.    172800  IN  DNSKEY  257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaDX6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpzW5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relSQageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0='))
res.set_dnssec(True)
res.set_recursive(False)


glue_addr_list = [
        '192.228.79.201',
        '192.33.4.12',
        '199.7.91.13',
        '192.203.230.10',
        '192.5.5.241',
        '192.112.36.4',
        '128.63.2.53',
        '192.36.148.17',
        '192.58.128.30',
        '193.0.14.129',
        '199.7.83.42',
        '202.12.27.33',
        ]

ref_list =[]

done = False

zone_name = 'kumina.nl.'

while not done:
    while True:
        while res.nameserver_count():
            res.pop_nameserver()
        random.shuffle(glue_addr_list)
        for ref in glue_addr_list:
            res.push_nameserver(ldns.ldns_rdf.new_frm_str(ref, ldns.LDNS_RR_TYPE_A))
        ans_pkt = res.query('kumina.nl.', ldns.LDNS_RR_TYPE_SOA, ldns.LDNS_RR_CLASS_IN)

        if not ans_pkt:
            sys.exit(2)

        print ans_pkt

        if ans_pkt.reply_type() == ldns.LDNS_PACKET_REFERRAL:
            # We got a referral from the upstream nameserver
            auth_list = ans_pkt.authority()
            add_list = ans_pkt.additional()
            ref_list = []
            glue_addr_list = []
            for num in range(auth_list.rr_count()):
                ref_list.append(str(auth_list.rr(num).ns_nsdname()))
            for num in range(add_list.rr_count()):
                glue_addr_list.append(str(add_list.rr(num).pop_rdf()))
            if auth_list.owner() == zone_name:
                # we got the final referral :D
                # Save the NS records in the authority section to a global list
                done = True
                break
        elif ans_pkt.reply_type() == ldns.LDNS_PACKET_ANSWER:
            # we reached the correct nameserver. This happens when the
            # nameserver for example.com is also authoritative for
            # sub.example.com and .com has send us a referral to example.com
            done = True
            break
        elif ans_pkt.reply_type() == ldns.LDNS_PACKET_NODATA:
            # This is possibly not a zone
            break




    
