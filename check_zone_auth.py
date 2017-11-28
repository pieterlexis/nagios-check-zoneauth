#!/usr/bin/env python3

from __future__ import print_function
from builtins import super
import argparse
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver
import dns.dnssec
import time
import socket
import logging
import nagiosplugin

_log = logging.getLogger('nagiosplugin')


class CheckResolver(dns.resolver.Resolver):
    def __init__(self, filename='/etc/resolv.conf', configure=True, do_ipv6=False):
        super().__init__(filename, configure)
        self.cache = dns.resolver.LRUCache()
        self.edns = 0
        self.ednsflags = dns.flags.DO
        self.flags = dns.flags.CD + dns.flags.RD

    def get_parent_ns(self, qname):
        """

        :param dns.name.Name qname:
        :return:
        """
        if not isinstance(qname, dns.name.Name):
            raise ValueError('qname is not a dns.name.Name')
        _log.info('Attempting to get the NSSet for the parent of {}'.format(qname))
        name = qname
        while True:
            try:
                name = name.parent()
            except dns.name.NoParent:
                break
            try:
                _log.info('Finding out if {} is the parent of {}'.format(name, qname))
                resp = self.query(name, dns.rdatatype.NS, raise_on_no_answer=False)  # type: dns.resolver.Answer
            except dns.resolver.NXDOMAIN:
                _log.info('Got NXDomain for {}'.format(name))
                continue
            if resp is not None:
                _log.debug('Got a response: {}'.format(resp.response))
                for rrset in resp.response.answer:
                    if rrset.rdtype == dns.rdatatype.NS and rrset.name == name:
                        return [elem.target for elem in rrset.items]
        raise dns.resolver.NoAnswer('No NS records found for {} or any of its parents'.format(qname))

    def get_addrs(self, qname):
        if not isinstance(qname, dns.name.Name):
            raise ValueError('qname is not a dns.name.Name')
        _log.info('Attempting to retrieve IP addresses for {}'.format(qname))
        ret = {}
        for addr_type in ['A', 'AAAA']:
            _log.info('Doing a query for {}|{}'.format(qname, addr_type))
            res = self.query(qname, addr_type, raise_on_no_answer=False)  # type: dns.resolver.Answer
            _log.debug('Got a response: {}'.format(res.response))
            for rrset in res.response.answer:
                if rrset.rdtype == dns.rdatatype.from_text(addr_type) and rrset.name == qname:
                    ret[addr_type] = [elem.address for elem in rrset.items]
        return ret

    def get_delegation_ns_from(self, qname, nameserver, tcp=False, source=None, raise_on_no_answer=True, source_port=0):
        _log.info('Attempting to get the delegation NSSet for {} from {}'.format(qname, nameserver))
        res = self.do_query_at_ip(qname, nameserver, tcp, source, raise_on_no_answer, source_port)
        _log.debug('Got a response: {}'.format(res))

        for rrset in res.authority:
            if rrset.rdtype == dns.rdatatype.NS and rrset.name == qname:
                return [elem.target for elem in rrset.items]

    def get_ns_from(self, qname, nameserver, tcp=False, source=None, raise_on_no_answer=True, source_port=0):
        _log.info('Attempting to get the authoritative NSSet for {} from {}'.format(qname, nameserver))
        res = self.do_query_at_ip(qname, nameserver, tcp, source, raise_on_no_answer, source_port)
        _log.debug('Got a response: {}'.format(res))

        for rrset in res.answer:
            if rrset.rdtype == dns.rdatatype.NS and rrset.name == qname:
                return [elem.target for elem in rrset.items]

    def do_query_at_ip(self, qname, nameserver, tcp=False, source=None, raise_on_no_answer=True, source_port=0):
        if isinstance(qname, (str,)):
            qname = dns.name.from_text(qname, None)
        rdtype = dns.rdatatype.NS
        rdclass = dns.rdataclass.IN
        if self.cache:
            answer = self.cache.get((qname, rdtype, rdclass))
            if answer is not None:
                if answer.rrset is None and raise_on_no_answer:
                    raise dns.resolver.NoAnswer(response=answer.response)
                else:
                    return answer
        request = dns.message.make_query(qname, rdtype, rdclass)
        if self.keyname is not None:
            request.use_tsig(self.keyring, self.keyname,
                             algorithm=self.keyalgorithm)
        request.use_edns(self.edns, self.ednsflags, self.payload)
        request.flags = dns.flags.CD
        response = None
        start = time.time()
        timeout = self._compute_timeout(start)
        port = self.nameserver_ports.get(nameserver, self.port)
        while response is None:
            try:
                tcp_attempt = tcp
                if tcp:
                    response = dns.query.tcp(request, nameserver,
                                             timeout, port,
                                             source=source,
                                             source_port=source_port)
                else:
                    response = dns.query.udp(request, nameserver,
                                             timeout, port,
                                             source=source,
                                             source_port=source_port)
                    if response.flags & dns.flags.TC:
                        # Response truncated; retry with TCP.
                        tcp_attempt = True
                        timeout = self._compute_timeout(start)
                        response = \
                            dns.query.tcp(request, nameserver,
                                          timeout, port,
                                          source=source,
                                          source_port=source_port)
                        break
            except (socket.error, dns.exception.Timeout):
                raise
            except dns.query.UnexpectedSource:
                raise
            except dns.exception.FormError:
                raise
            except EOFError:
                raise

        if response is None:
            raise dns.resolver.NoAnswer()

        if response.rcode() == dns.rcode.YXDOMAIN:
            raise dns.resolver.YXDOMAIN()

        if response.rcode == dns.rcode.NXDOMAIN:
            raise dns.resolver.NXDOMAIN(qnames=qname, responses=response)

        return response


class ZoneAuth(nagiosplugin.Resource):
    def __init__(self, domain):
        """

        :param dns.name.Name domain:
        """
        self.domain = domain
        self.resolver = CheckResolver()

    def probe(self):
        _log.info('Trying to get Parent NSes for {}'.format(self.domain))
        parent_nameservers = self.resolver.get_parent_ns(self.domain)
        _log.debug('Got response'.format(parent_nameservers))
        authority_ns_from_parent = []
        for nameserver in parent_nameservers:
            addresses = self.resolver.get_addrs(nameserver)
            if addresses:
                for add_type, values in addresses.items():
                    for address in values:
                        try:
                            authority_ns_from_parent = self.resolver.get_delegation_ns_from(self.domain, address)
                            if authority_ns_from_parent:
                                break
                        except Exception as e:
                            pass
            if authority_ns_from_parent:
                break

        if not authority_ns_from_parent:
            raise nagiosplugin.CheckError('Unable to retrieve nameservers for {} from parent'.format(self.domain))

        authority_ns_from_auth = {}

        for nameserver in authority_ns_from_parent:
            addresses = self.resolver.get_addrs(nameserver)
            if not addresses:
                raise nagiosplugin.CheckError('No addresses exist for authoritative nameserver {}'.format(nameserver))

            for add_type, values in addresses.items():
                for address in values:
                    try:
                        authority_ns_from_auth[nameserver] = self.resolver.get_ns_from(self.domain, address)
                    except Exception as e:
                        pass

        yield nagiosplugin.Metric('parent_delegation', set(authority_ns_from_parent), context='parent delegation')

        to_yield = {'auth_nssets': {}, 'parent_nsset': set(authority_ns_from_parent)}
        for nameserver, auth_nsset in authority_ns_from_auth.items():
            tmp = {nameserver: set(auth_nsset)}
            to_yield['auth_nssets'].update(tmp)
        yield nagiosplugin.Metric('auth_nssets', to_yield, context='zone auth')


class ParentDelegationContext(nagiosplugin.context.Context):
    def __init__(self, name, expected_servers=None,
                 fmt_metric=None, result_cls=nagiosplugin.Result):
        super(ParentDelegationContext, self).__init__(name, fmt_metric, result_cls)
        self.expected_servers = expected_servers

    def evaluate(self, metric, resource):
        """

        :param nagiosplugin.Metric metric:
        :param resource:
        :return:
        """
        if self.expected_servers:
            if metric.value != self.expected_servers:
                expected_str = ','.join([str(x) for x in self.expected_servers])
                delegation_str = ','.join([str(x) for x in metric.value])
                return nagiosplugin.Result(nagiosplugin.Critical,
                                           'Parent delegation does match expected NSSet: "{}" vs "{}"'.format(
                                               delegation_str,
                                               expected_str
                                           ),
                                           metric)
        return nagiosplugin.Result(nagiosplugin.Ok, '', metric)


class ZoneAuthContext(nagiosplugin.context.Context):
    def __init__(self, name, expected_servers=None,
                 fmt_metric=None, result_cls=nagiosplugin.Result):
        super(ZoneAuthContext, self).__init__(name, fmt_metric, result_cls)
        self.expected_servers = expected_servers

    def evaluate(self, metric, resource):
        """

        :param nagiosplugin.Metric metric:
        :param resource:
        :return:
        """
        parent_nsset_str = ','.join([str(x) for x in metric.value.get('parent_nsset')])
        expected_str = ','.join([str(x) for x in self.expected_servers])
        if self.expected_servers:
            for auth, nsset in metric.value.get('auth_nssets').items():
                nsset_str = ','.join([str(x) for x in nsset])
                if nsset != self.expected_servers:
                    if self.expected_servers.isdisjoint(nsset):
                        return nagiosplugin.Result(nagiosplugin.Critical,
                                                   '{}: NSSet does not match expected: "{}" vs "{}"'.format(
                                                       auth,
                                                       nsset_str,
                                                       expected_str
                                                   ),
                                                   metric)
                    return nagiosplugin.Result(nagiosplugin.Warn,
                                               '{}: NSSet does not fully match expected: "{}" vs "{}"'.format(
                                                   auth,
                                                   nsset_str,
                                                   expected_str
                                               ),
                                               metric)

        for auth, nsset in metric.value.get('auth_nssets').items():
            nsset_str = ','.join([str(x) for x in nsset])
            if metric.value.get('parent_nsset') != nsset:
                if metric.value.get('parent_nsset').isdisjoint(nsset):
                    return nagiosplugin.Result(nagiosplugin.Critical,
                                               '{}: NSSet does not match parent NSSet: "{}" vs "{}"'.format(
                                                   auth, nsset_str, parent_nsset_str
                                               ),
                                               metric)
                return nagiosplugin.Result(nagiosplugin.Warn,
                                           '{}: NSSet does not fully match parent NSSet: "{}" vs "{}"'.format(
                                               auth, nsset_str, parent_nsset_str
                                           ),
                                           metric)

        return nagiosplugin.Result(nagiosplugin.Ok, '', metric)


class ZoneAuthSummary(nagiosplugin.Summary):
    def make_summary_for_result(self, result):
        if result.metric.context == 'parent delegation':
            return 'Parent NSSet: {}'.format(','.join([str(x) for x in result.metric.value]))
        elif result.metric.context == 'zone auth':
            ret = []
            for auth, nsset in result.metric.value.get('auth_nssets').items():
                ret.append('{} NSSet: {}'.format(auth, ','.join([str(x) for x in nsset])))
            return ', '.join(ret)

    def problem(self, results):
        """

        :param nagiosplugins.result.Results results:
        :return:
        """
        ret_hints = []
        ret = []
        for result in results.most_significant:
            ret_hints.append(result.hint)
            ret.append(self.make_summary_for_result(result))
        return '{}! {}'.format(', '.join(ret_hints), ' ; '.join(ret))

    def ok(self, results):
        ret = []
        for result in results:
            ret.append(self.make_summary_for_result(result))
        return ' ; '.join(ret)


@nagiosplugin.guarded
def main():
    parser = argparse.ArgumentParser(description='Check for delegation and '
                                                 'zone-consistency')
    parser.add_argument('zone', help='Zone to check', metavar='ZONE')
    #    group = parser.add_mutually_exclusive_group()
    #    group.add_argument('-6', action='store_true', dest='ip6_only')
    #    group.add_argument('-4', action='store_true', dest='ip4_only')
    parser.add_argument('--nameservers', '-n', help='A comma-separated list of '
                                                    'expected nameservers')
    parser.add_argument('--verbose', '-v', help='Be a little verbose',
                        action='count', default=0)
    # parser.add_argument('--dnssec', action='store_true', help='Also check DNSSEC')
    args = parser.parse_args()

    zone_name = dns.name.from_text(args.zone)

    #    ip4 = True
    #    ip6 = True
    #
    #    if args.ip4_only:
    #        ip6 = False
    #    if args.ip6_only:
    #        ip4 = False

    expected = set()
    if args.nameservers:
        expected = set([dns.name.Name(x.split('.')).derelativize(dns.name.root) for x in args.nameservers.split(',')])

    check = nagiosplugin.Check(
        ZoneAuth(domain=zone_name),
        ZoneAuthContext('zone auth', expected_servers=expected),
        ParentDelegationContext('parent delegation', expected_servers=expected),
        ZoneAuthSummary()
    )

    check.main(verbose=args.verbose)


if __name__ == '__main__':
    main()
