from __future__ import absolute_import, division, print_function, unicode_literals

import dns.query
import dns.resolver
import dns.exception
import argparse
import socket

def list_authoritative_nameservers(nameservers, domain):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = nameservers
    resolver.timeout = 5
    resolver.lifetime = 5
    authoritative_nameservers = []
    for rdata in resolver.query(domain, 'NS'):
        authoritative_nameservers.append(rdata.target.to_text())
    return authoritative_nameservers

def check_ns_record(nameservers, domain, attempts=3):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = nameservers
    resolver.timeout = 1
    resolver.lifetime = 1
    try:
        resolver.query(domain, 'NS')
    except dns.exception.DNSException as e:
        if 'SERVFAIL' in e.msg:
            return 'SERVFAIL'
        elif 'IN NS' in e.msg:
            return 'INNS'
        elif 'None of DNS query names exist' in e.msg:
            return 'NOTFOUND'
        elif 'timed out' in e.msg:
            if attempts > 0:
                check_ns_record(nameservers, domain, attempts - 1)
            else:
                return 'TIMEOUT'
        else:
            return 'ERROR: ' + e.msg
    return 'OK'

parser = argparse.ArgumentParser()
parser.add_argument('-t', '--target-domain', help='target base domain')
parser.add_argument('-p', '--public-dns', help='public DNS', default='8.8.8.8')
parser.add_argument('-s', '--subdomain-list', help='file containing a list of subdomains')
args = parser.parse_args()

with open(args.subdomain_list) as list_file:
    subdomains = list_file.readlines()
subdomains = [x.strip() for x in subdomains]

public_nameservers = [args.public_dns]

print('authoritative nameservers:')
authoritative_nameservers = list_authoritative_nameservers(public_nameservers, args.target_domain)
for nameserver in authoritative_nameservers:
    print(nameserver)
print('')

for subdomain in subdomains:
    domain = subdomain + '.' + args.target_domain
    print(domain, end=' ')
    public_ns_status = check_ns_record(public_nameservers, domain)
    print(public_ns_status, end=' ')
    if public_ns_status == 'SERVFAIL':
        authoritative_ns_status = check_ns_record(authoritative_nameservers, domain)
        print(authoritative_ns_status, end=' ')
        if authoritative_ns_status == 'INNS':
            print('--- VULNERABLE ---', end='')
    print('')
