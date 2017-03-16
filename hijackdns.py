from __future__ import absolute_import, division, print_function, unicode_literals

import dns.query
import dns.resolver
import dns.exception
import argparse
import socket

def list_authoritative_nameservers(nameserver, domain):
    resolver = dns.resolver.Resolver()
    resolver.nameservers=[socket.gethostbyname(nameserver)]
    resolver.timeout = 5
    resolver.lifetime = 5
    nameservers = []
    for rdata in resolver.query(domain, 'NS'):
        nameservers.append(rdata.target.to_text())
    return nameservers

def check_ns_record(nameserver, domain):
    resolver = dns.resolver.Resolver()
    resolver.nameservers=[socket.gethostbyname(nameserver)]
    resolver.timeout = 5
    resolver.lifetime = 5
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
            return 'TIMEOUT'
        else:
            return 'ERROR: ' + e.msg
    return 'OK'

parser = argparse.ArgumentParser()
parser.add_argument('-t', '--target-domain', help='target base domain')
parser.add_argument('-p', '--public-dns', help='public DNS server', default='8.8.8.8')
parser.add_argument('-s', '--subdomain-list', help='file containing a list of subdomains')
args = parser.parse_args()

with open(args.subdomain_list) as list_file:
    subdomains = list_file.readlines()
subdomains = [x.strip() for x in subdomains]

print('authoritative nameservers:')
authoritative_nameservers = list_authoritative_nameservers(args.public_dns, args.target_domain)
for nameserver in authoritative_nameservers:
    print(nameserver)
print('')

subdomains.insert(0, '_example.dev')

for subdomain in subdomains:
    domain = subdomain + '.' + args.target_domain
    print(domain, end=' ')
    public_ns_status = check_ns_record(args.public_dns, domain)
    print(public_ns_status, end=' ')
    if public_ns_status == 'SERVFAIL':
        authoritative_ns_status = check_ns_record(authoritative_nameservers[0], domain)
        print(authoritative_ns_status, end=' ')
        if authoritative_ns_status == 'INNS':
            print('--- VULNERABLE ---', end='')
    print('')
