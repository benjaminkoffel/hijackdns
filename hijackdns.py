from __future__ import absolute_import, division, print_function, unicode_literals
import dns.query
import dns.resolver
import dns.exception
import argparse
import socket
import boto3

def list_authoritative_nameservers(nameserver, domain):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [nameserver]
    resolver.timeout = 10
    resolver.lifetime = 10
    authoritative_nameservers = []
    try:
        for rdata in resolver.query(domain, 'NS'):
            authoritative_nameservers.append(rdata.target.to_text())
    except:
        pass
    else:
        return authoritative_nameservers

def check_ns_record(nameserver, domain, attempts=3):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [nameserver]
    resolver.timeout = 5
    resolver.lifetime = 5
    try:
        resolver.query(domain, 'NS')
    except dns.exception.DNSException as e:
        if 'SERVFAIL' in e.msg:
            return 'SERVFAIL'
        if 'REFUSED' in e.msg:
            return 'REFUSED'
        elif 'IN NS' in e.msg:
            return 'INNS'
        elif 'None of DNS query names exist' in e.msg:
            return 'NOTFOUND'
        elif 'timed out' in e.msg:
            if attempts > 0:
                return check_ns_record(nameserver, domain, attempts - 1)
            else:
                return 'TIMEOUT'
        else:
            return 'ERROR: ' + e.msg
    return 'OK'

def check_domain_for_ns_hijack(public_dns, nameserver, domain):
    print(domain, '@', nameserver, end=' ')
    public_ns_status = check_ns_record(public_dns, domain)
    print(public_ns_status, end=' ')
    if public_ns_status == 'SERVFAIL' or public_ns_status == 'REFUSED':
        authoritative_ns_status = check_ns_record(nameserver, domain)
        print(authoritative_ns_status, end=' ')
        if authoritative_ns_status == 'INNS':
            print('---VULNERABLE---', end='')
    print('')

def scan_hostedzone(target_domain, public_dns, append, domain_list):
    print('\nHOSTED ZONE', target_domain)
    authoritative_nameservers = list_authoritative_nameservers(public_dns, target_domain)
    if authoritative_nameservers:
        print('\nauthoritative nameservers:')
        for nameserver in authoritative_nameservers:
            print(nameserver)
        nameserver = socket.gethostbyname(authoritative_nameservers[0])
        print('\ntesting NS records:')
        for domain in domain_list:
            if append == True:
                domain = domain + '.' + target_domain
            check_domain_for_ns_hijack(public_dns, nameserver, domain)

def scan_hostedzone_dynamic(public_dns, append, domain_list):
    print('\ntesting NS records:')
    nameservers = {}
    for domain in domain_list:
        parts = domain.split('.')
        for i in range(1, len(parts)):
            target_domain = '.'.join(parts[i:])
            if target_domain not in nameservers:
                ns = list_authoritative_nameservers(public_dns, target_domain)
                if not ns:
                    continue
                nameservers[target_domain] = socket.gethostbyname(ns[0])
            print(target_domain, end=': ')
            check_domain_for_ns_hijack(public_dns, nameservers[target_domain], domain)
            break

parser = argparse.ArgumentParser()
parser.add_argument('-t', '--target-domain', help='target base domain')
parser.add_argument('-p', '--public-dns', help='public DNS', default='8.8.8.8')
parser.add_argument('-l', '--list', help='file containing a list of domains or subdomains')
parser.add_argument('-a', '--append', help='append to list items to target domain', action='store_true', default=False)
parser.add_argument('-r', '--route53', help='grab hosted zones and NS records from route53', action='store_true', default=False)
args = parser.parse_args()

if args.route53:
    client = boto3.client('route53')
    hosted_zones = client.list_hosted_zones()
    for hosted_zone in hosted_zones['HostedZones']:
        ns_records = client.list_resource_record_sets(HostedZoneId=hosted_zone['Id'], MaxItems='1000')
        domain_list = []
        for ns_record in ns_records['ResourceRecordSets']:
            if ns_record['Type'] == 'NS':
                domain_list.append(ns_record['Name'])
        scan_hostedzone(hosted_zone['Name'], args.public_dns, False, domain_list)

elif args.target_domain and args.list:
    with open(args.list) as list_file:
        domain_list = list_file.readlines()
    domain_list = [x.strip('.,\n\t ') for x in domain_list]
    scan_hostedzone(args.target_domain, args.public_dns, args.append, domain_list)

elif args.list:
    with open(args.list) as list_file:
        domain_list = list_file.readlines()
    domain_list = [x.strip('.,\n\t ') for x in domain_list]
    scan_hostedzone_dynamic(args.public_dns, args.append, domain_list)

else:
    print(parser.usage)
