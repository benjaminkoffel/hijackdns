from __future__ import absolute_import, division, print_function, unicode_literals
import boto3

client = boto3.client('route53')

hosted_zones = client.list_hosted_zones()

for hosted_zone in hosted_zones['HostedZones']:
    print(hosted_zone['Id'], hosted_zone['Name'])
    ns_records = client.list_resource_record_sets(HostedZoneId=hosted_zone['Id'], MaxItems='1000')
    for ns_record in ns_records['ResourceRecordSets']:
        if ns_record['Type'] == 'NS':
            print(ns_record['Name'])
