from pprint import pprint
from jnpr.junos import Device

dev = Device(host='my_host_or_ipaddr', user='jeremy', password='jeremy123' )
dev.open()

pprint( dev.facts )

dev.close()
