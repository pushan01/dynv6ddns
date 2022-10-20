# Dyndns Updater for dynv6

## Description
Simple DDNS client for updating your ip address to dynv6.com. Testing in synology DSM7.1.

## Usage in DSM7.1

1. upload dynv6.py to `/usr/syno/bin/ddns` of your synology.
2. install dependency 
3. add dynv6 client to `/etc.defaults/ddns_provider.conf`
```
[Dynv6User]
    modulepath=/usr/syno/bin/ddns/dynv6.py
    ueryurl=https://dynv6.com
```
4. configure dynv6 params in dsm remote access