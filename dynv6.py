#!/usr/bin/env python3
import abc
import collections
import ipaddress
import socket
import sys
import requests
import logging
import re
import netifaces
import urllib3
from urllib import parse
from typing import List, Dict, NamedTuple, Optional


def set_network_v6_only():
    urllib3.util.connection.allowed_gai_family = lambda: socket.AF_INET6


def set_network_v4_only():
    urllib3.util.connection.allowed_gai_family = lambda: socket.AF_INET


class DynV6(object):
    base_url = 'http://dynv6.com/api/update'

    def __init__(self,
                 token: str,
                 hostname: str,
                 ip_mgr: 'IPMgr',
                 ipv4: bool = False,
                 ipv6: bool = True,
                 timeout: int = 5,
                 retries: int = 3):
        self.ip_mgr = ip_mgr
        self.enable_ipv4 = ipv4
        self.enable_ipv6 = ipv6
        self.token = token
        self.hostname = hostname
        self.timeout = timeout
        self.retrie_times = retries

    def update(self):
        if self.enable_ipv4:
            self._update_ipv4()
        if self.enable_ipv6:
            self._update_ipv6()

    def _update_ipv4(self) -> bool:
        adr = self.ip_mgr.get_ip(socket.AF_INET)
        adr = adr or 'auto'
        set_network_v4_only()
        url = f'{self.base_url}?hostname={parse.quote(self.hostname)}' \
              f'&token={parse.quote(self.token)}&ipv4={parse.quote(adr)}'
        return self._request_with_retries(url, self.timeout, self.retrie_times)

    def _update_ipv6(self) -> bool:
        adr = self.ip_mgr.get_ip(socket.AF_INET6)
        adr = adr or 'auto'
        set_network_v6_only()
        url = f'{self.base_url}?hostname={parse.quote(self.hostname)}' \
              f'&token={parse.quote(self.token)}&ipv6={parse.quote(adr)}'
        return self._request_with_retries(url, self.timeout, self.retrie_times)


    @classmethod
    def _request_with_retries(cls, url: str, timeout: int, retries: int) -> bool:
        for i in range(retries):
            try:
                resp = requests.get(url, timeout=timeout).text
                if resp == 'addresses updated':
                    print('good')
                    return True
                elif resp == 'invalid authentication token':
                    print('badauth')
                    return False
                elif resp == 'hostname not found' or resp == 'zone not found':
                    print('nohost')
                    return False
                elif resp == 'addresses unchanged':
                    print('nochg')
                    return True
            except requests.exceptions.RequestException as e:
                logging.warning(f"request exception ocurred, err={str(e)}")
        logging.error("all update request failed")
        print('badconn')
        return False


class IPAdapter(object):

    ipv4re = re.compile(r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|'
                        r'2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)', re.IGNORECASE | re.UNICODE)

    ipv6re = re.compile(r'\s*(?!.*::.*::)(?:(?!:)|:(?=:))(?:[\da-f]{0,4}(?:(?<=::)|(?<!::):)){6}(?:[\da-f]{0,4}'
                        r'(?:(?<=::)|(?<!::):)[\da-f]{0,4}(?:(?<=::)|(?<!:)|(?<=:)(?<!::):)|(?:25[0-4]|2[0-4]\d|1\d\d|'
                        r'[1-9]?\d)(?:\.(?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)){3})\s*',
                        re.IGNORECASE | re.DOTALL | re.UNICODE | re.VERBOSE)

    @abc.abstractmethod
    def register(self, mgr: 'IPMgr'):
        pass

    def fetch_one(self) -> Optional[str]:
        ips = self.fetch()
        if len(ips) > 0:
            return ips[0]

    @abc.abstractmethod
    def fetch(self) -> List[str]:
        pass

    @staticmethod
    def valid_ipv6(ip: str) -> bool:
        try:
            addr = ipaddress.IPv6Address(ip)
            return addr.is_global
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def valid_ipv4(ip: str) -> bool:
        try:
            addr = ipaddress.IPv4Address(ip)
            return addr.is_global
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def get_inet4_from_str(content: str) -> List[str]:
        ips = IPAdapter.ipv4re.findall(content)
        result_ips = []
        for ip in ips:
            if IPAdapter.valid_ipv4(ip):
                result_ips.append(str(ip).strip())
        return result_ips

    @staticmethod
    def get_inet6_from_str(content: str) -> List[str]:
        ips = IPAdapter.ipv6re.findall(content)
        result_ips = []
        for ip in ips:
            ip = ip.strip()
            if IPAdapter.valid_ipv6(ip):
                result_ips.append(ip)
        return result_ips

    @staticmethod
    def ip_type_to_str(typ: int) -> str:
        if typ == socket.AF_INET:
            return "ipv4"
        elif typ == socket.AF_INET6:
            return "ipv6"
        return "unknown"


class RemoteIPV4Adapter(IPAdapter):

    def __init__(self, priority: int, remote_url: str):
        self.priority = priority
        self.remote_url = remote_url
        self.ip_type = socket.AF_INET

    def register(self, mgr: 'IPMgr'):
        mgr.register_adapter(self, self.ip_type, self.priority)

    def fetch(self) -> List[str]:
        set_network_v4_only()
        try:
            content = requests.get(self.remote_url).text
            return self.get_inet4_from_str(content)
        except Exception as e:
            logging.error(f"get ip address from {self.remote_url} failed, type={self.ip_type_to_str(self.ip_type)}, "
                          f"err={str(e)}")


class RemoteIPV6Adapter(IPAdapter):

    def __init__(self, priority: int, remote_url: str):
        self.priority = priority
        self.remote_url = remote_url
        self.ip_type = socket.AF_INET6

    def register(self, mgr: 'IPMgr'):
        mgr.register_adapter(self, self.ip_type, self.priority)

    def fetch(self) -> List[str]:
        set_network_v6_only()
        try:
            content = requests.get(self.remote_url).text
            return self.get_inet6_from_str(content)
        except Exception as e:
            logging.error(f"get ip address from {self.remote_url} failed, type={self.ip_type_to_str(self.ip_type)}, "
                          f"err={str(e)}")


class LocalIPAdapter(IPAdapter):
    ignore_interfaces = ['lo', 'lo0', 'docker0']

    def __init__(self, priority, ip_type):
        self.priority = priority
        self.ip_type = ip_type

    def register(self, mgr: 'IPMgr'):
        mgr.register_adapter(self, self.ip_type, self.priority)

    def fetch(self) -> List[str]:
        interfaces = netifaces.interfaces()
        valid_address = []
        for interface in interfaces:
            if interface not in self.ignore_interfaces:
                nic_addrs = netifaces.ifaddresses(interface)
                addrs = nic_addrs.get(self.ip_type, [])
                for addrinfo in addrs:
                    addr = addrinfo.get('addr', '').strip()
                    if self.valid_ipv6(addr):
                        valid_address.append(addr)
        return valid_address


class IPMgr(object):

    class PriorityAdapter(NamedTuple):
        priority: int
        adapter: IPAdapter

    def __init__(self):
        self.ip_adapter: Dict[int, List[IPMgr.PriorityAdapter[int, IPAdapter]]] = collections.defaultdict(list)

    def register_adapter(self, adapter: 'IPAdapter', ip_type: int, priority: int = 0):
        self.ip_adapter[ip_type].append(self.PriorityAdapter(priority, adapter))
        self.ip_adapter[ip_type].sort(key=lambda x: x.priority)

    # fetcher: Callable[[str], str], extractor: Callable[[str], str], validator: Callable[[str], bool]
    def get_ip(self, ip_type: int) -> Optional[str]:
        pas = self.ip_adapter[ip_type]
        if len(pas) > 0:
            for pa in pas:
                ip = pa.adapter.fetch_one()
                if ip is not None:
                    return ip


if __name__ == '__main__':
    if len(sys.argv) < 5:
        print("badparam")
        exit(-1)

    account, token, hostname, ip = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    ip_mgr = IPMgr()
    RemoteIPV4Adapter(0, 'https://getip.me').register(ip_mgr)
    LocalIPAdapter(1, socket.AF_INET).register(ip_mgr)
    RemoteIPV6Adapter(0, 'https://getip.me').register(ip_mgr)
    LocalIPAdapter(1, socket.AF_INET6).register(ip_mgr)
    ddns = DynV6(token, hostname, ip_mgr, ipv4=True)
    ddns.update()
