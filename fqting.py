#!/usr/bin/env python
import logging
import logging.handlers
import argparse
import sys
import signal
import atexit
import subprocess
import fqsocks.china_ip
import fqsocks.lan_ip
import socket
import time

import dpkt


LOGGER = logging.getLogger('fqting')
MIN_TTL_TO_GFW = 8
MAX_TTL_TO_GFW = 14
RANGE_OF_TTL_TO_GFW = range(MIN_TTL_TO_GFW, MAX_TTL_TO_GFW + 1)
probe_results = {}
probed_ttls = {} # ip => ttl


def setup_development_env():
    subprocess.check_call(
        'iptables -I OUTPUT -p tcp --tcp-flags ALL SYN -j NFQUEUE', shell=True)
    subprocess.check_call(
        'iptables -I INPUT -p icmp -j NFQUEUE', shell=True)
    subprocess.check_call(
        'iptables -I OUTPUT -p tcp -m mark --mark 0xbabe -j NFQUEUE', shell=True)


def teardown_development_env():
    subprocess.check_call(
        'iptables -D OUTPUT -p tcp --tcp-flags ALL SYN -j NFQUEUE', shell=True)
    subprocess.check_call(
        'iptables -D INPUT -p icmp -j NFQUEUE', shell=True)
    subprocess.check_call(
        'iptables -D OUTPUT -p tcp -m mark --mark 0xbabe -j NFQUEUE', shell=True)


raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
atexit.register(raw_socket.close)
raw_socket.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
SO_MARK = 36
raw_socket.setsockopt(socket.SOL_SOCKET, SO_MARK, 0xcafe)


def main():
    global DEFAULT_VERDICT
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument('--log-file')
    argument_parser.add_argument('--log-level', choices=['INFO', 'DEBUG'], default='INFO')
    argument_parser.add_argument('--queue-number', default=0, type=int)
    argument_parser.add_argument('--dev', action='store_true')
    args = argument_parser.parse_args()
    log_level = getattr(logging, args.log_level)
    logging.basicConfig(stream=sys.stdout, level=log_level, format='%(asctime)s %(levelname)s %(message)s')
    if args.log_file:
        handler = logging.handlers.RotatingFileHandler(
            args.log_file, maxBytes=1024 * 16, backupCount=0)
        handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
        handler.setLevel(log_level)
        logging.getLogger('fqting').addHandler(handler)
    if args.dev:
        signal.signal(signal.SIGTERM, lambda signum, fame: teardown_development_env())
        signal.signal(signal.SIGINT, lambda signum, fame: teardown_development_env())
        atexit.register(teardown_development_env)
        setup_development_env()
    handle_nfqueue(args.queue_number)


def handle_nfqueue(queue_number):
    from netfilterqueue import NetfilterQueue

    try:
        nfqueue = NetfilterQueue()
        nfqueue.bind(queue_number, handle_packet)
        LOGGER.info('handling nfqueue at queue number %s' % queue_number)
        nfqueue.run()
    except:
        LOGGER.exception('failed to handle nfqueue')
    finally:
        LOGGER.info('stopped handling nfqueue')


def handle_packet(nfqueue_element):
    try:
        ip_packet = dpkt.ip.IP(nfqueue_element.get_payload())
        ip_packet.nfqueue_element = nfqueue_element
        ip_packet.src_ip = socket.inet_ntoa(ip_packet.src)
        ip_packet.dst_ip = socket.inet_ntoa(ip_packet.dst)
        if fqsocks.china_ip.is_china_ip(ip_packet.dst_ip):
            nfqueue_element.accept()
            return
        if fqsocks.lan_ip.is_lan_traffic(ip_packet.src_ip, ip_packet.dst_ip):
            nfqueue_element.accept()
            return
        if hasattr(ip_packet, 'tcp'):
            if dpkt.tcp.TH_SYN == ip_packet.tcp.flags:
                handle_syn(ip_packet)
                nfqueue_element.accept()
                return
        elif hasattr(ip_packet, 'icmp'):
            icmp_packet = ip_packet.data
            if dpkt.icmp.ICMP_TIMEXCEED == icmp_packet.type and dpkt.icmp.ICMP_TIMEXCEED_INTRANS == icmp_packet.code:
                handle_time_exceeded(ip_packet)
                nfqueue_element.accept()
                return
        nfqueue_element.accept()
    except:
        LOGGER.exception('failed to handle packet')
        nfqueue_element.accept()


def handle_syn(ip_packet):
    inject_ping_requests_to_find_right_ttl(ip_packet.dst_ip)


def inject_ping_requests_to_find_right_ttl(dst_ip):
    if dst_ip in probe_results:
        return
    probe_results[dst_ip] = ProbeResult()
    if LOGGER.isEnabledFor(logging.DEBUG):
        LOGGER.debug('inject ping request: %s %s' % (dst_ip, RANGE_OF_TTL_TO_GFW))
    for ttl in RANGE_OF_TTL_TO_GFW:
        icmp_packet = dpkt.icmp.ICMP(type=dpkt.icmp.ICMP_ECHO, data=dpkt.icmp.ICMP.Echo(id=ttl, seq=1, data=''))
        ip_packet = dpkt.ip.IP(
            src=socket.inet_aton(find_probe_src(dst_ip)),
            dst=socket.inet_aton(dst_ip),
            p=dpkt.ip.IP_PROTO_ICMP)
        ip_packet.ttl = ttl
        ip_packet.data = icmp_packet
        raw_socket.sendto(str(ip_packet), (dst_ip, 0))


def find_probe_src(dst_ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((dst_ip, 80))
        return s.getsockname()[0]
    finally:
        s.close()


def handle_time_exceeded(ip_packet):
    global MAX_TTL_TO_GFW
    global MIN_TTL_TO_GFW
    global RANGE_OF_TTL_TO_GFW
    time_exceed = ip_packet.icmp.data
    if not isinstance(time_exceed.data, dpkt.ip.IP):
        return
    te_ip_packet = time_exceed.data
    dst_ip = socket.inet_ntoa(te_ip_packet.dst)
    if dst_ip in probed_ttls:
        return
    if not isinstance(te_ip_packet.data, dpkt.icmp.ICMP):
        return
    te_icmp_packet = te_ip_packet.data
    if not isinstance(te_icmp_packet.data, dpkt.icmp.ICMP.Echo):
        return
    te_icmp_echo = te_icmp_packet.data
    ttl = te_icmp_echo.id
    router_ip = socket.inet_ntoa(ip_packet.src)
    is_china_router = fqsocks.china_ip.is_china_ip(router_ip)
    probe_result = probe_results.get(dst_ip)
    if not probe_result:
        return
    probe_result.routers[ttl] = (router_ip, is_china_router)
    ttl_to_gfw = probe_result.analyze_ttl_to_gfw()
    if not ttl_to_gfw:
        return
    LOGGER.info('found ttl to gfw: %s %s' % (dst_ip, ttl_to_gfw))
    probed_ttls[dst_ip] = ttl_to_gfw
    probe_results.pop(dst_ip, None)
    if ttl_to_gfw == MAX_TTL_TO_GFW:
        MIN_TTL_TO_GFW += 2
        MAX_TTL_TO_GFW += 2
        LOGGER.info('slide ttl range to [%s ~ %s]' % (MIN_TTL_TO_GFW, MAX_TTL_TO_GFW))
        RANGE_OF_TTL_TO_GFW = range(MIN_TTL_TO_GFW, MAX_TTL_TO_GFW + 1)


class ProbeResult(object):
    def __init__(self):
        super(ProbeResult, self).__init__()
        self.started_at = time.time()
        self.routers = {} # ttl => (router_ip, is_china_router)

    def analyze_ttl_to_gfw(self, exact_match_only=True):
        max_china_ttl = None
        if self.routers.get(MAX_TTL_TO_GFW):
            router_ip, is_china_router = self.routers.get(MAX_TTL_TO_GFW)
            if is_china_router:
                LOGGER.info('max ttl is still in china: %s, %s' % (MAX_TTL_TO_GFW, router_ip))
                return MAX_TTL_TO_GFW
        for ttl in sorted(self.routers.keys()):
            next = self.routers.get(ttl + 1)
            if next is None:
                continue
                # ttl 8 is china, ttl 9 is not
            _, current_is_china_router = self.routers[ttl]
            _, next_is_china_router = next
            # then we think 8 is the ttl to gfw
            if current_is_china_router:
                max_china_ttl = ttl
                if not next_is_china_router:
                    return ttl
        if exact_match_only:
            return None
        else:
            return max_china_ttl


if '__main__' == __name__:
    main()