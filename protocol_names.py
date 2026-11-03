"""Shared protocol labels; protocol versions describe config features, not binaries."""


def protocol_display_name(protocol, header_protection=False, protocol_version=None):
    base, _, instance = str(protocol or 'awg').partition('__')
    try:
        idx = max(1, int(instance or 1))
    except ValueError:
        idx = 1
    names = {
        'awg': 'AmneziaWG', 'awg2': 'AmneziaWG 2.0',
        'awg3': 'AmneziaWG 3.1', 'awg_legacy': 'AmneziaWG Legacy',
        'xray': 'Xray', 'telemt': 'Telemt', 'dns': 'AmneziaDNS',
        'wireguard': 'WireGuard', 'socks5': 'SOCKS5', 'adguard': 'AdGuard Home',
        'nginx': 'NGINX', 'exit': 'Exit Node',
    }
    name = names.get(base, base)
    if base == 'awg2':
        if protocol_version == '3.1':
            name = 'AmneziaWG 3.1 (amnezia-awg2)'
        elif protocol_version == '3.x' or (protocol_version is None and header_protection):
            name = 'AmneziaWG 3.x (amnezia-awg2)'
    return name if idx <= 1 else f'{name} #{idx}'


def server_protocol_names(server):
    return {protocol: protocol_display_name(protocol, record.get('header_protection'),
                                            record.get('protocol_version'))
            for protocol, record in (server.get('protocols') or {}).items()}
