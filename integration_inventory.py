"""Credential-free control-plane projection for authenticated integrations.

No SSH, protocol discovery, counters, config reads or persistence happen here.
The caller supplies one load_data snapshot; mutable indices retain their UIDs.
"""


def integration_inventory(data, protocol_base):
    def identifier(value):
        if not isinstance(value, str) or not value or len(value) > 256:
            raise ValueError('Invalid inventory identity')
        return value

    for key in ('servers', 'users', 'user_connections'):
        if not isinstance(data.get(key), list):
            raise ValueError('Incomplete inventory')
    servers, users, connections = [], [], []
    uids, owners, links = set(), set(), set()
    for server in data['servers']:
        uid = identifier(server.get('uid'))
        if uid in uids or not isinstance(server.get('name'), str) or not isinstance(server.get('protocols'), dict):
            raise ValueError('Ambiguous server inventory')
        uids.add(uid)
        protocols = {}
        for instance, info in server['protocols'].items():
            identifier(instance)
            if not isinstance(info, dict) or not isinstance(info.get('installed'), bool):
                raise ValueError('Invalid protocol inventory')
            protocols[instance] = {'installed': info['installed'],
                                   'base_protocol': protocol_base(instance)}
        servers.append({'uid': uid, 'name': server['name'],
                        'protocols': protocols})
    for user in data['users']:
        uid = identifier(user.get('id'))
        if uid in owners:
            raise ValueError('Ambiguous user inventory')
        owners.add(uid)
        users.append({'id': uid})
    for connection in data['user_connections']:
        cid = identifier(connection.get('id'))
        owner = identifier(connection.get('user_id'))
        sid = connection.get('server_id')
        if cid in links or owner not in owners or type(sid) is not int or sid < 0:
            raise ValueError('Invalid ownership inventory')
        links.add(cid)
        row = {'id': cid, 'user_id': owner, 'server_id': sid,
               'protocol': identifier(connection.get('protocol')),
               'client_id': identifier(connection.get('client_id'))}
        # Explicit fields only: never export SSH credentials, configs, tokens,
        # private keys, arbitrary protocol fields or future stored user fields.
        for key in ('name', 'create_operation_id'):
            if isinstance(connection.get(key), str):
                row[key] = connection[key]
        connections.append(row)
    return {'contract': 'integration-inventory-v1', 'complete': True,
            'expected_server_uid': True, 'servers': servers, 'users': users,
            'user_connections': connections}
