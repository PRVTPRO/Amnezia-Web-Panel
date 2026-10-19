"""Checked, private staging for clientsTable; callers own the RMW lock."""
import json
import logging
import posixpath
import re
import secrets
import shlex


logger = logging.getLogger(__name__)


def save_clients_table(ssh, container, path, table):
    out, _, code = ssh.run_command('mktemp -d /tmp/amnezia-clients.XXXXXXXXXX')
    directory = out.strip()
    if code != 0 or not re.fullmatch(r'/tmp/amnezia-clients\.[A-Za-z0-9]+', directory):
        raise RuntimeError('Could not allocate private clientsTable staging')
    host_file = directory + '/clientsTable'
    nonce = secrets.token_hex(16)
    stage = posixpath.dirname(path) + '/.clientsTable.' + nonce + '.tmp'
    backup_stage = posixpath.dirname(path) + '/.clientsTable.' + nonce + '.backup'
    q = shlex.quote
    try:
        ssh.upload_file(json.dumps(table, indent=2), host_file)
        _, _, code = ssh.run_command('chmod 600 -- ' + q(host_file))
        if code != 0:
            raise RuntimeError('Could not protect clientsTable staging')
        _, _, code = ssh.run_sudo_command(
            'docker cp -- ' + q(host_file) + ' ' + q(container + ':' + stage))
        if code != 0:
            raise RuntimeError('Could not stage clientsTable in container')
        # Rename within the destination directory: failed/partial docker cp
        # cannot truncate the live table. Keep one previous snapshot, with
        # private permissions; failure to back it up aborts the replacement.
        cleanup = 'rm -f -- ' + q(stage) + ' ' + q(backup_stage)
        script = '\n'.join([
            'set -eu',
            'trap ' + q(cleanup) + ' EXIT',
            'test -f ' + q(stage) + ' && test ! -L ' + q(stage),
            'chmod 600 -- ' + q(stage),
            'test ! -e ' + q(backup_stage),
            'test ! -d ' + q(path + '.panel-backup'),
            'if test -e ' + q(path) + '; then',
            '  cp -p -- ' + q(path) + ' ' + q(backup_stage),
            '  chmod 600 -- ' + q(backup_stage),
            '  mv -f -- ' + q(backup_stage) + ' ' + q(path + '.panel-backup'),
            'fi',
            'mv -f -- ' + q(stage) + ' ' + q(path),
        ])
        _, _, code = ssh.run_sudo_command(
            'docker exec -i ' + q(container) + ' sh -c ' + q(script))
        if code != 0:
            raise RuntimeError('Could not confirm clientsTable commit')
    except Exception:
        try:
            ssh.run_sudo_command('docker exec -i ' + q(container) + ' rm -f -- ' + q(stage))
        except Exception:
            logger.warning('Could not clean up container clientsTable staging')
        raise
    finally:
        try:
            _, _, code = ssh.run_command('rm -rf -- ' + q(directory))
            if code != 0:
                logger.warning('Could not clean up private clientsTable staging')
        except Exception:
            logger.warning('Could not clean up private clientsTable staging')
