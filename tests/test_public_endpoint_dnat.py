"""Docker public-port reconciliation: synthetic rules, never host netfilter."""
import copy
import json
import os
import shlex
import subprocess
import sys
import time
import unittest
from unittest import mock

import public_port_forward as forwarding


def container(name='amnezia-awg3', ip='172.20.0.2', transport='udp', p='443'):
    return ['container-id', '/' + name, True,
            {'bridge': {'IPAddress': ip, 'GlobalIPv6Address': 'fd00::2'}},
            {p + '/' + transport: [{'HostIp': '0.0.0.0', 'HostPort': p},
                                      {'HostIp': '::', 'HostPort': p}]}]


def dnat(ip='172.20.0.2', transport='udp', p='443'):
    target = f'[{ip}]:{p}' if ':' in ip else f'{ip}:{p}'
    return f'-A DOCKER -p {transport} -m {transport} --dport {p} -j DNAT --to-destination {target}'


def request(**kw):
    req = dict(container='amnezia-awg3', server_uid='synthetic-uid', protocol='awg3',
               l4='udp', listen_port='443', public_port='8443', old_public_port='',
               scopes={4: ['203.0.113.9'], 6: []})
    req.update(kw)
    return req


class Netfilter:
    def __init__(self):
        self.container = container()
        self.docker = {4: dnat(), 6: dnat('fd00::2')}
        self.prerouting = {4: [], 6: []}
        self.commands = []
        self.fail = None
        self.on_inspect = None

    def run(self, argv):
        self.commands.append(list(argv))
        if argv[0] == 'docker':
            if self.on_inspect:
                self.on_inspect()
            return json.dumps(self.container), 0
        if self.fail and self.fail(argv):
            return '', 1
        family = 4 if argv[0] == 'iptables' else 6
        action, chain = argv[5:7]
        if action == '-S':
            if chain == 'DOCKER':
                return self.docker[family], 0
            return '\n'.join('-A PREROUTING ' + shlex.join(r) for r in self.prerouting[family]), 0
        r = argv[8:] if action == '-I' else argv[7:]
        if action == '-C':
            return '', 0 if r in self.prerouting[family] else 1
        if action == '-A':
            self.prerouting[family].append(r)
        elif action == '-D':
            self.prerouting[family].remove(r)
        else:
            raise AssertionError(argv)
        return '', 0

    @property
    def mutations(self):
        return [c for c in self.commands if '-A' in c or '-D' in c]


class DnatReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.nf = Netfilter()

    def apply(self, **kw):
        return forwarding.reconcile(request(**kw), self.nf.run)

    def test_same_port_tcp_udp_selects_transport_and_container(self):
        self.nf.docker[4] = dnat('172.20.0.9', 'tcp') + '\n' + dnat()
        self.apply()
        rule = self.nf.prerouting[4][0]
        self.assertEqual(forwarding.option(rule, '--to-destination'), '172.20.0.2:443')
        self.assertEqual(forwarding.option(rule, '-p'), 'udp')

    def test_tcp_uses_its_own_container(self):
        self.nf.container = container('amnezia-xray', '172.20.0.9', 'tcp')
        self.nf.docker[4] = dnat() + '\n' + dnat('172.20.0.9', 'tcp')
        self.apply(container='amnezia-xray', protocol='xray', l4='tcp')
        self.assertIn('172.20.0.9:443', self.nf.prerouting[4][0])

    def test_ambiguous_containers_fail_before_mutation(self):
        self.nf.docker[4] += '\n' + dnat('172.20.0.9')
        with self.assertRaisesRegex(forwarding.ForwardError, 'another container|ambiguous'):
            self.apply()
        self.assertFalse(self.nf.mutations)

    def test_disjoint_host_bindings_are_not_ambiguous(self):
        self.nf.docker[4] += '\n' + dnat('172.20.0.9').replace('-A DOCKER', '-A DOCKER -d 203.0.113.10/32')
        self.apply()
        self.assertEqual(len(self.nf.prerouting[4]), 1)

    def test_recreated_container_replaces_old_ip_and_clear_removes_it(self):
        self.apply()
        self.nf.container[0] = 'replacement-id'
        self.nf.container[3]['bridge']['IPAddress'] = '172.20.0.3'
        self.nf.docker[4] = dnat('172.20.0.3')
        self.apply()
        self.assertEqual(len(self.nf.prerouting[4]), 1)
        self.assertIn('172.20.0.3:443', self.nf.prerouting[4][0])
        self.apply(public_port='', old_public_port='8443')
        self.assertFalse(self.nf.prerouting[4])

    def test_restore_is_idempotent_and_duplicate_owned_rules_are_removed(self):
        self.apply()
        self.nf.commands.clear()
        self.apply()
        self.assertFalse(self.nf.mutations)
        self.nf.prerouting[4] *= 2
        self.apply()
        self.assertEqual(len(self.nf.prerouting[4]), 1)

    def test_kernel_canonical_option_order_keeps_existing_rule(self):
        self.apply()
        r = self.nf.prerouting[4][0]
        i = r.index('-d')
        r[:] = r[i:i+2] + r[:i] + r[i+2:]
        r[1] += '/32'
        # Real -C accepts equivalent option order; emulate that separately.
        original = self.nf.run
        def run(argv):
            if '-C' in argv:
                return '', 0
            return original(argv)
        self.nf.commands.clear()
        forwarding.reconcile(request(), run)
        self.assertFalse(self.nf.mutations)

    def test_port_and_host_change_removes_all_stale_owned_rules(self):
        self.apply()
        self.apply(public_port='9443', scopes={4: ['203.0.113.10'], 6: []})
        self.assertEqual(len(self.nf.prerouting[4]), 1)
        self.assertIn('9443', self.nf.prerouting[4][0])
        self.assertIn('203.0.113.10', self.nf.prerouting[4][0])

    def test_discovery_errors_do_not_mean_missing_container_or_redirect(self):
        self.apply()
        before = copy.deepcopy(self.nf.prerouting)
        self.nf.commands.clear()
        for failure in (lambda a: a[-2:] == ['-S', 'DOCKER'],
                        lambda a: a[-2:] == ['-S', 'PREROUTING']):
            self.nf.fail = failure
            with self.assertRaises(forwarding.ForwardError):
                self.apply()
            self.assertFalse(self.nf.mutations)
            self.assertEqual(self.nf.prerouting, before)

    def test_required_ipv6_discovery_failure_does_not_partially_apply_ipv4(self):
        self.nf.fail = lambda argv: argv[0] == 'ip6tables' and argv[-2:] == ['-S', 'DOCKER']
        with self.assertRaises(forwarding.ForwardError):
            self.apply(scopes={4: ['203.0.113.9'], 6: ['2001:db8::9']})
        self.assertFalse(self.nf.mutations)

    def test_unused_ipv6_unavailable_is_explicit_cleanup_warning(self):
        self.nf.fail = lambda argv: argv[0] == 'ip6tables'
        warning = self.apply()
        self.assertIn('IPv6 cleanup unavailable', warning)
        self.assertEqual(len(self.nf.prerouting[4]), 1)
        self.assertFalse(self.nf.prerouting[6])

    def test_absent_publication_or_port_binding_is_fail_closed(self):
        for missing in ('rule', 'binding'):
            with self.subTest(missing=missing):
                nf = Netfilter()
                if missing == 'rule':
                    nf.docker[4] = ''
                else:
                    nf.container[4] = {}
                with self.assertRaises(forwarding.ForwardError):
                    forwarding.reconcile(request(), nf.run)
                self.assertFalse(nf.mutations)

    def test_wrong_identity_stopped_container_and_mid_discovery_recreation(self):
        for i, value in ((1, '/another-container'), (2, False)):
            nf = Netfilter(); nf.container[i] = value
            with self.assertRaises(forwarding.ForwardError):
                forwarding.reconcile(request(), nf.run)
            self.assertFalse(nf.mutations)
        def recreate():
            self.nf.container[0] += 'x'
        self.nf.on_inspect = recreate
        with self.assertRaisesRegex(forwarding.ForwardError, 'changed during discovery'):
            self.apply()
        self.assertFalse(self.nf.mutations)

    def test_ipv6_is_canonical_and_never_interpreted_by_a_shell(self):
        self.apply(scopes={4: [], 6: ['2001:db8::9']})
        self.assertIn('[fd00::2]:443', self.nf.prerouting[6][0])
        self.assertFalse(self.nf.prerouting[4])
        for value in ("172.20.0.2:443'; touch /tmp/unsafe; '", '[fd00::2]:443;id'):
            self.nf.docker[4] = dnat().replace('172.20.0.2:443', shlex.quote(value))
            self.nf.commands.clear()
            with self.assertRaises(forwarding.ForwardError):
                self.apply()
            self.assertFalse(self.nf.mutations)

    def test_local_destination_only_does_not_intercept_transit(self):
        self.apply()
        self.assertEqual(forwarding.option(self.nf.prerouting[4][0], '--dst-type'), 'LOCAL')

    def test_foreign_nat_preserved_and_conflicting_legacy_rules_block(self):
        foreign = shlex.split('-p tcp --dport 8443 -j DNAT --to-destination 172.20.0.9:443')
        self.nf.prerouting[4].append(foreign)
        self.apply()
        self.apply(public_port='', old_public_port='8443')
        self.assertEqual(self.nf.prerouting[4], [foreign])
        self.nf.prerouting[4].append(shlex.split('-p udp --dport 8443 -j REDIRECT --to-ports 443'))
        self.nf.commands.clear()
        with self.assertRaisesRegex(forwarding.ForwardError, 'unowned'):
            self.apply()
        self.assertFalse(self.nf.mutations)

    def test_other_docker_publication_on_new_port_blocks_insertion(self):
        self.nf.docker[4] += '\n' + dnat('172.20.0.9', p='8443')
        with self.assertRaisesRegex(forwarding.ForwardError, 'unowned'):
            self.apply()
        self.assertFalse(self.nf.mutations)

    def test_instances_have_distinct_markers_and_cannot_remove_each_other(self):
        self.apply()
        first = copy.deepcopy(self.nf.prerouting[4][0])
        self.nf.container[1] = '/amnezia-awg3-2'
        self.apply(protocol='awg3__2', container='amnezia-awg3-2', public_port='9443')
        self.assertEqual(len(self.nf.prerouting[4]), 2)
        self.apply(protocol='awg3__2', container='amnezia-awg3-2', public_port='')
        self.assertEqual(self.nf.prerouting[4], [first])

    def test_failure_during_apply_is_not_reported_as_success(self):
        self.nf.fail = lambda a: '-A' in a
        with self.assertRaisesRegex(forwarding.ForwardError, 'command failed'):
            self.apply()

    def test_recreation_during_apply_withdraws_only_own_forward(self):
        original = self.nf.run
        def run(argv):
            result = original(argv)
            if '-A' in argv:
                self.nf.container[0] = 'recreated-during-apply'
            return result
        with self.assertRaisesRegex(forwarding.ForwardError, 'withdrawn'):
            forwarding.reconcile(request(), run)
        self.assertFalse(self.nf.prerouting[4])

    def test_invalid_ports_and_container_names_are_rejected_without_commands(self):
        for kw in ({'public_port':'84;43'}, {'listen_port':'0'}, {'public_port':'65536'},
                   {'container':"x';id"}, {'public_port':'８４４３'}, {'server_uid':''}):
            with self.subTest(kw=kw), self.assertRaises(forwarding.ForwardError):
                self.apply(**kw)
        self.assertFalse(self.nf.commands)

    def test_clear_warns_instead_of_deleting_an_unmarked_legacy_forward(self):
        legacy = shlex.split('-p udp --dport 8443 -j DNAT --to-destination 172.20.0.99:443')
        self.nf.prerouting[4].append(legacy)
        warning = self.apply(public_port='', old_public_port='8443')
        self.assertIn('manual review', warning)
        self.assertEqual(self.nf.prerouting[4], [legacy])

    def test_subprocess_timeout_does_not_become_success(self):
        with mock.patch.object(subprocess, 'run', side_effect=subprocess.TimeoutExpired('iptables', 15)):
            with self.assertRaisesRegex(forwarding.ForwardError, 'timed out'):
                forwarding.run_command(['iptables', '-S'])


class FakeForwardSSH:
    """Exercise the generated payload with synthetic Docker/netfilter data."""
    def __init__(self):
        self.nf = Netfilter()
        self.requests = []
        self.disconnected = False

    def connect(self):
        pass

    def disconnect(self):
        self.disconnected = True

    def run_sudo_command(self, command, **kwargs):
        argv = shlex.split(command)
        if argv[:2] != ['python3', '-c']:
            raise AssertionError(command)
        compile(argv[2], '<forward-script>', 'exec')
        req = json.loads(argv[3]); self.requests.append(req)
        try:
            warning = forwarding.reconcile(req, self.nf.run)
            return json.dumps({'warning':warning}), '', 0
        except forwarding.ForwardError as e:
            return json.dumps({'warning':str(e)}), '', 1


@unittest.skipUnless(os.environ.get('PUBLIC_FORWARD_LAB_HOST_NETNS'),
                     'opt-in: run inside an isolated Linux network namespace')
class NamespaceDnatTests(unittest.TestCase):
    def test_nonroot_sudo_keeps_complete_process_privileged(self):
        from managers.ssh_manager import SSHManager
        host = int(os.environ['PUBLIC_FORWARD_LAB_HOST_NETNS'])
        self.assertNotEqual(os.stat('/proc/self/ns/net').st_ino, host)
        self.assertNotEqual(os.stat('/proc/self/ns/net').st_ino,
                            os.stat('/proc/1/ns/net').st_ino)
        uid = int(os.environ['PUBLIC_FORWARD_LAB_NONROOT_UID'])
        self.assertGreater(uid, 0)
        # Emulate only SSH transport locally. The real SSHManager sudo wrapper
        # is executed by an unprivileged runner, inside this private netns.
        ssh = mock.Mock()
        ssh._is_root = False
        ssh.password = None
        def execute(command, timeout=60, **kwargs):
            p = subprocess.run(['sudo', '-u', '#' + str(uid), '--', 'sh', '-c', command],
                               capture_output=True, text=True, timeout=timeout)
            return p.stdout, p.stderr, p.returncode
        ssh.run_command = execute
        code = ("import os,subprocess;assert os.geteuid()==0;"
                "subprocess.run(['iptables','-t','nat','-S','PREROUTING'],check=True);"
                "print('privileged-process-ok')")
        out, err, status = SSHManager.run_sudo_command(
            ssh, 'python3 -c ' + shlex.quote(code))
        self.assertEqual(status, 0, err)
        self.assertIn('privileged-process-ok', out)

    def test_real_tcp_udp_reconcile_cleanup_and_recovery(self):
        """Kernel NAT with simulated Docker discovery, no Docker/host mutation.

        Launch via unshare --net; PUBLIC_FORWARD_LAB_HOST_NETNS must contain
        the original host netns inode. Every network mutation checks isolation.
        """
        host = int(os.environ['PUBLIC_FORWARD_LAB_HOST_NETNS'])
        self.assertNotEqual(os.stat('/proc/self/ns/net').st_ino, host)
        self.assertNotEqual(os.stat('/proc/self/ns/net').st_ino,
                            os.stat('/proc/1/ns/net').st_ino,
                            'refusing to mutate the init network namespace')
        children = []
        def command(argv, **kw):
            self.assertNotEqual(os.stat('/proc/self/ns/net').st_ino, host)
            return subprocess.run(argv, capture_output=True, text=True, timeout=8, **kw)
        def checked(argv):
            p = command(argv)
            self.assertEqual(p.returncode, 0, (argv, p.stderr))
            return p.stdout
        def inside(pid, argv):
            self.assertNotEqual(os.stat(f'/proc/{pid}/ns/net').st_ino, host)
            return ['nsenter', '-t', str(pid), '-n'] + argv
        def node(label, subnet):
            p = subprocess.Popen(['unshare', '--net', sys.executable, '-c', 'import time;time.sleep(120)'])
            children.append(p)
            for _ in range(100):
                if os.stat(f'/proc/{p.pid}/ns/net').st_ino != os.stat('/proc/self/ns/net').st_ino:
                    break
                time.sleep(.01)
            self.assertNotEqual(os.stat(f'/proc/{p.pid}/ns/net').st_ino, os.stat('/proc/self/ns/net').st_ino)
            checked(['ip', 'link', 'add', label, 'type', 'veth', 'peer', 'name', label + 'p'])
            checked(['ip', 'link', 'set', label + 'p', 'netns', str(p.pid)])
            # Fresh veth link-local addresses must be usable before the probe;
            # do not race the kernel's one-second DAD timer on fast CI hosts.
            checked(['sysctl', '-q', '-w', 'net.ipv6.conf.' + label + '.accept_dad=0'])
            checked(inside(p.pid, ['sysctl', '-q', '-w',
                                   'net.ipv6.conf.' + label + 'p.accept_dad=0']))
            checked(['ip', 'addr', 'add', subnet + '.1/24', 'dev', label])
            checked(['ip', 'link', 'set', label, 'up'])
            checked(inside(p.pid, ['ip', 'link', 'set', 'lo', 'up']))
            checked(inside(p.pid, ['ip', 'addr', 'add', subnet + '.2/24', 'dev', label + 'p']))
            checked(inside(p.pid, ['ip', 'link', 'set', label + 'p', 'up']))
            checked(inside(p.pid, ['ip', 'route', 'add', 'default', 'via', subnet + '.1']))
            v6 = {'client':'fd42:231::', 'backend':'fd42:232::', 'other':'fd42:233::'}[label]
            checked(['ip', '-6', 'addr', 'add', v6 + '1/64', 'dev', label, 'nodad'])
            checked(inside(p.pid, ['ip', '-6', 'addr', 'add', v6 + '2/64', 'dev', label + 'p', 'nodad']))
            checked(inside(p.pid, ['ip', '-6', 'route', 'add', 'default', 'via', v6 + '1']))
            return p.pid
        echo = '''import socket,threading,time
def tcp(family,host):
 s=socket.socket(family);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
 if family==socket.AF_INET6:s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
 s.bind((host,5000));s.listen()
 while True:
  c,a=s.accept();c.recv(64);c.sendall(b'echo');c.close()
def udp(family,host):
 s=socket.socket(family,socket.SOCK_DGRAM)
 if family==socket.AF_INET6:s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
 s.bind((host,5000))
 while True:
  b,a=s.recvfrom(64);s.sendto(b'echo',a)
for family,host in ((socket.AF_INET,'0.0.0.0'),(socket.AF_INET6,'::')):
 threading.Thread(target=tcp,args=(family,host),daemon=True).start();threading.Thread(target=udp,args=(family,host),daemon=True).start()
time.sleep(120)
'''
        try:
            checked(['ip', 'link', 'set', 'lo', 'up'])
            checked(['ip', 'addr', 'add', '203.0.113.9/32', 'dev', 'lo'])
            checked(['ip', '-6', 'addr', 'add', '2001:db8::9/128', 'dev', 'lo', 'nodad'])
            client = node('client', '10.231.0')
            backend = node('backend', '10.232.0')
            other = node('other', '10.233.0')
            echo_processes = {}
            for pid in (backend, other):
                echo_processes[pid] = subprocess.Popen(inside(pid, [sys.executable, '-c', echo]))
                children.append(echo_processes[pid])
            checked(['sysctl', '-q', '-w', 'net.ipv4.ip_forward=1'])
            checked(['sysctl', '-q', '-w', 'net.ipv6.conf.all.forwarding=1'])
            checked(['iptables', '-P', 'INPUT', 'DROP'])  # REDIRECT would fail
            checked(['ip6tables', '-P', 'INPUT', 'DROP'])
            checked(['ip6tables', '-A', 'INPUT', '-p', 'ipv6-icmp', '-j', 'ACCEPT'])  # neighbor discovery
            checked(['iptables', '-t', 'nat', '-N', 'DOCKER'])
            checked(['ip6tables', '-t', 'nat', '-N', 'DOCKER'])
            for ipt in ('iptables', 'ip6tables'):
                checked([ipt, '-t', 'nat', '-A', 'PREROUTING', '-m', 'addrtype', '--dst-type', 'LOCAL', '-j', 'DOCKER'])
            checked(['iptables', '-t', 'nat', '-A', 'PREROUTING', '-p', 'tcp', '--dport', '9999', '-j', 'REDIRECT', '--to-ports', '9998'])
            foreign = checked(['iptables', '-t', 'nat', '-S', 'PREROUTING']).splitlines()[-1]
            def publish(ip, transport):
                ipt = 'ip6tables' if ':' in ip else 'iptables'
                target = '[' + ip + ']:5000' if ':' in ip else ip + ':5000'
                checked([ipt, '-t', 'nat', '-A', 'DOCKER', '-p', transport, '--dport', '443', '-j', 'DNAT', '--to-destination', target])
            publish('10.232.0.2', 'udp'); publish('10.233.0.2', 'tcp')
            publish('fd42:232::2', 'udp'); publish('fd42:233::2', 'tcp')
            state = {'amnezia-awg3': container(ip='10.232.0.2', p='5000'),
                     'amnezia-xray': container('amnezia-xray', '10.233.0.2', 'tcp', '5000')}
            for c in state.values():
                for binds in c[4].values():
                    for b in binds:
                        b['HostPort'] = '443'
            state['amnezia-awg3'][3]['bridge']['GlobalIPv6Address'] = 'fd42:232::2'
            state['amnezia-xray'][3]['bridge']['GlobalIPv6Address'] = 'fd42:233::2'
            def run(argv):
                if argv[0] == 'docker':
                    return json.dumps(state[argv[-1]]), 0
                p = command(argv)
                return p.stdout, p.returncode
            def apply(**kw):
                kw.setdefault('scopes', {4:['203.0.113.9'], 6:['2001:db8::9']})
                return forwarding.reconcile(request(**kw), run)
            def probe(transport, v6=False):
                code = ("import socket;s=socket.socket(" + ('socket.AF_INET6' if v6 else 'socket.AF_INET') + "," +
                        ('socket.SOCK_DGRAM' if transport == 'udp' else 'socket.SOCK_STREAM') +
                        ");s.settimeout(2);s.connect((" + repr('2001:db8::9' if v6 else '203.0.113.9') + ",8443));s.send(b'probe');assert s.recv(64)==b'echo'")
                p = command(inside(client, [sys.executable, '-c', code]))
                if p.returncode:
                    self.fail(str({'error':p.stderr,
                        'rules':checked(['iptables', '-t', 'nat', '-S', 'PREROUTING']),
                        'counts':checked(['iptables', '-t', 'nat', '-n', '-v', '-L', 'PREROUTING']),
                        'route':checked(inside(backend, ['ip','route','get','10.231.0.2'])),
                        'neighbors':checked(['ip','neigh'])}))
            time.sleep(.2)
            apply(); apply(protocol='xray', container='amnezia-xray', l4='tcp')
            probe('udp'); probe('tcp')
            probe('udp', True); probe('tcp', True)
            before = checked(['iptables', '-t', 'nat', '-S', 'PREROUTING'])
            apply()
            self.assertEqual(checked(['iptables', '-t', 'nat', '-S', 'PREROUTING']), before)
            # Recreate the synthetic UDP publication at a new backend address.
            checked(inside(backend, ['ip', 'addr', 'del', '10.232.0.2/24', 'dev', 'backendp']))
            checked(inside(backend, ['ip', 'addr', 'add', '10.232.0.3/24', 'dev', 'backendp']))
            checked(inside(backend, ['ip', 'route', 'replace', 'default', 'via', '10.232.0.1']))
            # Recreated container => fresh application sockets as well as IP.
            echo_processes[backend].terminate(); echo_processes[backend].wait(timeout=5)
            children.append(subprocess.Popen(inside(backend, [sys.executable, '-c', echo])))
            time.sleep(.2)
            state['amnezia-awg3'][0] = 'recreated-container'
            state['amnezia-awg3'][3]['bridge']['IPAddress'] = '10.232.0.3'
            checked(['iptables', '-t', 'nat', '-D', 'DOCKER', '-p', 'udp', '--dport', '443', '-j', 'DNAT', '--to-destination', '10.232.0.2:5000'])
            publish('10.232.0.3', 'udp'); apply(); probe('udp')
            self.assertNotIn('10.232.0.2:5000', checked(['iptables', '-t', 'nat', '-S', 'PREROUTING']))
            checked(['iptables', '-t', 'nat', '-F', 'DOCKER'])
            before = checked(['iptables', '-t', 'nat', '-S', 'PREROUTING'])
            with self.assertRaises(forwarding.ForwardError):
                apply()
            self.assertEqual(checked(['iptables', '-t', 'nat', '-S', 'PREROUTING']), before)
            publish('10.232.0.3', 'udp'); publish('10.233.0.2', 'tcp')
            apply(); probe('udp'); probe('tcp')
            # An unscoped public endpoint must still exclude routed traffic.
            # The other backend serves 8443 at a non-local routed address;
            # stealing it into our UDP echo on 5000 would return "echo".
            checked(inside(other, ['ip', 'addr', 'add', '198.51.100.99/32', 'dev', 'lo']))
            checked(['ip', 'route', 'add', '198.51.100.99/32', 'via', '10.233.0.2'])
            transit_echo = "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('198.51.100.99',8443));b,a=s.recvfrom(64);s.sendto(b'transit',a)"
            children.append(subprocess.Popen(inside(other, [sys.executable, '-c', transit_echo])))
            apply(scopes={4:[''], 6:[]})
            time.sleep(.1)
            transit_probe = "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2);s.connect(('198.51.100.99',8443));s.send(b'probe');assert s.recv(64)==b'transit'"
            checked(inside(client, [sys.executable, '-c', transit_probe]))
            apply(public_port=''); apply(protocol='xray', container='amnezia-xray', l4='tcp', public_port='')
            final = checked(['iptables', '-t', 'nat', '-S', 'PREROUTING'])
            self.assertIn(foreign, final)
            self.assertNotIn('amnezia-pf:', final)
            self.assertNotIn('amnezia-pf:', checked(['ip6tables', '-t', 'nat', '-S', 'PREROUTING']))
        finally:
            for p in reversed(children):
                p.terminate()
            for p in children:
                p.wait(timeout=5)
