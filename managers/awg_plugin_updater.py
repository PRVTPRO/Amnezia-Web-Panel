"""Safe updates of the AmneziaWG components used by a managed server.

Two components are handled independently:

* ``kernel_module`` – the DKMS-built ``amneziawg`` kernel module.
* ``userspace``     – the ``amneziavpn/amneziawg-go`` based container image.

The single non-negotiable rule of this module is that a failed update must
leave the server on the version it was running before the operation.  That is
why nothing here removes an installed/working version before the replacement
has been built and verified, and why every failure path ends either with the
previous state untouched or with an explicit rollback.

Notes that shaped the implementation:

* The panel's container keeps its configuration (server key, peers,
  ``clientsTable``) *inside* the container under ``/opt/amnezia``.  A plain
  ``docker run`` replacement would therefore lose every peer, so the userspace
  path copies that directory out and restores it into the new container, and
  the old container is kept (stopped) until the new one has been verified.
* Kernel modules cannot be "swapped atomically": the old module is unloaded
  immediately before the new one is loaded, and the old DKMS version is kept
  registered so a failed activation can be rolled back.

The module never touches ``data.json`` and never decides authorization: the
caller (``app.py``) does that.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import time
import urllib.request
from datetime import datetime, timezone

MODULE_REPO = 'https://github.com/amnezia-vpn/amneziawg-linux-kernel-module.git'
GO_REPO = 'https://github.com/amnezia-vpn/amneziawg-go'
GO_IMAGE = 'amneziavpn/amneziawg-go'

KERNEL_MODULE = 'kernel_module'
USERSPACE = 'userspace'
COMPONENTS = (KERNEL_MODULE, USERSPACE)

#: ``v3.1.20260812`` -> ``3.1.20260812``.  Anything else is not offered as an
#: update target: release names, ``latest`` and free-form tags are rejected so
#: a malicious or renamed tag can never be passed to a shell script.
TAG_RE = re.compile(r'^v?(\d+\.\d+\.\d{8})$')

_VERSION_RE = re.compile(r'(\d+\.\d+\.\d{8})')

#: GitHub tag listings change slowly; one lookup per component per process is
#: plenty and keeps the status endpoint from being rate limited.
TAG_CACHE_TTL = 6 * 60 * 60
_tag_cache = {}

CONTAINER_CONFIG_DIR = '/opt/amnezia'
CONTAINER_CONFIG_SUBDIR = '/opt/amnezia/awg'
KERNEL_BACKUP_DIR = '/var/lib/amnezia-plugin'
DOCKER_NETWORK_SKIP = ('bridge', 'host', 'none')

#: Ordered stages of each update, used by the UI to show "step N of 12" and a
#: percentage that moves even when one stage (DKMS build) takes minutes.
TOTAL_STEPS = 12
STAGE_STEPS = {
    KERNEL_MODULE: {
        'start': 1, 'preflight': 2, 'dependencies': 3, 'backup': 4,
        'download': 5, 'dkms-add': 6, 'build': 7, 'install': 8,
        'verify': 9, 'activate': 10, 'tunnel': 11, 'done': 12,
        'cleanup': 12,
    },
    USERSPACE: {
        'start': 1, 'prepare': 2, 'dependencies': 3, 'backup': 4,
        'build': 5, 'switch': 6, 'network': 7, 'restore': 8,
        'verify': 9, 'finalize': 10, 'tunnel': 11, 'done': 12,
        'cleanup': 12,
    },
}


def stage_step(component, stage):
    """``(step, total)`` for a log stage, or ``None`` for transient lines."""
    step = (STAGE_STEPS.get(component) or {}).get(stage)
    if not step:
        return None
    return step, TOTAL_STEPS


class PluginUpdateError(Exception):
    """Operation failure with a stable machine-readable ``code``."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


def parse_tag(tag):
    """Return the bare version from a release tag, or ``None``."""
    match = TAG_RE.match((tag or '').strip())
    return match.group(1) if match else None


def version_tuple(version):
    """Comparable ``(major, minor, date)`` tuple, or ``None``."""
    parsed = parse_tag(version)
    if not parsed:
        return None
    major, minor, date = parsed.split('.')
    return int(major), int(minor), int(date)


def pick_latest(tags):
    """Highest valid version among ``tags``, ignoring everything else."""
    best = None
    for tag in tags or ():
        version = parse_tag(tag)
        if version is None:
            continue
        if best is None or version_tuple(version) > version_tuple(best):
            best = version
    return best


def _repo_slug(repo):
    """``https://github.com/owner/name.git`` -> ``owner/name``.

    The GitHub API needs the owner: a bare repository name answers 404, which
    is exactly the kind of failure that must not be mistaken for "up to date".
    """
    text = (repo or '').strip()
    if 'github.com/' in text:
        text = text.split('github.com/', 1)[1]
    return text.replace('.git', '').strip('/')


def _headers():
    headers = {
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'amnezia-web-panel',
    }
    # Unauthenticated GitHub API is limited to 60 requests/hour; an operator
    # that runs a large fleet can supply a token instead of hitting the limit.
    token = (os.environ.get('GITHUB_TOKEN') or '').strip()
    if token:
        headers['Authorization'] = 'Bearer ' + token
    return headers


def _github_tags(repo):
    url = 'https://api.github.com/repos/%s/tags?per_page=100' % repo
    request = urllib.request.Request(url, headers=_headers())
    with urllib.request.urlopen(request, timeout=15) as response:
        payload = json.loads(response.read().decode('utf-8'))
    return [entry.get('name', '') for entry in payload if isinstance(entry, dict)]


def _github_compare(repo, base, head):
    url = 'https://api.github.com/repos/%s/compare/%s...%s' % (repo, base, head)
    request = urllib.request.Request(url, headers=_headers())
    with urllib.request.urlopen(request, timeout=15) as response:
        payload = json.loads(response.read().decode('utf-8'))
    commits = []
    for item in payload.get('commits') or []:
        commits.append({
            'sha': (item.get('sha') or '')[:8],
            'subject': ((item.get('commit') or {}).get('message') or '').splitlines()[0],
        })
    return commits


def _iteration(text):
    # The binary prints "amneziawg-go v3.1.20260828" and `wg --version` prints
    # a whole sentence, so the version must be found anywhere in the line.
    return re.findall(r'(\d+\.\d+\.\d{8})', text or '')


class AwgPluginUpdater:
    """Version discovery and fail-safe updates for one server."""

    def __init__(self, ssh, *, tag_source=None):
        self.ssh = ssh
        self._root = getattr(ssh, '_is_root', True)
        self._tag_source = tag_source or _github_tags

    # ---------------------------------------------------------------- versions

    def latest_versions(self, component=None):
        """Newest published version of one or all components."""
        wanted = [component] if component else list(COMPONENTS)
        now = time.time()
        result = {}
        for component in wanted:
            repo = MODULE_REPO if component == KERNEL_MODULE else GO_REPO
            cached = _tag_cache.get(component)
            if cached and now - cached[0] < TAG_CACHE_TTL:
                result[component] = cached[1]
                continue
            try:
                tags = self._tag_source(_repo_slug(repo))
            except Exception as exc:  # network/API failure is not "up to date"
                raise PluginUpdateError(
                    'version_check_failed',
                    'cannot read published versions: %s' % exc,
                )
            latest = pick_latest(tags)
            _tag_cache[component] = (now, latest)
            result[component] = latest
        return result

    def installed_versions(self, containers=None):
        """Versions actually present on the managed server."""
        out, _, _ = self._exec(
            "modinfo -F version amneziawg 2>/dev/null || "
            "cat /sys/module/amneziawg/version 2>/dev/null || true"
        )
        kernel = _VERSION_RE.search((out or '').strip())
        kernel_version = kernel.group(1) if kernel else None
        recorded = self._recorded_version()
        if recorded:
            # A module built from a tag whose sources still carry the old
            # WIREGUARD_VERSION would under-report itself; the record is
            # trusted only while its code hash matches the loaded module.
            kernel_version = recorded
        return {
            KERNEL_MODULE: kernel_version,
            USERSPACE: self._userspace_version(containers),
        }

    def _recorded_version(self):
        out, _, _ = self._exec(
            'cat %s/applied.json 2>/dev/null || true' % KERNEL_BACKUP_DIR
        )
        text = (out or '').strip()
        if not text:
            return None
        try:
            payload = json.loads(text)
        except ValueError:
            return None
        version = payload.get('version')
        srcversion = payload.get('srcversion')
        if not version or not srcversion:
            return None
        sys_src, _, _ = self._exec(
            'cat /sys/module/amneziawg/srcversion 2>/dev/null || true'
        )
        if (sys_src or '').strip() != srcversion:
            return None
        return version

    def _record_applied(self, version, srcversion, log):
        if not srcversion:
            return
        payload = json.dumps({'version': version, 'srcversion': srcversion})
        self._run(
            "mkdir -p %s && printf '%%s' '%s' > %s/applied.json"
            % (KERNEL_BACKUP_DIR, payload.replace("'", ''), KERNEL_BACKUP_DIR),
            log, 'finalize',
        )

    def _go_containers(self):
        """AWG containers whose image is built from amneziawg-go.

        The panel tags its derived images with the container name
        (``amnezia-awg3``), so matching the base repository name never works.
        The generated Dockerfile is the reliable marker, and it also excludes
        the legacy ``amnezia-wg`` containers.
        """
        out, _, _ = self._exec(
            "docker ps -a --format '{{.Names}}\t{{.Image}}' 2>/dev/null || true"
        )
        containers = []
        for line in (out or '').splitlines():
            if '\t' not in line:
                continue
            name, image = line.split('\t', 1)
            name = name.strip()
            if not name.startswith('amnezia-awg'):
                continue
            dockerfile, _, _ = self._exec(
                'head -1 /opt/amnezia/%s/Dockerfile 2>/dev/null || true' % name
            )
            if 'amneziavpn/amneziawg-go' not in (dockerfile or ''):
                continue
            containers.append((name, image.strip()))
        return containers

    def _image_version(self, tag):
        """Version of an image: label first, then the binary inside it."""
        out, _, _ = self._exec(
            "docker inspect --format '{{index .Config.Labels "
            "\"org.opencontainers.image.version\"}}' %s 2>/dev/null || true" % tag
        )
        found = _VERSION_RE.search(out or '')
        if found:
            return found.group(1)
        out, _, _ = self._exec(
            'docker run --rm --entrypoint sh %s -c '
            '"amneziawg-go --version 2>/dev/null || wg --version 2>/dev/null" 2>/dev/null || true'
            % tag,
            timeout=120,
        )
        found = _VERSION_RE.search(out or '')
        return found.group(1) if found else None

    def _userspace_version(self, containers=None):
        containers = containers if containers is not None else self._go_containers()
        versions = set()
        for name, image in containers:
            # The userspace daemon has its own version line (0.0.YYYYMMDD),
            # unrelated to the git tags of the repository, so the binary is
            # the only honest source.
            out, _, _ = self._exec(
                'docker exec %s sh -c '
                '"amneziawg-go --version 2>/dev/null || wg --version 2>/dev/null" 2>/dev/null || true'
                % name,
                timeout=120,
            )
            for found in _iteration(out or ''):
                versions.add(found)
            if not versions:
                out, _, _ = self._exec(
                    "docker inspect --format "
                    "'{{index .Config.Labels \"org.opencontainers.image.version\"}}' "
                    "%s 2>/dev/null || true" % name
                )
                for found in _iteration(out or ''):
                    versions.add(found)
            if not versions:
                tag = image.split(':', 1)[-1]
                for found in _iteration(tag):
                    versions.add(found)
        if not versions:
            return None
        return sorted(versions, key=version_tuple)[-1]

    def status(self, latest=None, installed=None):
        containers = self._go_containers()
        installed = installed if installed is not None else self.installed_versions(containers)
        # A component that the server does not use at all is not offered as an
        # update: installing the userspace image without AWG containers (or
        # the kernel module without a module user) would be pointless.
        applicable = dict.fromkeys(COMPONENTS, True)
        if not containers:
            applicable[USERSPACE] = False
        if latest is None:
            latest = {}
            for component in COMPONENTS:
                # The userspace daemon reports 0.0.YYYYMMDD, which cannot be
                # compared with the repository's 3.1.YYYYMMDD tags. It is shown
                # for information only and never offered as an update; it is
                # replaced by rebuilding the protocol image.
                if component == USERSPACE:
                    latest[component] = None
                    continue
                if applicable[component]:
                    latest.update(self.latest_versions(component))
        components = {}
        for component in COMPONENTS:
            if not applicable[component]:
                components[component] = {
                    'applicable': False,
                    'installed': None,
                    'available': None,
                    'update_available': False,
                    'installed_detected': False,
                }
                continue
            current = installed.get(component)
            available = latest.get(component)
            components[component] = {
                'applicable': True,
                'installed': current,
                'available': available,
                'update_available': bool(
                    available and (current is None or version_tuple(current) < version_tuple(available))
                ),
                'installed_detected': current is not None,
            }
        return {
            'components': components,
            'checked_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        }

    def changelog(self, component, version):
        repo = MODULE_REPO if component == KERNEL_MODULE else GO_REPO
        installed = self.installed_versions().get(component)
        if not installed or not version:
            return []
        try:
            return _github_compare(
                _repo_slug(repo),
                'v%s' % installed if not installed.startswith('v') else installed,
                'v%s' % version,
            )
        except Exception as exc:
            raise PluginUpdateError('changelog_failed', 'cannot read changelog: %s' % exc)

    # -------------------------------------------------------------- preflight

    def _module_ref_count(self):
        out, _, _ = self._exec(
            "awk '$1==\"amneziawg\"{print $3}' /proc/modules 2>/dev/null || true"
        )
        text = (out or '').strip()
        return int(text) if text.isdigit() else 0

    def _package_manager(self):
        out, _, _ = self._exec(
            "for m in apt-get dnf yum apk pacman; do command -v $m >/dev/null && echo $m && break; done"
        )
        return (out or '').strip().splitlines()[0] if (out or '').strip() else None

    def preflight(self, component):
        if component not in COMPONENTS:
            raise PluginUpdateError('unsupported', 'unknown component')
        if component == KERNEL_MODULE:
            out, _, _ = self._exec(
                "echo KVER=$(uname -r); "
                "test -d /lib/modules/$(uname -r)/build && echo HEADERS=yes || echo HEADERS=no; "
                "command -v dkms >/dev/null && echo DKMS=yes || echo DKMS=no; "
                "command -v gcc >/dev/null && echo GCC=yes || echo GCC=no; "
                "command -v make >/dev/null && echo MAKE=yes || echo MAKE=no; "
                "command -v git >/dev/null && echo GIT=yes || echo GIT=no"
            )
            values = dict(
                line.split('=', 1) for line in (out or '').splitlines() if '=' in line
            )
            manager = self._package_manager()
            installable = []
            blockers = []
            if values.get('HEADERS') != 'yes':
                if manager:
                    installable.append('headers')
                else:
                    blockers.append(
                        'no kernel headers for the running kernel and no known package manager'
                    )
            for tool, flag in (('dkms', 'DKMS'), ('gcc', 'GCC'), ('make', 'MAKE'), ('git', 'GIT')):
                if values.get(flag) != 'yes':
                    if manager:
                        installable.append(tool)
                    else:
                        blockers.append('%s is not installed and there is no known package manager' % tool)
            secure_boot = self._secure_boot_enabled()
            if secure_boot:
                # If the module is already loaded, Secure Boot must already
                # accept it (enrolled MOK), so the new build will load too.
                loaded, _, _ = self._exec(
                    'test -d /sys/module/amneziawg && echo yes || true'
                )
                if 'yes' not in (loaded or ''):
                    blockers.append(
                        'Secure Boot is enabled; an unsigned module cannot be loaded'
                    )
            refs = self._module_ref_count()
            return {
                'component': component,
                'kernel': values.get('KVER'),
                'package_manager': manager,
                'requires_interruption': refs > 0,
                'ready': not blockers,
                'installable': installable,
                'blockers': blockers,
            }
        containers = self._go_containers()
        if not containers:
            raise PluginUpdateError('not_installed', 'no userspace AWG containers found')
        return {
            'component': component,
            'containers': [name for name, _ in containers],
            # Recreating a container restarts the tunnel for a moment.
            'requires_interruption': True,
            'ready': True,
            'installable': [],
            'blockers': [],
        }

    def _secure_boot_enabled(self):
        out, _, _ = self._exec(
            'command -v mokutil >/dev/null 2>&1 && mokutil --sb-state 2>/dev/null || true'
        )
        return 'enabled' in (out or '').lower()

    # ----------------------------------------------------------- dependencies

    #: package name per manager for the base build tools
    PACKAGE_NAMES = {
        'apt-get': {'dkms': 'dkms', 'gcc': 'gcc', 'make': 'make', 'git': 'git'},
        'dnf': {'dkms': 'dkms', 'gcc': 'gcc', 'make': 'make', 'git': 'git'},
        'yum': {'dkms': 'dkms', 'gcc': 'gcc', 'make': 'make', 'git': 'git'},
        'apk': {'dkms': 'dkms', 'gcc': 'gcc', 'make': 'make', 'git': 'git'},
        'pacman': {'dkms': 'dkms', 'gcc': 'gcc', 'make': 'make', 'git': 'git'},
    }

    def _install(self, manager, packages, log):
        joined = ' '.join(packages)
        if manager == 'apt-get':
            command = 'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq %s' % joined
        elif manager in ('dnf', 'yum'):
            command = '%s install -y %s' % (manager, joined)
        elif manager == 'apk':
            command = 'apk add --no-cache %s' % joined
        elif manager == 'pacman':
            command = 'pacman -S --noconfirm --needed %s' % joined
        else:
            raise PluginUpdateError('preflight_failed', 'unsupported package manager')
        out, err, code = self._run(command, log, 'dependencies', timeout=900, sudo=True)
        if code == 0:
            return True
        text = ((out or '') + (err or '')).lower()
        if manager == 'apt-get' and ('lock' in text or 'held by process' in text):
            log('dependencies', 'package manager is busy, retrying once')
            time.sleep(15)
            out, err, code = self._run(command, log, 'dependencies', timeout=900, sudo=True)
            if code == 0:
                return True
        return False

    def _headers_candidates(self, manager, kernel):
        """Possible header packages for a kernel, most specific first."""
        candidates = []
        if manager == 'apt-get':
            candidates.append('linux-headers-%s' % kernel)
            if 'cloud' in (kernel or ''):
                candidates.append('linux-headers-cloud-amd64')
            if 'generic' in (kernel or ''):
                candidates.append('linux-headers-generic')
            candidates.append('linux-headers-amd64')
        elif manager in ('dnf', 'yum'):
            candidates.append('kernel-devel-%s' % kernel)
            candidates.append('kernel-devel')
        elif manager == 'apk':
            candidates.append('linux-headers')
        elif manager == 'pacman':
            candidates.append('linux-headers')
        return candidates

    def ensure_dependencies(self, component, log):
        """Install whatever the build needs; only impossible cases block."""
        check = self.preflight(component)
        if check['blockers']:
            raise PluginUpdateError('preflight_failed', '; '.join(check['blockers']))
        installable = check.get('installable') or []
        if not installable:
            log('dependencies', 'all build dependencies are present')
            return
        manager = check['package_manager']
        log('dependencies', 'missing: %s' % ', '.join(installable))
        names = self.PACKAGE_NAMES.get(manager, {})
        packages = [names[item] for item in installable if item != 'headers' and item in names]
        if packages:
            if not self._install(manager, packages, log):
                raise PluginUpdateError(
                    'preflight_failed',
                    'cannot install %s with %s; see the journal' % (', '.join(packages), manager),
                )
        if 'headers' in installable:
            kernel = check.get('kernel') or ''
            installed = False
            for candidate in self._headers_candidates(manager, kernel):
                log('dependencies', 'trying %s' % candidate)
                if self._install(manager, [candidate], log):
                    installed = True
                    break
            if not installed:
                raise PluginUpdateError(
                    'preflight_failed',
                    'no kernel headers for %s are available in the repositories' % kernel,
                )
        recheck = self.preflight(component)
        if recheck['blockers']:
            raise PluginUpdateError('preflight_failed', '; '.join(recheck['blockers']))
        missing = recheck.get('installable') or []
        if missing:
            raise PluginUpdateError(
                'preflight_failed',
                'still missing after installation: %s' % ', '.join(missing),
            )
        log('dependencies', 'dependencies are ready')

    # ---------------------------------------------------------------- updates

    def update(self, component, target, *, allow_interrupt=False, log=None, should_cancel=None):
        log = log or (lambda stage, message: None)
        if component not in COMPONENTS:
            raise PluginUpdateError('unsupported', 'unknown component')
        version = parse_tag(target)
        if version is None:
            raise PluginUpdateError('unsupported', 'refusing unsupported target %r' % (target,))

        check = self.preflight(component)
        log('preflight', 'kernel %s, blockers: %s' % (check.get('kernel'), check.get('blockers') or 'none'))
        if check['blockers']:
            raise PluginUpdateError('preflight_failed', '; '.join(check['blockers']))
        if check['requires_interruption'] and not allow_interrupt:
            raise PluginUpdateError(
                'requires_confirmation',
                'updating this component temporarily interrupts active tunnels',
            )

        # One click: install whatever is missing instead of failing the update.
        self.ensure_dependencies(component, log)

        if component == KERNEL_MODULE:
            return self._update_kernel(version, allow_interrupt, log, should_cancel)
        return self._update_userspace(version, allow_interrupt, log, should_cancel)

    # -- kernel ---------------------------------------------------------------

    def _exec(self, command, timeout=60):
        """Run a command with enough privileges for the build.

        On cloud images the panel often connects as a normal user (debian,
        ubuntu, …). ``dkms`` and ``modinfo`` live in /usr/sbin, which is not in
        that user's PATH, and installing packages needs root anyway, so every
        remote command is elevated when the session is not root.
        """
        if getattr(self, '_root', True):
            return self.ssh.run_command(command, timeout=timeout)
        if '\n' in command:
            return self.ssh.run_sudo_script(command, timeout=timeout)
        runner = getattr(self.ssh, 'run_sudo_command', None)
        if runner is None:
            return self.ssh.run_command(command, timeout=timeout)
        # sudo only understands `sudo <program> <args>`: loops, pipelines and
        # `&&` chains must be handed to a shell, otherwise the probe silently
        # returns nothing ("no known package manager").
        return runner('bash -c ' + shlex.quote(command), timeout=timeout)

    def _run(self, command, log, stage, timeout=120, sudo=False):
        log(stage, command)
        if sudo or not getattr(self, '_root', True):
            runner = self.ssh.run_sudo_script
        else:
            runner = self.ssh.run_command
        out, err, code = runner(command, timeout=timeout)
        text = ((out or '') + (err or '')).strip()
        if text:
            for line in text.splitlines()[-40:]:
                log(stage, line)
        return out or '', err or '', code

    def _dkms_remove(self, version, log, stage='cleanup'):
        # "not located in the DKMS tree" is a normal outcome on a fresh retry.
        return self._run(
            'dkms remove amneziawg/%s --all 2>/dev/null || true' % version,
            log, stage, timeout=600,
        )

    def _update_kernel(self, version, allow_interrupt, log, should_cancel=None):
        # The previously installed module is preserved twice before anything
        # is built: a byte copy of the loaded .ko (DKMS sources may have been
        # removed by an earlier install) and the DKMS version itself.
        previous = self.installed_versions().get(KERNEL_MODULE)
        backup = self._backup_kernel_module(previous, log)
        stopped = self._stop_awg_containers(log) if allow_interrupt else []

        def cancelled():
            return bool(should_cancel and should_cancel())

        try:
            self._run('rm -rf /tmp/awg-plugin-update', log, 'prepare')
            # A previous attempt may have left this exact version registered.
            # Never remove the version that is currently installed and loaded.
            if version != previous:
                self._dkms_remove(version, log, 'prepare')
            out, err, code = self._run(
                'git clone --depth 1 --branch v%s %s /tmp/awg-plugin-update'
                % (version, MODULE_REPO),
                log, 'download', timeout=300,
            )
            if code != 0:
                raise PluginUpdateError('update_failed', 'cannot download module sources')

            self._run(
                'cd /tmp/awg-plugin-update/src && '
                "sed -i 's/^PACKAGE_VERSION=.*/PACKAGE_VERSION=\"%s\"/' dkms.conf"
                % version,
                log, 'prepare',
            )
            # Upstream does not always bump the in-tree version string, so a
            # module built from the new tag can still report the old version.
            # Patch it, otherwise MODULE_VERSION() keeps advertising the old
            # number and the panel would offer the same update forever.
            self._run(
                "cd /tmp/awg-plugin-update/src && "
                "sed -i 's/#define WIREGUARD_VERSION .*/#define WIREGUARD_VERSION \"%s\"/' version.h"
                % version,
                log, 'prepare',
            )
            self._run(
                'cd /tmp/awg-plugin-update/src && grep -m1 WIREGUARD_VERSION version.h || true',
                log, 'prepare',
            )
            out, err, code = self._run(
                'cd /tmp/awg-plugin-update/src && dkms add .', log, 'dkms-add', timeout=300,
            )
            if code != 0:
                raise PluginUpdateError('update_failed', 'dkms add failed')

            out, err, code = self._run(
                'dkms build amneziawg/%s' % version, log, 'build', timeout=1800,
            )
            if code != 0:
                self._dkms_remove(version, log, 'cleanup')
                raise PluginUpdateError(
                    'update_failed',
                    'dkms build failed; previously installed module kept',
                )
            if cancelled():
                self._dkms_remove(version, log, 'cleanup')
                raise PluginUpdateError('cancelled', 'update cancelled; previously installed module kept')

            out, err, code = self._run(
                'dkms install amneziawg/%s --force' % version, log, 'install', timeout=600,
            )
            if code != 0:
                self._dkms_remove(version, log, 'cleanup')
                raise PluginUpdateError(
                    'update_failed',
                    'dkms install failed; previously installed module kept',
                )

            # modprobe -n is a no-op while the old module is loaded, so check
            # the real thing: the new .ko must have been built for this kernel.
            kver_out, _, _ = self._run('uname -r', log, 'verify')
            kver = (kver_out or '').strip()
            out, err, code = self._run(
                "modinfo -F vermagic $(modinfo -n amneziawg 2>/dev/null) 2>/dev/null || true",
                log, 'verify',
            )
            vermagic = (out or '').strip()
            if kver and vermagic and not vermagic.startswith(kver):
                self._dkms_remove(version, log, 'cleanup')
                raise PluginUpdateError(
                    'update_failed',
                    'the built module targets %s, not the running kernel %s; nothing was switched'
                    % (vermagic.split()[0], kver),
                )

            # srcversion is a hash of the built code and changes even when the
            # version string does not, so it is the reliable identity check.
            out, _, _ = self._run(
                'modinfo -F srcversion $(modinfo -n amneziawg 2>/dev/null) 2>/dev/null || true',
                log, 'verify',
            )
            new_srcversion = (out or '').strip().splitlines()[0] if (out or '').strip() else ''

            out, err, code = self._run('modprobe -n amneziawg', log, 'verify', timeout=120)
            if code != 0:
                self._dkms_remove(version, log, 'cleanup')
                raise PluginUpdateError(
                    'update_failed',
                    'the built module cannot be loaded; previously installed module kept',
                )

            if cancelled():
                self._dkms_remove(version, log, 'cleanup')
                raise PluginUpdateError('cancelled', 'update cancelled before the module switch')

            log('activate', 'unloading the current module')
            out, err, code = self._run('modprobe -r amneziawg', log, 'activate', timeout=120, sudo=True)
            if code != 0:
                # The module was grabbed by a new tunnel between the preflight
                # and now. dkms install of the new version overwrote its .ko on
                # disk, so put the saved copy of the old one back.
                self._restore_kernel_files(version, previous, backup, log)
                raise PluginUpdateError(
                    'update_failed',
                    'the module is in use by running tunnels; nothing was switched',
                )
            out, err, code = self._run('modprobe amneziawg', log, 'activate', timeout=120, sudo=True)
            if code != 0:
                self._rollback_kernel(version, previous, backup, log)
                raise PluginUpdateError('update_failed', 'module built but could not be loaded; rolled back')

            # Identity check. Prefer srcversion (a hash of the built code) so a
            # stale version string in upstream sources cannot cause a false
            # mismatch; fall back to the version when srcversion is absent.
            out, _, _ = self._run(
                'cat /sys/module/amneziawg/srcversion 2>/dev/null || true',
                log, 'verify',
            )
            loaded_srcversion = (out or '').strip()
            out, _, _ = self._run(
                'cat /sys/module/amneziawg/version 2>/dev/null || true',
                log, 'verify',
            )
            loaded = _VERSION_RE.search(out or '')
            same_code = bool(new_srcversion) and loaded_srcversion == new_srcversion
            same_version = bool(loaded) and loaded.group(1) == version
            if not (same_code or same_version):
                self._rollback_kernel(version, previous, backup, log)
                raise PluginUpdateError(
                    'update_failed',
                    'the loaded module is still the previous build; rolled back',
                )
            if not same_version:
                log('verify', 'note: the module reports %s but was built from %s'
                    % (loaded.group(1) if loaded else 'unknown', version))

            self._record_applied(version, new_srcversion or loaded_srcversion, log)
            self._start_awg_containers(stopped, log)
            self._cleanup_tmp(log)
            return {
                'component': KERNEL_MODULE,
                'previous': previous,
                'installed': version,
                'state': 'updated',
                'rolled_back': False,
            }
        except PluginUpdateError as exc:
            self._start_awg_containers(stopped, log)
            if exc.code != 'rollback_failed':
                self._cleanup_tmp(log)
            raise
        except Exception as exc:
            self._start_awg_containers(stopped, log)
            self._cleanup_tmp(log)
            raise PluginUpdateError('update_failed', str(exc))

    def _backup_kernel_module(self, previous, log):
        """Copy the loaded .ko before anything can overwrite it.

        ``dkms install`` puts the new module at the same path as the old one,
        and an earlier install may have removed the old DKMS source, so a file
        copy is the only rollback material that is always available.
        """
        if not previous:
            log('backup', 'no installed module to back up (first install)')
            return None
        out, _, _ = self._run(
            'mkdir -p %s; MODPATH=$(modinfo -n amneziawg 2>/dev/null || true); '
            'if [ -n "$MODPATH" ] && [ -f "$MODPATH" ]; then '
            'cp -a "$MODPATH" %s/amneziawg-%s.ko; '
            'echo "ORIG=$MODPATH"; echo "BACKUP=%s/amneziawg-%s.ko"; fi'
            % (KERNEL_BACKUP_DIR, KERNEL_BACKUP_DIR, previous, KERNEL_BACKUP_DIR, previous),
            log, 'backup',
        )
        backup = None
        original = None
        for line in (out or '').splitlines():
            if line.startswith('ORIG='):
                original = line.split('=', 1)[1].strip()
            elif line.startswith('BACKUP='):
                backup = line.split('=', 1)[1].strip()
        if not backup:
            log('backup', 'WARNING: could not copy the current module file')
            return None
        log('backup', 'saved %s -> %s' % (original, backup))
        return {'path': backup, 'original': original, 'version': previous}

    def _restore_kernel_files(self, version, previous, backup, log):
        """Put the previous module back on disk after a failed switch."""
        self._dkms_remove(version, log, 'rollback')
        if backup and backup.get('path') and backup.get('original'):
            out, err, code = self._run(
                'mkdir -p "$(dirname %s)" && cp -a %s %s'
                % (backup['original'], backup['path'], backup['original']),
                log, 'rollback',
            )
            if code != 0:
                raise PluginUpdateError(
                    'rollback_failed',
                    'cannot put the saved module back at %s; restore it by hand before rebooting'
                    % backup['original'],
                )
            self._run('depmod -a', log, 'rollback', timeout=120, sudo=True)
            return
        if previous:
            # No file copy (older deployments): rebuild from the DKMS source.
            out, err, code = self._run(
                'dkms build amneziawg/%s' % previous, log, 'rollback', timeout=1800,
            )
            if code != 0:
                raise PluginUpdateError(
                    'rollback_failed',
                    'cannot rebuild module %s; reload the host before relying on AWG' % previous,
                )
            out, err, code = self._run(
                'dkms install amneziawg/%s --force' % previous, log, 'rollback', timeout=600,
            )
            if code != 0:
                raise PluginUpdateError(
                    'rollback_failed',
                    'cannot reinstall module %s; reload the host before relying on AWG' % previous,
                )
            self._run('depmod -a', log, 'rollback', timeout=120, sudo=True)

    def _rollback_kernel(self, version, previous, backup, log):
        """Restore the previously loaded module after a failed activation."""
        log('rollback', 'restoring previous module %s' % (previous or 'unknown'))
        self._restore_kernel_files(version, previous, backup, log)
        out, err, code = self._run('modprobe amneziawg', log, 'rollback', timeout=120, sudo=True)
        if code != 0:
            raise PluginUpdateError(
                'rollback_failed',
                'the previous module is on disk but could not be loaded; reload the host',
            )
        # Only /sys reflects the module that is actually loaded; modinfo reads
        # the file on disk and can differ.
        out, _, _ = self._run(
            'cat /sys/module/amneziawg/version 2>/dev/null || true', log, 'rollback',
        )
        loaded = _VERSION_RE.search(out or '')
        if previous and (not loaded or loaded.group(1) != previous):
            raise PluginUpdateError(
                'rollback_failed',
                'could not restore module %s; reload the host before relying on AWG' % previous,
            )

    def _awg_container_names(self):
        out, _, _ = self._exec(
            "docker ps --format '{{.Names}}' 2>/dev/null | grep -E '^amnezia-awg' || true"
        )
        return [line.strip() for line in (out or '').splitlines() if line.strip()]

    def _stop_awg_containers(self, log):
        names = self._awg_container_names()
        for name in names:
            log('stop', 'stopping %s to release the kernel module' % name)
            self._exec('docker stop %s' % name, timeout=120)
        return names

    def _start_awg_containers(self, names, log):
        for name in names or ():
            log('tunnel', 'starting %s' % name)
            self._exec('docker start %s' % name, timeout=120)
            # The tunnel comes back through start.sh, which needs a few seconds;
            # a single immediate check produces false warnings on slow hosts.
            up = False
            for _attempt in range(5):
                out, _, _ = self._exec(
                    'docker exec %s sh -c "awg show 2>/dev/null || wg show 2>/dev/null"' % name,
                    timeout=60,
                )
                if 'interface' in (out or ''):
                    up = True
                    break
                time.sleep(2)
            if not up:
                log('tunnel', 'WARNING: %s started but its tunnel is not up yet' % name)

    # -- userspace ------------------------------------------------------------

    def _inspect_container(self, name):
        out, err, code = self._exec('docker inspect %s 2>/dev/null' % name)
        if code != 0 or not (out or '').strip():
            raise PluginUpdateError('unsupported', 'cannot inspect container %s' % name)
        try:
            payload = json.loads(out)
        except ValueError:
            raise PluginUpdateError('unsupported', 'unreadable container metadata for %s' % name)
        if not isinstance(payload, list) or not payload:
            raise PluginUpdateError('unsupported', 'unexpected container metadata for %s' % name)
        return payload[0]

    @staticmethod
    def _validate_container_shape(name, info):
        """Only containers created by this panel are recreated automatically."""
        host = info.get('HostConfig') or {}
        unsupported = []
        if not host.get('Privileged'):
            unsupported.append('privileged')
        caps = set(host.get('CapAdd') or [])
        if not caps or not caps <= {'NET_ADMIN', 'SYS_MODULE'}:
            unsupported.append('capabilities')
        if not any(bind.startswith('/lib/modules:') for bind in (host.get('Binds') or [])):
            unsupported.append('module mount')
        for key in ('Devices', 'Tmpfs', 'ExtraHosts', 'PidMode', 'IpcMode'):
            if host.get(key):
                unsupported.append(key)
        network = host.get('NetworkMode') or 'default'
        if network not in ('default', 'bridge'):
            unsupported.append('network mode %s' % network)
        if (host.get('RestartPolicy') or {}).get('Name') != 'always':
            unsupported.append('restart policy')
        return unsupported

    def _dockerfile_dir(self, name):
        path = '/opt/amnezia/%s' % name
        out, _, code = self._exec('test -f %s/Dockerfile && echo yes || true' % path)
        return path if 'yes' in (out or '') else None

    def _update_userspace(self, version, allow_interrupt, log, should_cancel=None):
        containers = self._go_containers()
        if not containers:
            raise PluginUpdateError('not_installed', 'no userspace AWG containers found')

        before = self._userspace_version()
        prepared = []
        try:
            for name, _image in containers:
                prepared.append(self._prepare_container_update(name, log))
            for item in prepared:
                if should_cancel and should_cancel():
                    raise PluginUpdateError(
                        'cancelled',
                        'update cancelled; containers already replaced are being restored',
                    )
                self._apply_container_update(item, version, log, should_cancel)
        except PluginUpdateError as exc:
            failures = self._rollback_containers(prepared, log)
            if failures:
                raise PluginUpdateError(
                    'rollback_failed',
                    '%s; could not restore %s - check these containers manually'
                    % (exc.message, ', '.join(failures)),
                )
            self._cleanup_tmp(log)
            raise
        except Exception as exc:
            failures = self._rollback_containers(prepared, log)
            if failures:
                raise PluginUpdateError(
                    'rollback_failed',
                    '%s; could not restore %s - check these containers manually'
                    % (exc, ', '.join(failures)),
                )
            self._cleanup_tmp(log)
            raise PluginUpdateError('update_failed', str(exc))

        # Everything is verified: only now are the predecessors removed, and
        # outside the try above, so a cleanup hiccup can never trigger a
        # rollback for which the old containers no longer exist.
        try:
            for item in prepared:
                self._finalize_container_update(item, log)
        except Exception:
            log('cleanup', 'WARNING: could not remove every old container/image')
        self._cleanup_tmp(log)
        return {
            'component': USERSPACE,
            'previous': before,
            'installed': self._userspace_version(),
            'state': 'updated',
            'rolled_back': False,
        }

    def _finalize_container_update(self, item, log):
        old_name = item.get('old_name')
        if not old_name:
            return
        self._run('docker rm -f %s' % old_name, log, 'cleanup')
        self._remove_old_image(item.get('image_id'), log)

    def _remove_old_image(self, image_id, log):
        if not image_id:
            return
        # Several containers can share the same previous image, so the removal
        # is attempted once per image and a failure is reported, not swallowed.
        _removed = getattr(self, '_removed_images', None)
        if _removed is None:
            _removed = self._removed_images = set()
        if image_id in _removed:
            return
        _removed.add(image_id)
        out, err, code = self._run('docker rmi %s' % image_id, log, 'cleanup')
        if code != 0:
            log('cleanup', 'note: old image %s is still used elsewhere' % image_id)

    def _cleanup_tmp(self, log):
        """Remove build/backup artefacts; keep them only after a failed rollback."""
        self._run('rm -rf /tmp/awg-plugin-update /tmp/awg-plugin-backup-*', log, 'cleanup')

    def _prepare_container_update(self, name, log):
        """Validate and back up one container before touching anything."""
        dockerfile_dir = self._dockerfile_dir(name)
        if not dockerfile_dir:
            raise PluginUpdateError(
                'unsupported',
                'container %s was not created by this panel; reinstall the protocol '
                'to update userspace' % name,
            )
        info = self._inspect_container(name)
        unsupported = self._validate_container_shape(name, info)
        if unsupported:
            raise PluginUpdateError(
                'unsupported',
                'container %s has an unsupported configuration (%s); reinstall the '
                'protocol to update userspace' % (name, ', '.join(unsupported)),
            )
        backup = '/tmp/awg-plugin-backup-%s' % name
        self._run('rm -rf %s' % backup, log, 'prepare')
        out, err, code = self._run(
            'docker cp %s:%s %s' % (name, CONTAINER_CONFIG_DIR, backup), log, 'backup',
        )
        if code != 0:
            raise PluginUpdateError('update_failed', 'cannot back up %s configuration' % name)
        peers_out, _, _ = self._run(
            "docker exec %s sh -c \"grep -c '^\\[Peer\\]' %s/*.conf 2>/dev/null\" "
            % (name, CONTAINER_CONFIG_SUBDIR),
            log, 'backup',
        )
        peers = sum(int(value) for value in re.findall(r'\d+', peers_out or '') if value.isdigit())
        return {
            'name': name,
            'dockerfile_dir': dockerfile_dir,
            'backup': backup,
            'peers': peers,
            'image_id': info.get('Image'),
            'host': info.get('HostConfig') or {},
            # The panel attaches the container to amnezia-dns-net after
            # `docker run`; a recreate must not silently drop that.
            'networks': [
                net for net in ((info.get('NetworkSettings') or {}).get('Networks') or {})
                if net not in DOCKER_NETWORK_SKIP
            ],
        }

    def _apply_container_update(self, item, version, log, should_cancel=None):
        name = item['name']
        stamp = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')
        old_name = '%s.old-%s' % (name, stamp)
        item['old_name'] = old_name
        item['switched'] = False

        # Rebuild the panel image from its own Dockerfile, exactly like the
        # protocol installer does.  A failed build leaves the old tag intact
        # and the running container untouched.
        out, err, code = self._run(
            'docker build --no-cache --pull -t %s %s' % (name, item['dockerfile_dir']),
            log, 'build', timeout=1800,
        )
        if code != 0:
            raise PluginUpdateError('update_failed', 'image build failed for %s' % name)

        out, _, _ = self._run(
            "docker inspect --format '{{index .Config.Labels "
            "\"org.opencontainers.image.version\"}}' %s" % name,
            log, 'verify',
        )
        found = _VERSION_RE.search(out or '')
        built_version = found.group(1) if found else None
        if not built_version:
            # Some upstream images ship without the OCI version label; ask the
            # binary itself instead of declaring the update impossible.
            log('verify', 'image has no version label, asking the binary')
            built_version = self._image_version(name)
        if built_version != version:
            raise PluginUpdateError(
                'unsupported',
                'the published image does not contain %s yet (found %s); nothing was restarted'
                % (version, built_version or 'unknown'),
            )

        # The service is still untouched at this point: a late cancellation
        # during a long image build must not restart anything.
        if should_cancel and should_cancel():
            raise PluginUpdateError('cancelled', 'update cancelled before %s was replaced' % name)

        host = item['host']
        run_cmd = self._docker_run_from_inspect(name, host)
        out, err, code = self._run('docker stop %s' % name, log, 'switch')
        if code != 0:
            raise PluginUpdateError('update_failed', 'cannot stop %s' % name)
        out, err, code = self._run('docker rename %s %s' % (name, old_name), log, 'switch')
        if code != 0:
            raise PluginUpdateError('update_failed', 'cannot move %s aside' % name)
        # Set before `docker run`: if the replacement fails to start, the
        # rollback must still be able to rename the old container back.
        item['switched'] = True
        out, err, code = self._run(run_cmd, log, 'switch')
        if code != 0:
            raise PluginUpdateError('update_failed', 'cannot start the new container for %s' % name)

        for network in item.get('networks') or ():
            log('switch', 'attaching %s to %s' % (name, network))
            out, err, code = self._run(
                'docker network connect %s %s' % (network, name), log, 'switch', timeout=60,
            )
            if code != 0:
                raise PluginUpdateError('update_failed', 'cannot attach %s to %s' % (name, network))

        out, err, code = self._run(
            'docker cp %s/. %s:%s/' % (item['backup'], name, CONTAINER_CONFIG_DIR),
            log, 'restore',
        )
        if code != 0:
            raise PluginUpdateError('update_failed', 'cannot restore the configuration of %s' % name)
        out, err, code = self._run('docker restart %s' % name, log, 'restore')
        if code != 0:
            raise PluginUpdateError('update_failed', 'cannot restart %s' % name)
        out, err, code = self._run(
            'docker exec %s sh -c "test -f %s/*.conf"' % (name, CONTAINER_CONFIG_SUBDIR),
            log, 'verify',
        )
        if code != 0:
            raise PluginUpdateError('update_failed', 'new container has no configuration')

        peers_out, _, _ = self._run(
            "docker exec %s sh -c \"grep -c '^\\[Peer\\]' %s/*.conf 2>/dev/null\" "
            % (name, CONTAINER_CONFIG_SUBDIR),
            log, 'verify',
        )
        peers = sum(int(value) for value in re.findall(r'\d+', peers_out or '') if value.isdigit())
        if peers < item['peers']:
            raise PluginUpdateError(
                'update_failed',
                'peer count dropped from %s to %s; rolling back' % (item['peers'], peers),
            )
        # A restored config file does not mean the tunnel is up: start.sh runs
        # at container start and can fail. The old container is still around,
        # so failing here still allows a rollback.
        tunnel = False
        for _attempt in range(3):
            out, err, code = self._run(
                'docker exec %s sh -c "awg show 2>/dev/null || wg show 2>/dev/null"' % name,
                log, 'verify', timeout=60,
            )
            if code == 0 and 'interface' in (out or ''):
                tunnel = True
                break
            time.sleep(2)
        if not tunnel:
            raise PluginUpdateError(
                'update_failed',
                'the tunnel did not come up after the update; rolling back',
            )
        log('done', '%s is running %s with %s peers' % (name, version, peers))

    @staticmethod
    def _docker_run_from_inspect(name, host):
        """Rebuild the panel's ``docker run`` command from container metadata."""
        bindings = host.get('PortBindings') or {}
        ports = []
        for component_port, hosts in bindings.items():
            # docker names the key "55424/udp"; without the protocol suffix
            # `docker run -p` defaults to TCP and the tunnel would be dead.
            if '/' in component_port:
                port, proto = component_port.split('/', 1)
            else:
                port, proto = component_port, 'tcp'
            for binding in hosts or []:
                host_port = (binding or {}).get('HostPort')
                if host_port:
                    ports.append('-p %s:%s/%s' % (host_port, port, proto))
        sysctls = [
            '--sysctl="%s=%s"' % (key, value)
            for key, value in sorted((host.get('Sysctls') or {}).items())
        ]
        binds = ['-v %s' % bind for bind in (host.get('Binds') or [])]
        caps = ['--cap-add=%s' % cap for cap in (host.get('CapAdd') or [])]
        parts = [
            'docker run -d',
            '--restart always',
        ]
        if host.get('Privileged'):
            parts.append('--privileged')
        parts.extend(caps)
        parts.extend(ports)
        parts.extend(binds)
        parts.extend(sysctls)
        parts.append('--name %s' % name)
        ulimits = host.get('Ulimits') or []
        for ulimit in ulimits:
            name_ = (ulimit or {}).get('Name')
            soft = (ulimit or {}).get('Soft')
            hard = (ulimit or {}).get('Hard')
            if name_ and soft and hard:
                parts.append('--ulimit %s=%s:%s' % (name_, soft, hard))
        parts.append(name)
        return ' \\\n'.join(parts)

    def _rollback_containers(self, prepared, log):
        """Restore every switched container; returns the ones that failed.

        The predecessor is checked *before* the replacement is removed, so a
        missing old container leaves the (working) new one in place instead of
        destroying both. Runs in reverse order and only touches containers
        that were actually replaced.
        """
        failures = []
        for item in reversed(prepared):
            name = item['name']
            old_name = item.get('old_name')
            if not item.get('switched') or not old_name:
                continue
            log('rollback', 'restoring %s' % name)
            out, _, _ = self._exec(
                'docker inspect %s >/dev/null 2>&1 && echo yes || true' % old_name,
                timeout=60,
            )
            if 'yes' not in (out or ''):
                log('rollback', 'ERROR: %s is gone; leaving %s running' % (old_name, name))
                failures.append(name)
                continue
            self._exec('docker rm -f %s' % name, timeout=120)
            out, err, code = self._exec(
                'docker rename %s %s' % (old_name, name), timeout=60,
            )
            if code != 0:
                log('rollback', 'ERROR: cannot rename %s back' % old_name)
                failures.append(name)
                continue
            out, err, code = self._exec('docker start %s' % name, timeout=120)
            if code != 0:
                log('rollback', 'ERROR: %s did not start' % name)
                failures.append(name)
        return failures
