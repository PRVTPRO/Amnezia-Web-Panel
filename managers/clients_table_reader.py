"""A failed SSH/Docker command is not proof of a missing metadata file."""
import posixpath
import shlex


def clients_table_missing(ssh, container, path):
    parent = shlex.quote(posixpath.dirname(path))
    target = shlex.quote(path)
    probe = (f"test -d {parent} && test -r {parent} && test -x {parent} "
             f"&& test ! -e {target} && test ! -L {target} && printf missing")
    out, _, code = ssh.run_sudo_command(
        f"docker exec -i {shlex.quote(container)} sh -c {shlex.quote(probe)}")
    return code == 0 and out == 'missing'
