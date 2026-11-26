"""A remote side for XrayManager tests: docker keeps a real state.

`remote_answers(text)` is a run_sudo_command stand-in that answers `text`
to everything except the commands the checked config apply issues. The
container reports itself stopped after `docker stop` and running again
after `docker start`, and it mounts its config directory. A stand-in that
answered every command with the same text passed only while an unreadable
container state still counted as a healthy one."""


def remote_answers(text, mounts=('/opt/amnezia/xray',)):
    state = {'stopped': False}

    def run(command, **kwargs):
        if command.startswith('docker stop '):
            state['stopped'] = True
            return ('', '', 0)
        if command.startswith('docker start '):
            state['stopped'] = False
            return ('', '', 0)
        if command.startswith("docker inspect -f '{{.State.Status}}"):
            return (('exited' if state['stopped'] else 'running') + ' 0\n', '', 0)
        if command.startswith("docker inspect -f '{{range .Mounts}}"):
            return ('\n'.join(mounts) + '\n', '', 0)
        return (text, '', 0)

    return run
