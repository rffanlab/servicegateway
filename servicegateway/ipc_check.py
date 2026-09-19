"""Unprivileged smoke check run AFTER the new Agent starts, inside the API sandbox."""
import os
from .config import Settings
from .ipc import AgentClient


def main():
    if os.geteuid() == 0:
        raise SystemExit('IPC verification must run as the service user')
    agent = AgentClient(Settings().agent_socket)
    try:
        result = agent.call('status')
        if not result.get('running'):
            raise RuntimeError('Edge not running')
        sample = agent.call('traffic')
        if not isinstance(sample.get('sample'), list):
            raise RuntimeError('Invalid traffic response')
    except Exception as exc:
        raise SystemExit('Unprivileged Agent/traffic check failed: ' + type(exc).__name__) from None
    print('Non-root Agent status and traffic access verified')


if __name__ == '__main__':
    main()
