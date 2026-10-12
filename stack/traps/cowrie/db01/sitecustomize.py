"""Allow only the training deploy key; validate its signature, never allow arbitrary keys."""
from pathlib import Path
from twisted.conch.ssh.keys import Key
from twisted.conch import error
from twisted.cred.error import UnauthorizedLogin
from twisted.internet import defer
from cowrie.core.checkers import HoneypotPublicKeyChecker

original = HoneypotPublicKeyChecker.requestAvatarId

def training_key(self, credentials):
    allowed = Key.fromString(Path('/seeds/deploy_key.pub').read_bytes())
    if credentials.username != b'deploy' or credentials.blob != allowed.blob():
        return original(self, credentials)
    if not credentials.signature:
        return defer.fail(error.ValidPublicKey())
    if not allowed.verify(credentials.signature, credentials.sigData):
        return defer.fail(UnauthorizedLogin())
    events = getattr(credentials, 'events', None)
    if events:
        events.dispatch('cowrie.login.success', 'training deploy-key authentication succeeded',
                        username='deploy', key=allowed.toString('OPENSSH'), honeytoken_id='T4')
    return defer.succeed(credentials.username)

HoneypotPublicKeyChecker.requestAvatarId = training_key
