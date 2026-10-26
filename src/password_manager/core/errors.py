
#errors.py
# Base exception for all errors in the manager's core.
class CoreFailure(Exception):
    ...

#It is launched when decryption fails (incorrect key or altered data)
class DecryptionError(CoreFailure):
    ...