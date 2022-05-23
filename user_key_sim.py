# code taken from python-keyutils.
from time import sleep
import keyutils

name = b'some_key_name'
value = b'some random secret key'

# Add and request key.
ring = keyutils.KEY_SPEC_SESSION_KEYRING
key_id = keyutils.add_key(name, value, ring)
assert keyutils.request_key(name, ring) == key_id

# Read key.
assert value == keyutils.read_key(key_id)

# Set timeout to 5 seconds, wait and then... it's gone.
keyutils.set_timeout(key_id, 5)
sleep(6)
assert keyutils.request_key(name, ring) is None
