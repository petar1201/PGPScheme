from PGPScheme.security.private_keys import PrivateKeyRingCollection
from PGPScheme.security.public_keys import PublicKeyRingCollection
from PGPScheme.security.session_key import *

private_key_ring_collection = PrivateKeyRingCollection()
public_key_ring_collection = PublicKeyRingCollection()


key_generator = CAST128SessionKeyGenerator()

