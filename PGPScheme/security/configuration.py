from PGPScheme.security.keys import PrivateKeyRingCollection
from PGPScheme.security.session_key import *

private_key_ring_collection = PrivateKeyRingCollection()

initial_key = generate_initial_key()
key_generator = CAST128SessionKeyGenerator(initial_key)

