from PGPScheme.security.configuration import *
from message.message import Message
from algorithms.triple_des import *

private_key_ring_collection.add_key_pair("mina", "minavu@gmail.com", "mina123", 2048)


mess = Message("porukica", "naslov")
mess.authentication("minavu@gmail.com|mina", "mina123")

session_key = key_generator.generate_session_key(get_message_block())
triple_des = TripleDes(session_key, "porukica")
triple_des.encrypt()
triple_des.decrypt()