from PGPScheme.security.configuration import private_key_ring_collection


private_key_ring_collection.add_key_pair("mina", "minavu@gmail.com", "mina123", 2048)

from message.message import Message
mess = Message("porukica", "naslov")
mess.authentication("minavu@gmail.com|mina", "mina123")