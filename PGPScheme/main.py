from PGPScheme.security.configuration import *
from message.message import *
from algorithms.triple_des import *


#private_key_ring_collection.add_key_pair("mina", "minavu1@gmail.com", "mina123", 2048)
#public_key_ring_collection.add_key_pair("minavu1@gmail.com|mina", private_key_ring_collection.get_key_pair_by_user_id("minavu1@gmail.com|mina").get_public_key())


#header = Header(1, 1, 1, 1, "3des")
#authData = AuthenticationData("mina123", "minavu1@gmail.com|mina")
#secData = SecurityData("minavu1@gmail.com|mina")
#mess = Message()
#mess.send("porukica", "poruka", header, authData, secData)

#mess1 = Message()
#mess1.receive("poruka")
#mess1.read("mina123")

# private_key_ring_collection.export_key_ring_to_pem("PGPScheme/resources/private/private_keys.pem")