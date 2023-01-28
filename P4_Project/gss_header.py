from scapy.all import *

TYPE_GSS = 0x1212

class gss(Packet):
    name = "gss"
    fields_desc = [
        ThreeBytesField("geoname_id",0)
    ]
    def mysummary(self):
        return self.sprintf("geoname_id=%geoname_id%")


bind_layers(Ether, gss, type=TYPE_GSS)
bind_layers(gss, IP)
