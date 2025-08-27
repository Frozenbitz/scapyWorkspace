from scapy.all import *

from scapy.contrib.opc_binary import OPC_UA_Binary
from scapy.layers.inet import IP


def main():

    somepacket = OPC_UA_Binary()
    somepacket.show()

    ippacket = IP()/TCP()
    ippacket.show()
    pass


if __name__ == "__main__":
    main()
