from scapy.all import *

from scapy.layers.l2 import Ether

from scapy.contrib.opcua_binary import *

from workspace.randRead.randRead import (
    CreateSession,
    ActivateSession,
    ReadRequest,
    BrowseRequest,
)


def main():

    packet = Ether(CreateSession)
    packet.show()

    packet = Ether(ActivateSession)
    packet.show()

    packet = Ether(ReadRequest)
    packet.show()

    packet = Ether(BrowseRequest)
    packet.show()


if __name__ == "__main__":
    main()
