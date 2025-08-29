from scapy.all import *

from scapy.layers.l2 import Ether

from scapy.contrib.opcua_binary import (
    OPC_UA_Binary_Hello,
    OPC_UA_Binary_Ack,
    OPC_UA_Binary_OpenSecureChannel,
    OPC_UA_Binary_SecureConversationMessage,
)

# from scapy.layers.inet import IP

from workspace.diagnostics.python_opcua import (
    pythonopc_client_hello,
    pythonopc_client_hello_ack,
    pythonopc_client_OpenSecureChannel,
    pythonopc_client_ActivateSessionRequest,
)

from workspace.diagnostics.open62541 import (
    open62541_client_CloseSecureChannelRequest_err,
)


def main():

    packet = Ether(pythonopc_client_hello)
    packet.show()

    packet = Ether(pythonopc_client_hello_ack)
    packet.show()

    packet = Ether(pythonopc_client_OpenSecureChannel)
    packet.show()

    packet = Ether(pythonopc_client_ActivateSessionRequest)
    packet.show()

    packet = Ether(open62541_client_CloseSecureChannelRequest_err)
    packet.show()


if __name__ == "__main__":
    main()


def decodeSomeOpcBins():

    # somepacket = OPC_UA_Binary_Hello()
    # somepacket.show()

    somepacket = OPC_UA_Binary_OpenSecureChannel()
    somepacket.show()

    # somepacket = OPC_UA_Binary_SecureConversationMessage()
    # somepacket.show()

    # test the binary ack part without MSGT, CT and MSZ:
    packet = OPC_UA_Binary_Ack(
        bytes.fromhex("00000000ffff0000ffff00000000400641060000")
    )
    packet.show()
