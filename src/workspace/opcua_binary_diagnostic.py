from scapy.all import *

from scapy.layers.l2 import Ether

from scapy.contrib.opcua_binary import (
    OPC_UA_Binary_Hello,
    OPC_UA_Binary_Acknowledge,
    OPC_UA_Binary_OpenSecureChannel,
    OPC_UA_Binary_SecureConversationMessage,
)


from workspace.diagnostics.python_opcua import (
    pythonopc_client_hello,
    pythonopc_client_OpenSecureChannel,
    pythonopc_client_CreateSessionRequest,
    pythonopc_client_ActivateSessionRequest,
    pythonopc_client_ReadRequest,
    pythonopc_client_CloseSessionRequest,
    pythonopc_client_CloseSecureChannelRequest,
)


from workspace.diagnostics.python_opcua import (
    pythonopc_client_hello_ack,
    pythonopc_client_OpenSecureChannel_ack,
    pythonopc_client_CreateSessionRequest_ack,
    pythonopc_client_ActivateSessionRequest_ack,
    pythonopc_client_ReadRequest_ack,
    pythonopc_client_CloseSessionRequest_ack,
)


from workspace.diagnostics.nodejs_opcua import (
    nodejs_client_hello,
    nodejs_client_OpenSecureChannel,
    nodejs_client_CreateSessionRequest,
    nodejs_client_ActivateSessionRequest,
    nodejs_client_ReadRequest,
    nodejs_client_CloseSessionRequest,
    nodejs_client_CloseSecureChannelRequest,
)


from workspace.diagnostics.open62541 import (
    open62541_client_hello,
    open62541_client_OpenSecureChannel,
    open62541_client_CreateSessionRequest,
    open62541_client_ActivateSessionRequest,
    open62541_client_ReadRequest,
    open62541_client_CloseSessionRequest,
    open62541_client_CloseSecureChannelRequest,
)


from workspace.diagnostics.dotnetstd import (
    dotnetstd_client_hello,
    dotnetstd_client_OpenSecureChannel,
    dotnetstd_client_CreateSessionRequest,
    dotnetstd_client_ActivateSessionRequest,
    dotnetstd_client_ReadRequest,
    dotnetstd_client_CloseSessionRequest,
    dotnetstd_client_CloseSecureChannelRequest,
)


from workspace.diagnostics.open62541 import (
    open62541_client_CloseSecureChannelRequest_err,
)


def main():

    python_requests = {
        pythonopc_client_hello,
        pythonopc_client_OpenSecureChannel,
        pythonopc_client_CreateSessionRequest,
        pythonopc_client_ActivateSessionRequest,
        pythonopc_client_ReadRequest,
        pythonopc_client_CloseSessionRequest,
        pythonopc_client_CloseSecureChannelRequest,
    }

    # for request in python_requests:
    #     packet = Ether(request)
    #     packet.show()

    python_responses = {
        pythonopc_client_hello_ack,
        pythonopc_client_OpenSecureChannel_ack,
        pythonopc_client_CreateSessionRequest_ack,
        pythonopc_client_ActivateSessionRequest_ack,
        pythonopc_client_ReadRequest_ack,
        pythonopc_client_CloseSessionRequest_ack,
    }

    # for response in python_responses:
    #     packet = Ether(response)
    #     packet.show()

    # packet = Ether(pythonopc_client_hello_ack)
    # packet.show()

    nodejs_requests = {
        nodejs_client_hello,
        nodejs_client_OpenSecureChannel,
        nodejs_client_CreateSessionRequest,
        nodejs_client_ActivateSessionRequest,
        nodejs_client_ReadRequest,
        nodejs_client_CloseSessionRequest,
        nodejs_client_CloseSecureChannelRequest,
    }

    # for request in nodejs_requests:
    #     packet = Ether(request)
    #     packet.show()

    # packet = Ether(nodejs_client_CloseSessionRequest)
    # packet.show()

    open62541_requests = {
        open62541_client_hello,
        open62541_client_OpenSecureChannel,
        open62541_client_CreateSessionRequest,
        open62541_client_ActivateSessionRequest,
        open62541_client_ReadRequest,
        open62541_client_CloseSessionRequest,
        open62541_client_CloseSecureChannelRequest,
    }

    # for request in open62541_requests:
    #     packet = Ether(request)
    #     packet.show()

    # packet = Ether(open62541_client_ReadRequest)
    # packet.show()

    dotnetstd_requests = {
        dotnetstd_client_hello,
        dotnetstd_client_OpenSecureChannel,
        dotnetstd_client_CreateSessionRequest,
        dotnetstd_client_ActivateSessionRequest,
        dotnetstd_client_ReadRequest,
        dotnetstd_client_CloseSessionRequest,
        dotnetstd_client_CloseSecureChannelRequest,
    }

    for request in dotnetstd_requests:
        packet = Ether(request)
        packet.show()

    # packet = Ether(open62541_client_ReadRequest)
    # packet.show()


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
    packet = OPC_UA_Binary_Acknowledge(
        bytes.fromhex("00000000ffff0000ffff00000000400641060000")
    )
    packet.show()
