from scapy.all import *

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, TCP_client
from datetime import datetime, timezone

from scapy.contrib.opcua_binary import (
    BuiltIn_OPCUA_Binary_LocalizedText,
    BuiltIn_OPCUA_Binary_Variant,
    CommonParameter_DataValue,
    CommonParameter_DiagnosticInfo,
    CommonParameter_EndpointDescription,
    CommonParameter_RequestHeader,
    CommonParameter_ResponseHeader,
    CommonParameter_UserIdentityToken,
    Generic_NodeId,
    OPC_UA_Binary,
    OPC_UA_Binary_Hello,
    OPC_UA_Binary_Acknowledge,
    OPC_UA_Binary_Message_ActivateSessionRequest,
    OPC_UA_Binary_Message_OpenSecureChannelRequest,
    OPC_UA_Binary_Message_OpenSecureChannelResponse,
    OPC_UA_Binary_OpenSecureChannel,
    OPC_UA_Binary_SecureConversationMessage,
    OPC_UA_Binary_EncodableMessageObject,
    OPC_UA_Binary_Message_EncodedNodeId_4B,
    OPC_UA_Binary_Message_GetEndpointsRequest,
    OPC_UA_Binary_Message_GetEndpointsResponse,
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


from workspace.diagnostics.nodejs_opcua import (
    nodejs_client_hello_ack,
    nodejs_client_OpenSecureChannel_ack,
    nodejs_client_CreateSessionRequest_ack,
    nodejs_client_ActivateSessionRequest_ack,
    nodejs_client_ReadRequest_ack,
    nodejs_client_CloseSessionRequest_ack,
    nodejs_client_CloseSecureChannelRequest_ack,
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


from workspace.diagnostics.open62541 import (
    open62541_client_hello_ack,
    open62541_client_OpenSecureChannel_ack,
    open62541_client_CreateSessionRequest_ack,
    open62541_client_ActivateSessionRequest_ack,
    open62541_client_ReadRequest_ack,
    open62541_client_CloseSessionRequest_ack,
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

from workspace.diagnostics.dotnetstd import (
    dotnetstd_client_hello_ack,
    dotnetstd_client_OpenSecureChannel_ack,
    dotnetstd_client_CreateSessionRequest_ack,
    dotnetstd_client_ActivateSessionRequest_ack,
    dotnetstd_client_ReadRequest_ack,
    dotnetstd_client_CloseSessionRequest_ack,
)


from workspace.diagnostics.open62541 import (
    open62541_client_CloseSecureChannelRequest_err,
)


def initial_requests():

    print("####################################################################")
    print("python")
    print("####################################################################")

    python_requests = {
        pythonopc_client_hello,
        pythonopc_client_OpenSecureChannel,
        pythonopc_client_CreateSessionRequest,
        pythonopc_client_ActivateSessionRequest,
        pythonopc_client_ReadRequest,
        pythonopc_client_CloseSessionRequest,
        pythonopc_client_CloseSecureChannelRequest,
    }

    for request in python_requests:
        packet = Ether(request)
        packet.show()

    print("####################################################################")
    print("nodejs")
    print("####################################################################")

    nodejs_requests = {
        nodejs_client_hello,
        nodejs_client_OpenSecureChannel,
        nodejs_client_CreateSessionRequest,
        nodejs_client_ActivateSessionRequest,
        nodejs_client_ReadRequest,
        nodejs_client_CloseSessionRequest,
        nodejs_client_CloseSecureChannelRequest,
    }

    for request in nodejs_requests:
        packet = Ether(request)
        packet.show()

    # packet = Ether(nodejs_client_CloseSessionRequest)
    # packet.show()

    print("####################################################################")
    print("open62541")
    print("####################################################################")

    open62541_requests = {
        open62541_client_hello,
        open62541_client_OpenSecureChannel,
        open62541_client_CreateSessionRequest,
        open62541_client_ActivateSessionRequest,
        open62541_client_ReadRequest,
        open62541_client_CloseSessionRequest,
        open62541_client_CloseSecureChannelRequest,
    }

    for request in open62541_requests:
        packet = Ether(request)
        packet.show()

    # packet = Ether(open62541_client_ReadRequest)
    # packet.show()

    print("####################################################################")
    print("dotnetstd")
    print("####################################################################")

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


def initial_responses():

    print("####################################################################")
    print("python")
    print("####################################################################")

    python_responses = {
        pythonopc_client_hello_ack,
        pythonopc_client_OpenSecureChannel_ack,
        pythonopc_client_CreateSessionRequest_ack,
        pythonopc_client_ActivateSessionRequest_ack,
        pythonopc_client_ReadRequest_ack,
        pythonopc_client_CloseSessionRequest_ack,
    }

    for response in python_responses:
        packet = Ether(response)
        packet.show()

    print("####################################################################")
    print("nodejs")
    print("####################################################################")

    nodejs_responses = {
        nodejs_client_hello_ack,
        nodejs_client_OpenSecureChannel_ack,
        nodejs_client_CreateSessionRequest_ack,
        nodejs_client_ActivateSessionRequest_ack,
        nodejs_client_ReadRequest_ack,
        nodejs_client_CloseSessionRequest_ack,
        nodejs_client_CloseSecureChannelRequest_ack,
    }

    for response in nodejs_responses:
        packet = Ether(response)
        packet.show()

    print("####################################################################")
    print("open62541")
    print("####################################################################")

    open62541_responses = {
        open62541_client_hello_ack,
        open62541_client_OpenSecureChannel_ack,
        open62541_client_CreateSessionRequest_ack,
        open62541_client_ActivateSessionRequest_ack,
        open62541_client_ReadRequest_ack,
        open62541_client_CloseSessionRequest_ack,
    }

    for response in open62541_responses:
        packet = Ether(response)
        packet.show()

    print("####################################################################")
    print("dotnetstd")
    print("####################################################################")

    dotnetstd_responses = {
        dotnetstd_client_hello_ack,
        dotnetstd_client_OpenSecureChannel_ack,
        dotnetstd_client_CreateSessionRequest_ack,
        dotnetstd_client_ActivateSessionRequest_ack,
        dotnetstd_client_ReadRequest_ack,
        dotnetstd_client_CloseSessionRequest_ack,
    }

    for response in dotnetstd_responses:
        packet = Ether(response)
        packet.show()


def main():
    initial_requests()
    initial_responses()

    # the decoding of our generic node is broken for some reason
    # test = Generic_NodeId(
    #     bytes.fromhex(
    #         "00003a7c2235e965d8010300000000000000ffffffff102700000000001c0000007"
    #         "5726e3a756e636f6e666967757265643a6170706c69636174696f6effffffff0001"
    #         "000000ffffffffffffffffffffffffffffffff180000006f70632e7463703a2f2f6"
    #         "c6f63616c686f73743a34383430ffffffffffffffffffffffff0000000000f91541"
    #         "ffffff7f"
    #     )
    # )
    # test.show()

    # test2 = CommonParameter_ResponseHeader(
    #     bytes.fromhex(
    #         "59251b4d8316dc0142420f00000000000000000000000000"
    #     )
    # )
    # test2.show()

    # test2 = CommonParameter_EndpointDescription(bytes.fromhex("240000006f70632e7463703a2f2f31302e31302e362e3132363a343834302f4b5249544953334d2f2000000075726e3a6f70656e36323534312e7365727665722e6170706c69636174696f6e2500000075726e3a667265656f706375612e6769746875622e696f3a707974686f6e3a73657276657202160000004b5249544953334d2053616d706c652053657276657202000000ffffffffffffffff01000000240000006f70632e7463703a2f2f31302e31302e362e3132363a343834302f4b5249544953334d2fffffffff010000002f000000687474703a2f2f6f7063666f756e646174696f6e2e6f72672f55412f5365637572697479506f6c696379234e6f6e650300000009000000616e6f6e796d6f757300000000ffffffffffffffff2f000000687474703a2f2f6f7063666f756e646174696f6e2e6f72672f55412f5365637572697479506f6c696379234e6f6e650b000000636572746966696361746502000000ffffffffffffffff39000000687474703a2f2f6f7063666f756e646174696f6e2e6f72672f55412f5365637572697479506f6c69637923426173696332353653686132353608000000757365726e616d6501000000ffffffffffffffff2f000000687474703a2f2f6f7063666f756e646174696f6e2e6f72672f55412f5365637572697479506f6c696379234e6f6e6541000000687474703a2f2f6f7063666f756e646174696f6e2e6f72672f55412d50726f66696c652f5472616e73706f72742f75617463702d756173632d756162696e61727900"))
    # test2.show()

    # packet = Ether(pythonopc_client_CreateSessionRequest_ack)
    # packet.show()

    # header = CommonParameter_RequestHeader(Timestamp=0x2451EDBEF09D901)
    # header.show2()

    # activateSession = (
    #     OPC_UA_Binary()
    #     / OPC_UA_Binary_SecureConversationMessage()
    #     / OPC_UA_Binary_EncodableMessageObject()
    #     / OPC_UA_Binary_Message_EncodedNodeId_4B(NodeId_Identifier_Numeric_4B=467)
    #     / OPC_UA_Binary_Message_ActivateSessionRequest()
    # )
    # activateSession.show2()


if __name__ == "__main__":
    main()
