from scapy.all import *

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, TCP_client
from datetime import datetime, timezone

from scapy.contrib.opcua_binary import (
    BuiltIn_OPCUA_Binary_LocalizedText,
    BuiltIn_OPCUA_Binary_Variant,
    CommonParameter_DataValue,
    CommonParameter_RequestHeader,
    CommonParameter_ResponseHeader,
    Generic_NodeId,
    OPC_UA_Binary,
    OPC_UA_Binary_Hello,
    OPC_UA_Binary_Acknowledge,
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


def main():
    conf.use_pcap = True
    s = socket.socket()
    s.connect(("172.17.0.2", 4840))
    ss = StreamSocket(s, Raw)

    endpoint = "opc.tcp://172.17.0.2:4840/"
    hello = OPC_UA_Binary() / OPC_UA_Binary_Hello()
    hello[OPC_UA_Binary_Hello].EndpointUri = endpoint
    hello[OPC_UA_Binary_Hello].EndpointUriSize = len(endpoint)
    hello[OPC_UA_Binary].MessageSize = len(hello)
    ans = ss.sr1(Raw(hello))
    # OPC_UA_Binary(ans.load).show()

    chOpn = (
        OPC_UA_Binary()
        / OPC_UA_Binary_OpenSecureChannel()
        / OPC_UA_Binary_EncodableMessageObject()
        / OPC_UA_Binary_Message_OpenSecureChannelRequest()
    )

    chOpn[CommonParameter_RequestHeader].NodeIdentifier_Numeric_4B = 446

    policy = "http://opcfoundation.org/UA/SecurityPolicy#None"
    chOpn[OPC_UA_Binary_OpenSecureChannel].SecurityPolicyUri = policy
    chOpn[OPC_UA_Binary_OpenSecureChannel].SecurityPolicyUri_Size = len(policy)
    chOpn[OPC_UA_Binary_OpenSecureChannel].SequenceNumber = 1
    chOpn[OPC_UA_Binary_OpenSecureChannel].RequestId = 1
    chOpn[OPC_UA_Binary].MessageSize = len(chOpn)
    # chOpn.show2()

    ans = ss.sr1(Raw(chOpn))
    # OPC_UA_Binary(ans.load).show()

    dissect = OPC_UA_Binary(ans.load)
    channelId = dissect[OPC_UA_Binary_Message_OpenSecureChannelResponse].SecureChannelId
    tokenId = dissect[OPC_UA_Binary_Message_OpenSecureChannelResponse].TokenId
    ts = dissect[OPC_UA_Binary_Message_OpenSecureChannelResponse].Timestamp

    getEndpointsRequest = OPC_UA_Binary_Message_GetEndpointsRequest
    getEndpoints = (
        OPC_UA_Binary()
        / OPC_UA_Binary_SecureConversationMessage()
        / OPC_UA_Binary_EncodableMessageObject()
        / getEndpointsRequest()
    )

    getEndpoints[CommonParameter_RequestHeader].NodeIdentifier_Numeric_4B = 428

    enpoint = "opc.tcp://0.0.0.0:4840"
    getEndpoints[getEndpointsRequest].EndpointUrl = enpoint
    getEndpoints[getEndpointsRequest].EndpointUrl_Size = len(enpoint)
    getEndpoints[CommonParameter_RequestHeader].RequestHandle = 2
    getEndpoints[CommonParameter_RequestHeader].Timestamp = ts + 100
    getEndpoints[OPC_UA_Binary_SecureConversationMessage].SequenceNumber = 2
    getEndpoints[OPC_UA_Binary_SecureConversationMessage].RequestId = 2
    getEndpoints[OPC_UA_Binary_SecureConversationMessage].SecureChannelId = channelId
    getEndpoints[OPC_UA_Binary_SecureConversationMessage].SecurityTokenId = tokenId
    getEndpoints[OPC_UA_Binary_SecureConversationMessage].TokenId = tokenId
    getEndpoints[OPC_UA_Binary].MessageSize = len(getEndpoints)
    # getEndpoints.show2()

    ans = ss.sr1(Raw(getEndpoints))
    OPC_UA_Binary(ans.load).show()


if __name__ == "__main__":
    main()
