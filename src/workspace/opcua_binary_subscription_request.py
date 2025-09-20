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
    OPC_UA_Binary_Message_CreateSubscriptionResponse,
    OPC_UA_Binary_Message_OpenSecureChannelRequest,
    OPC_UA_Binary_Message_OpenSecureChannelResponse,
    OPC_UA_Binary_OpenSecureChannel,
    OPC_UA_Binary_SecureConversationMessage,
    OPC_UA_Binary_EncodableMessageObject,
    CustomParameter_LocaleId,
)


################################################################################
#### @ send hello message
################################################################################


def send_OPC_HEL(
    ip: str,
    port: int,
    endpoint: str,
    show_payload: bool = False,
) -> SuperSocket:
    """
    Craft a new OPC Hello frame to start a conversation with a server.
    Returns the created socket for the chosen endpoint

    """

    # Can be used to craft multiple sessions?

    # use the scapy builtin supersockets for setting up the sockets
    conf.use_pcap = True
    s = socket.socket()
    s.connect((ip, port))
    ss = StreamSocket(s, Raw)

    # craft a hello package to open a new endpoint
    hello = OPC_UA_Binary() / OPC_UA_Binary_Hello()
    hello[OPC_UA_Binary_Hello].EndpointUri = endpoint
    hello[OPC_UA_Binary_Hello].EndpointUriSize = len(endpoint)
    hello[OPC_UA_Binary].MessageSize = len(hello)

    if show_payload:
        hello.show2()

    # emit payload
    ans = ss.sr1(Raw(hello))

    # show the crafted package
    if show_payload:
        OPC_UA_Binary(ans.load).show()

    return ss


################################################################################
#### @ open secure channel
################################################################################


def send_OPC_OpenSecureChannel(
    socket: SuperSocket,
    sequenceId: int,
    requestId: int,
    show_payload: bool = False,
) -> OPC_UA_Binary:
    """
    initiate a new connection

    """

    chanOpen = (
        OPC_UA_Binary()
        / OPC_UA_Binary_OpenSecureChannel()
        / OPC_UA_Binary_EncodableMessageObject()
        / OPC_UA_Binary_Message_OpenSecureChannelRequest()
    )

    chanOpen[CommonParameter_RequestHeader].NodeIdentifier_Numeric_4B = 446

    # we can only use policy none for the public stuff here
    policy = "http://opcfoundation.org/UA/SecurityPolicy#None"
    chanOpen[OPC_UA_Binary_OpenSecureChannel].SecurityPolicyUri = policy
    chanOpen[OPC_UA_Binary_OpenSecureChannel].SecurityPolicyUri_Size = len(policy)
    chanOpen[OPC_UA_Binary_OpenSecureChannel].SequenceNumber = sequenceId
    chanOpen[OPC_UA_Binary_OpenSecureChannel].RequestId = requestId
    chanOpen[OPC_UA_Binary].MessageSize = len(chanOpen)

    if show_payload:
        chanOpen.show2()

    # emit data
    ans = socket.sr1(Raw(chanOpen))

    if show_payload:
        OPC_UA_Binary(ans.load).show()

    return ans


################################################################################
#### @ create session
################################################################################


def OPC_create_session(
    socket: SuperSocket,
    sequence_id: int,
    request_id: int,  # main OPC BIN header
    request_handle_Id: int,  # requestHeader id, can be different
    channel_id: int,
    token_id: int,
    target_endpoint: str,
    session_name: str,
    application_uri: str,
    product_uri: str,
    client_nonce: bytes,
    session_timeout: int,
    timestamp_start: int,
    show_payload: bool = False,
) -> OPC_UA_Binary:
    """
    request a new session handle from the server

    """

    # craft the main packet
    createSession = (
        OPC_UA_Binary()
        / OPC_UA_Binary_SecureConversationMessage()
        / OPC_UA_Binary_EncodableMessageObject()
        / OPC_UA_Binary_Message_CreateSessionRequest()
    )

    createSession[CommonParameter_RequestHeader].NodeIdentifier_Numeric_4B = 461

    # setup the main header (not length)
    createSession[OPC_UA_Binary_SecureConversationMessage].SequenceNumber = sequence_id
    createSession[OPC_UA_Binary_SecureConversationMessage].RequestId = request_id
    createSession[OPC_UA_Binary_SecureConversationMessage].SecureChannelId = channel_id
    createSession[OPC_UA_Binary_SecureConversationMessage].SecurityTokenId = token_id
    createSession[OPC_UA_Binary_SecureConversationMessage].TokenId = token_id

    request_header = CommonParameter_RequestHeader
    createSession[request_header].RequestHandle = request_handle_Id
    createSession[request_header].Timestamp = timestamp_start
    createSession[request_header].TimeoutHint = 4000

    sessionRequest = OPC_UA_Binary_Message_CreateSessionRequest
    createSession[sessionRequest].ApplicationUri = application_uri
    createSession[sessionRequest].ApplicationUri_Size = len(application_uri)
    createSession[sessionRequest].ProcuctUri = product_uri
    createSession[sessionRequest].ProcuctUri_Size = len(product_uri)
    createSession[sessionRequest].ApplicationType = "Client"
    createSession[sessionRequest].EndpointUrl = target_endpoint
    createSession[sessionRequest].EndpointUrl_Size = len(target_endpoint)
    createSession[sessionRequest].SessionName = session_name
    createSession[sessionRequest].SessionName_Size = len(session_name)

    # we need to set this up with a semi rand value, since NodeJS checks the nonce
    createSession[sessionRequest].ClientNonce = client_nonce
    createSession[sessionRequest].ClientNonce_Size = len(client_nonce)

    # we need to set the timeout, otherwise the server will timeout within 0.1s
    createSession[sessionRequest].RequestedSessionTimeout = session_timeout

    createSession[OPC_UA_Binary].MessageSize = len(createSession)

    if show_payload:
        createSession.show2()

    ans = socket.sr1(Raw(createSession))

    if show_payload:
        OPC_UA_Binary(ans.load).show()

    return ans


################################################################################
#### @ activate session
################################################################################


def OPC_activate_session(
    socket,
    sequence_id,
    request_id,
    request_handle_id,
    channel_id,
    token_id,
    timestamp_start,
    auth_token,
    show_payload: bool = False,
) -> OPC_UA_Binary:
    """
    pass the auth token from the initial session request to start a new user session

    """

    # craft the main message
    activateSession = (
        OPC_UA_Binary()
        / OPC_UA_Binary_SecureConversationMessage()
        / OPC_UA_Binary_EncodableMessageObject()
        / OPC_UA_Binary_Message_ActivateSessionRequest()
    )

    activateSession[CommonParameter_RequestHeader].NodeIdentifier_Numeric_4B = 467

    activateSession[OPC_UA_Binary_SecureConversationMessage].SequenceNumber = (
        sequence_id
    )
    activateSession[OPC_UA_Binary_SecureConversationMessage].RequestId = request_id
    activateSession[OPC_UA_Binary_SecureConversationMessage].SecureChannelId = (
        channel_id
    )
    activateSession[OPC_UA_Binary_SecureConversationMessage].SecurityTokenId = token_id
    activateSession[OPC_UA_Binary_SecureConversationMessage].TokenId = token_id

    requestHeader = CommonParameter_RequestHeader
    activateSession[requestHeader].RequestHandle = request_handle_id
    activateSession[requestHeader].Timestamp = timestamp_start
    activateSession[requestHeader].TimeoutHint = 4000

    # important: set the secret session id
    # node uses the string IDs:
    # Response_SessionId_NodeID_Mask= 0x4
    # Response_SessionId_NamespaceIndex_Default= 1
    # = 3d6cc2652777976d615dc0b892e27094

    activateSession[Generic_NodeId].NodeID_Mask = 0x5
    activateSession[Generic_NodeId].NodespaceIndex_Short = 0
    activateSession[Generic_NodeId].NodeIdentifier_String_Size = len(auth_token)
    activateSession[Generic_NodeId].NodeIdentifier_String = auth_token

    SessionRequest = OPC_UA_Binary_Message_ActivateSessionRequest

    # Client locale support
    # LocaleIds_ArraySize, default en
    activateSession[SessionRequest].LocaleIds_ArraySize = 1
    activateSession[SessionRequest].LocaleIds_Array = CustomParameter_LocaleId()

    # Client Signature support
    client_signature_algo = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
    # AnonymousIdentityToken_Encoding_DefaultBinary,321,Object
    activateSession[SessionRequest].ClientSignature.AlgorithmUri = client_signature_algo
    activateSession[SessionRequest].ClientSignature.AlgorithmUri_Size = len(
        client_signature_algo
    )

    # Construct UserIdentityToken = Anonymous
    policy = "anonymous"
    activateSession[SessionRequest].UserIdentityToken.Encoding = "ByteString"
    activateSession[SessionRequest].UserIdentityToken.Identifier_Numeric_4B = 321
    activateSession[SessionRequest].UserIdentityToken.EncodedData_Body_Size = (
        len(policy) + 4
    )
    activateSession[SessionRequest].UserIdentityToken.EncodedBody = policy
    activateSession[SessionRequest].UserIdentityToken.EncodedBody_Size = len(policy)

    activateSession[OPC_UA_Binary].MessageSize = len(activateSession)

    if show_payload:
        activateSession.show2()

    ans = socket.sr1(Raw(activateSession))

    if show_payload:
        OPC_UA_Binary(ans.load).show()

    return ans


################################################################################
#### @ browse
################################################################################


def OPC_browse_request(
    socket,
    sequence_id,
    request_id,
    request_handle_id,
    channel_id,
    token_id,
    timestamp_start,
    auth_token,
    show_payload: bool = False,
) -> OPC_UA_Binary:
    """
    fetch the main server object

    """

    # craft the main message
    browseRequest = (
        OPC_UA_Binary()
        / OPC_UA_Binary_SecureConversationMessage()
        / OPC_UA_Binary_EncodableMessageObject()
        / OPC_UA_Binary_Message_BrowseRequest()
    )

    browseRequest[CommonParameter_RequestHeader].NodeIdentifier_Numeric_4B = 527

    requestHeader = CommonParameter_RequestHeader
    browseRequest[requestHeader].RequestHandle = request_handle_id
    browseRequest[requestHeader].Timestamp = timestamp_start
    browseRequest[requestHeader].TimeoutHint = 4000

    secureMessage = OPC_UA_Binary_SecureConversationMessage
    browseRequest[secureMessage].SequenceNumber = sequence_id
    browseRequest[secureMessage].RequestId = request_id
    browseRequest[secureMessage].SecureChannelId = channel_id
    browseRequest[secureMessage].SecurityTokenId = token_id
    browseRequest[secureMessage].TokenId = token_id

    # Auth Header
    browseRequest[Generic_NodeId].NodeID_Mask = 0x5
    browseRequest[Generic_NodeId].NodespaceIndex_Short = 0
    browseRequest[Generic_NodeId].NodeIdentifier_String_Size = len(auth_token)
    browseRequest[Generic_NodeId].NodeIdentifier_String = auth_token

    # BrowseDescription
    serverObject = CustomParameter_BrowseDescription()
    serverObject[Generic_NodeId].NodeID_Mask = 1
    serverObject[Generic_NodeId].NodeIdentifier_Numeric_4B = 2253  # main server object

    BrowseRequest = OPC_UA_Binary_Message_BrowseRequest
    browseRequest[BrowseRequest].NodesToBrowse_ArraySize = 1
    browseRequest[BrowseRequest].NodesToBrowse = serverObject
    browseRequest[BrowseRequest].NodesToBrowse[0].Reference_TypeId.NodeID_Mask = 0
    browseRequest[BrowseRequest].NodesToBrowse[
        0
    ].Reference_TypeId.NodeIdentifier_Numeric_2B = 33
    browseRequest[BrowseRequest].NodesToBrowse[0].browseDirection = "Forward"
    browseRequest[BrowseRequest].NodesToBrowse[0].NodeClassMask = "Variable"

    # update packet len
    browseRequest[OPC_UA_Binary].MessageSize = len(browseRequest)

    if show_payload:
        browseRequest.show2()

    ans = socket.sr1(Raw(browseRequest))

    if show_payload:
        OPC_UA_Binary(ans.load).show()

    return ans


################################################################################
#### @ create subscription
################################################################################


def OPC_subscription_request(
    socket,
    sequence_id,
    request_id,
    request_handle_id,
    channel_id,
    token_id,
    timestamp_start,
    auth_token,
    show_payload: bool = False,
) -> OPC_UA_Binary:
    """
    fetch the main server object

    """

    # craft the main message
    subscriptionRequest = (
        OPC_UA_Binary()
        / OPC_UA_Binary_SecureConversationMessage()
        / OPC_UA_Binary_EncodableMessageObject()
        / OPC_UA_Binary_Message_CreateSubscriptionRequest()
    )

    subscriptionRequest[CommonParameter_RequestHeader].NodeIdentifier_Numeric_4B = 787

    requestHeader = CommonParameter_RequestHeader
    subscriptionRequest[requestHeader].RequestHandle = request_handle_id
    subscriptionRequest[requestHeader].Timestamp = timestamp_start
    subscriptionRequest[requestHeader].TimeoutHint = 4000

    secureMessage = OPC_UA_Binary_SecureConversationMessage
    subscriptionRequest[secureMessage].SequenceNumber = sequence_id
    subscriptionRequest[secureMessage].RequestId = request_id
    subscriptionRequest[secureMessage].SecureChannelId = channel_id
    subscriptionRequest[secureMessage].SecurityTokenId = token_id
    subscriptionRequest[secureMessage].TokenId = token_id

    # Auth Header
    subscriptionRequest[Generic_NodeId].NodeID_Mask = 0x5
    subscriptionRequest[Generic_NodeId].NodespaceIndex_Short = 0
    subscriptionRequest[Generic_NodeId].NodeIdentifier_String_Size = len(auth_token)
    subscriptionRequest[Generic_NodeId].NodeIdentifier_String = auth_token

    # BrowseDescription
    serverObject = CustomParameter_BrowseDescription()
    serverObject[Generic_NodeId].NodeID_Mask = 1
    serverObject[Generic_NodeId].NodeIdentifier_Numeric_4B = 2253  # main server object

    SubscriptionRequest = OPC_UA_Binary_Message_CreateSubscriptionRequest
    subscriptionRequest[SubscriptionRequest].RequestedPublishingInterval = (
        0x0000000000408F40  # 1000
    )
    subscriptionRequest[SubscriptionRequest].RequestedLifetimeCount = 1000
    subscriptionRequest[SubscriptionRequest].RequestedMaxKeepAliveCount = 10
    subscriptionRequest[SubscriptionRequest].MaxNotificationsPerPublish = 0
    subscriptionRequest[SubscriptionRequest].PublishingEnabled = 0x1
    subscriptionRequest[SubscriptionRequest].Priority = 0xFF

    # update packet len
    subscriptionRequest[OPC_UA_Binary].MessageSize = len(subscriptionRequest)

    if show_payload:
        subscriptionRequest.show2()

    ans = socket.sr1(Raw(subscriptionRequest))

    if show_payload:
        OPC_UA_Binary(ans.load).show()

    return ans


################################################################################
#### @ create monitored items
################################################################################


def OPC_create_monitored_items_request(
    socket,
    sequence_id,
    request_id,
    request_handle_id,
    channel_id,
    token_id,
    timestamp_start,
    auth_token: str,
    subscription_id: int,
    nodes_to_query: list,
    show_payload: bool = False,
) -> OPC_UA_Binary:
    """
    fetch the main server object

    """

    # craft the main message
    itemsRequest = (
        OPC_UA_Binary()
        / OPC_UA_Binary_SecureConversationMessage()
        / OPC_UA_Binary_EncodableMessageObject()
        / OPC_UA_Binary_Message_CreateMonitoredItemsRequest()
    )

    itemsRequest[CommonParameter_RequestHeader].NodeIdentifier_Numeric_4B = 751

    requestHeader = CommonParameter_RequestHeader
    itemsRequest[requestHeader].RequestHandle = request_handle_id
    itemsRequest[requestHeader].Timestamp = timestamp_start
    itemsRequest[requestHeader].TimeoutHint = 4000

    secureMessage = OPC_UA_Binary_SecureConversationMessage
    itemsRequest[secureMessage].SequenceNumber = sequence_id
    itemsRequest[secureMessage].RequestId = request_id
    itemsRequest[secureMessage].SecureChannelId = channel_id
    itemsRequest[secureMessage].SecurityTokenId = token_id
    itemsRequest[secureMessage].TokenId = token_id

    # Auth Header
    itemsRequest[Generic_NodeId].NodeID_Mask = 0x5
    itemsRequest[Generic_NodeId].NodespaceIndex_Short = 0
    itemsRequest[Generic_NodeId].NodeIdentifier_String_Size = len(auth_token)
    itemsRequest[Generic_NodeId].NodeIdentifier_String = auth_token

    ItemRequest = OPC_UA_Binary_Message_CreateMonitoredItemsRequest
    itemsRequest[ItemRequest].SubscriptionId = subscription_id

    NodesToMonitor = []
    for targetId in nodes_to_query:

        monFilter = CommonParameter_MonitoringParameters()
        monFilter.ClientHandle = 12345
        monFilter.SamplingInterval = 0x00000000000406F40  # 250
        monFilter.QueueSize = 1
        monFilter.DiscardOldest = 1

        node_to_request = CustomParameter_MonitoredItem_CreateRequest(
            RequestedParameters=monFilter
        )
        ItemToMonitor = CommonParameter_ReadValueId
        node_to_request[ItemToMonitor].RVID_Node.NodeIdentifier_Numeric_4B = targetId
        node_to_request[ItemToMonitor].AttributeId = 13
        node_to_request[ItemToMonitor].MonitoringMode = "REPORTING"
        QualifiedName = BuiltIn_OPCUA_Binary_QualifiedName
        node_to_request[QualifiedName].QualifiedName_NSIDX = 0x0

        node_to_request.show2()

        NodesToMonitor.append(node_to_request)

    itemsRequest[ItemRequest].ItemsToCreate = NodesToMonitor
    itemsRequest[ItemRequest].ItemsToCreate_Size = len(NodesToMonitor)

    # update packet len
    itemsRequest[OPC_UA_Binary].MessageSize = len(itemsRequest)

    if show_payload:
        itemsRequest.show2()

    ans = socket.sr1(Raw(itemsRequest))

    if show_payload:
        OPC_UA_Binary(ans.load).show()

    return ans


################################################################################
#### @ close session
################################################################################


def OPC_close_session(
    socket,
    sequence_id,
    request_id,
    request_handle_id,
    channel_id,
    token_id,
    timestamp_start,
    auth_token,
    show_payload: bool = False,
) -> OPC_UA_Binary:
    """
    gracefully close a user session

    """

    # craft the main message
    closeSession = (
        OPC_UA_Binary()
        / OPC_UA_Binary_SecureConversationMessage()
        / OPC_UA_Binary_EncodableMessageObject()
        / OPC_UA_Binary_Message_CloseSessionRequest()
    )

    closeSession[CommonParameter_RequestHeader].NodeIdentifier_Numeric_4B = 473

    secureMessage = OPC_UA_Binary_SecureConversationMessage
    closeSession[secureMessage].SequenceNumber = sequence_id
    closeSession[secureMessage].RequestId = request_id
    closeSession[secureMessage].SecureChannelId = channel_id
    closeSession[secureMessage].SecurityTokenId = token_id
    closeSession[secureMessage].TokenId = token_id

    requestHeader = CommonParameter_RequestHeader
    closeSession[requestHeader].RequestHandle = request_handle_id
    closeSession[requestHeader].Timestamp = timestamp_start
    closeSession[requestHeader].TimeoutHint = 4000

    # important: set the secret session id
    # node uses the string IDs:
    # Response_SessionId_NodeID_Mask= 0x4
    # Response_SessionId_NamespaceIndex_Default= 1
    # = 3d6cc2652777976d615dc0b892e27094
    # Python might use other IDs, we need to adapt

    closeSession[Generic_NodeId].NodeID_Mask = 0x5
    closeSession[Generic_NodeId].NodespaceIndex_Short = 0
    closeSession[Generic_NodeId].NodeIdentifier_String_Size = len(auth_token)
    closeSession[Generic_NodeId].NodeIdentifier_String = auth_token

    closeRequest = OPC_UA_Binary_Message_CloseSessionRequest
    closeSession[closeRequest].DeleteSubscriptions = 0  # do not delete!

    closeSession[OPC_UA_Binary].MessageSize = len(closeSession)

    if show_payload:
        closeSession.show2()

    ans = socket.sr1(Raw(closeSession))

    if show_payload:
        OPC_UA_Binary(ans.load).show()

    return ans


################################################################################
#### @ close secure channel
################################################################################


def OPC_close_secureChannel(
    socket,
    sequence_id,
    request_id,
    request_handle_id,
    channel_id,
    token_id,
    timestamp_start,
    auth_token,
    show_payload: bool = False,
):
    """
    gracefully close a secure channel

    """

    # craft the main message
    closeSession = (
        OPC_UA_Binary()
        / OPC_UA_Binary_CloseSecureChannel()
        / OPC_UA_Binary_EncodableMessageObject()
        / OPC_UA_Binary_Message_CloseSecureChannelRequest()
    )

    closeSession[CommonParameter_RequestHeader].NodeIdentifier_Numeric_4B = 452

    secureMessage = OPC_UA_Binary_CloseSecureChannel
    closeSession[secureMessage].SequenceNumber = sequence_id
    closeSession[secureMessage].RequestId = request_id
    closeSession[secureMessage].SecureChannelId = channel_id
    closeSession[secureMessage].SecurityTokenId = token_id

    requestHeader = CommonParameter_RequestHeader
    closeSession[requestHeader].RequestHandle = request_handle_id
    closeSession[requestHeader].Timestamp = timestamp_start
    closeSession[requestHeader].TimeoutHint = 4000

    # important: set the secret session id
    # node uses the string IDs:
    # Response_SessionId_NodeID_Mask= 0x4
    # Response_SessionId_NamespaceIndex_Default= 1
    # = 3d6cc2652777976d615dc0b892e27094
    # Python might use other IDs, we need to adapt

    # closeSession[Generic_NodeId].NodeID_Mask = 0
    # closeSession[Generic_NodeId].NodespaceIndex_Short = 0
    # closeSession[Generic_NodeId].NodeIdentifier_String_Size = len(auth_token)
    # closeSession[Generic_NodeId].NodeIdentifier_String = auth_token

    closeSession[OPC_UA_Binary].MessageSize = len(closeSession)

    if show_payload:
        closeSession.show2()

    socket.send(Raw(closeSession))


################################################################################
#### @ main
################################################################################


def main():

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
        show_payload=True,
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

    answer = OPC_subscription_request(
        socket=socket,
        sequence_id=startSequence,
        request_id=startRequest,
        request_handle_id=startRequestHandle,
        channel_id=channelId,
        token_id=tokenId,
        timestamp_start=ts,
        auth_token=session_authToken,
        show_payload=True,
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
        show_payload=True,
    )

    startRequest += 1
    startSequence += 1
    startRequestHandle += 1
    ts += 1000

    res = OPC_UA_Binary(answer.load)

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


if __name__ == "__main__":
    main()
