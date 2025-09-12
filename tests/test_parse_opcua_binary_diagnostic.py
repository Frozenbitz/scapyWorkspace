from scapy.all import *
from scapy.contrib.opcua_binary import (
    AdditionalHeader,
    OPC_UA_Binary,
    OPC_UA_Binary_Hello,
    OPC_UA_Binary_Ack,
    OPC_UA_Binary_SecureConversationMessage,
    OPC_UA_Binary_Error,
    RequestHeader,
)


def test_opcua_binary_diagnostic_messages():
    opcBinary_HEL = bytes.fromhex(
        "48454c463a00000000000000ffff0000ffff000000000000000000001a0000006f70632"
        "e7463703a2f2f3137322e31372e302e323a343834302f"
    )
    pkt = OPC_UA_Binary(opcBinary_HEL)
    assert pkt.haslayer(OPC_UA_Binary)
    assert pkt.haslayer(OPC_UA_Binary_Hello)
    assert pkt[OPC_UA_Binary].MessageType == b"HEL"
    del pkt

    opcBinary_ACK = bytes.fromhex(
        "41434b461c0000000000000000200000002000000020000000000000"
    )
    pkt = OPC_UA_Binary(opcBinary_ACK)
    assert pkt is not None
    assert pkt.haslayer(OPC_UA_Binary)
    assert pkt.haslayer(OPC_UA_Binary_Ack)
    assert pkt[OPC_UA_Binary].MessageType == b"ACK"
    del pkt


def test_opcua_binary_diag_opensecurechannel_request():
    OPN_SEC_CHANNEL_requestHeader = bytes.fromhex(
        "0000a85e2235e965d8010000000000000000ffffffff00000000000000"
    )

    pkt = RequestHeader(OPN_SEC_CHANNEL_requestHeader)
    assert pkt[RequestHeader].NodeID == 0
    assert pkt[RequestHeader].RequestHandle == 0
    assert pkt[RequestHeader].ReturnDiagnostics == 0
    assert pkt[RequestHeader].TimeoutHint == 0
    assert pkt[RequestHeader].AH_NodeID == 0
    assert pkt[RequestHeader].EncodingMask == 0


def main():
    test_opcua_binary_diagnostic_messages()
    print("all tests ran successfuly")


if __name__ == "__main__":
    main()
