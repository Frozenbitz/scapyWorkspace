from scapy.all import *
from scapy.contrib.opcua_binary import (
    OPC_UA_Binary,
    OPC_UA_Binary_Hello,
    OPC_UA_Binary_Ack,
    OPC_UA_Binary_SecureConversationMessage,
    OPC_UA_Binary_Error,
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


def main():

    test_opcua_binary_diagnostic_messages()
    print("all tests ran successfuly")


if __name__ == "__main__":
    main()
