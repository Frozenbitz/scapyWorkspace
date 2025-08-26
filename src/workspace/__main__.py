from scapy.all import *
from scapy.scapy.compat import raw
from scapy.layers.l2 import Ether
from scapy.scapy.utils import hexdump


from workspace.diagnostics.open62541 import (
    open62541_client_hello,
    open62541_client_hello_ack,
    open62541_client_OpenSecureChannel,
    open62541_client_OpenSecureChannel_ack,
    open62541_client_CreateSessionRequest,
    open62541_client_CreateSessionRequest_ack,
    open62541_client_ActivateSessionRequest,
    open62541_client_ActivateSessionRequest_ack,
    open62541_client_ReadRequest,
    open62541_client_ReadRequest_ack,
    open62541_client_CloseSessionRequest,
    open62541_client_CloseSessionRequest_ack,
    open62541_client_CloseSecureChannelRequest,
    open62541_client_CloseSecureChannelRequest_ack,
)


def main():

    

    print("\n--- Parsing open62541 Client Hello as Ether ---\n")
    dumpOpcPackets(open62541_client_hello)

    print("\n--- Parsing open62541 Client Hello ACK as Ether ---\n")
    dumpOpcPackets(open62541_client_hello_ack)

    print("\n--- Parsing open62541 Client OpenSecureChannel as Ether ---\n")
    dumpOpcPackets(open62541_client_OpenSecureChannel)

    print("\n--- Parsing open62541 Client OpenSecureChannel ACK as Ether ---\n")
    dumpOpcPackets(open62541_client_OpenSecureChannel_ack)

    print("\n--- Parsing open62541 Client SecMSG CreateSessionRequest as Ether ---\n")
    dumpOpcPackets(open62541_client_CreateSessionRequest)

    print("\n--- Parsing open62541 Client SecMSG CreateSessionRequest ACK Ether ---\n")
    dumpOpcPackets(open62541_client_CreateSessionRequest_ack)

    print("\n--- Parsing open62541 Client SecMSG ActivateSessionRequest as Ether ---\n")
    dumpOpcPackets(open62541_client_ActivateSessionRequest)

    print("\n--- Parsing open62541 Client SecMSG ActivateSessionRequest ACK as Ether ---\n")
    dumpOpcPackets(open62541_client_ActivateSessionRequest_ack)

    print("\n--- Parsing open62541 Client SecMSG ReadRequest as Ether ---\n")
    dumpOpcPackets(open62541_client_ReadRequest)

    print("\n--- Parsing open62541 Client SecMSG ReadRequest ACK as Ether ---\n")
    dumpOpcPackets(open62541_client_ReadRequest_ack)

    print("\n--- Parsing open62541 Client SecMSG CloseSessionRequest as Ether ---\n")
    dumpOpcPackets(open62541_client_CloseSessionRequest)

    print("\n--- Parsing open62541 Client SecMSG CloseSessionRequest ACK as Ether ---\n")
    dumpOpcPackets(open62541_client_CloseSessionRequest_ack)

    print("\n--- Parsing open62541 Client CloseSecureChannelRequest as Ether ---\n")
    dumpOpcPackets(open62541_client_CloseSecureChannelRequest)

    print("\n--- Parsing open62541 Client CloseSecureChannelRequest ACK as Ether ---\n")
    dumpOpcPackets(open62541_client_CloseSecureChannelRequest_ack)



def dumpOpcPackets(rawPackage: bytes):
    parsed_ack = Ether(rawPackage)
    print("/>>>> dump ")
    hexdump(parsed_ack)
    print("end dump <<<</ \n")
    parsed_ack.show()

if __name__ == "__main__":
    main