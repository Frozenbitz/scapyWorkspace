from scapy.all import *
from scapy.compat import raw
from scapy.layers.l2 import Ether
from scapy.utils import hexdump


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
    open62541_client_CloseSecureChannelRequest_err,
)

from workspace.diagnostics.python_opcua import (
    pythonopc_client_hello,
    pythonopc_client_hello_ack,
    pythonopc_client_OpenSecureChannel,
    pythonopc_client_OpenSecureChannel_ack,
    pythonopc_client_CreateSessionRequest,
    pythonopc_client_CreateSessionRequest_ack,
    pythonopc_client_ActivateSessionRequest,
    pythonopc_client_ActivateSessionRequest_ack,
    pythonopc_client_ReadRequest,
    pythonopc_client_ReadRequest_ack,
    pythonopc_client_CloseSessionRequest,
    pythonopc_client_CloseSessionRequest_ack,
    pythonopc_client_CloseSecureChannelRequest,
)

from workspace.diagnostics.nodejs_opcua import (
    nodejs_client_hello,
    nodejs_client_hello_ack,
    nodejs_client_OpenSecureChannel,
    nodejs_client_OpenSecureChannel_ack,
    nodejs_client_CreateSessionRequest,
    nodejs_client_CreateSessionRequest_ack,
    nodejs_client_ActivateSessionRequest,
    nodejs_client_ActivateSessionRequest_ack,
    nodejs_client_ReadRequest,
    nodejs_client_ReadRequest_ack,
    nodejs_client_CloseSessionRequest,
    nodejs_client_CloseSessionRequest_ack,
    nodejs_client_CloseSecureChannelRequest,
    nodejs_client_CloseSecureChannelRequest_ack,
)

from workspace.diagnostics.dotnetstd import (
    dotnetstd_client_hello,
    dotnetstd_client_hello_ack,
    dotnetstd_client_OpenSecureChannel,
    dotnetstd_client_OpenSecureChannel_ack,
    dotnetstd_client_CreateSessionRequest,
    dotnetstd_client_CreateSessionRequest_ack,
    dotnetstd_client_ActivateSessionRequest,
    dotnetstd_client_ActivateSessionRequest_ack,
    dotnetstd_client_ReadRequest,
    dotnetstd_client_ReadRequest_ack,
    dotnetstd_client_CloseSessionRequest,
    dotnetstd_client_CloseSessionRequest_ack,
    dotnetstd_client_CloseSecureChannelRequest,
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

    print(
        "\n--- Parsing open62541 Client SecMSG ActivateSessionRequest ACK as Ether ---\n"
    )
    dumpOpcPackets(open62541_client_ActivateSessionRequest_ack)

    print("\n--- Parsing open62541 Client SecMSG ReadRequest as Ether ---\n")
    dumpOpcPackets(open62541_client_ReadRequest)

    print("\n--- Parsing open62541 Client SecMSG ReadRequest ACK as Ether ---\n")
    dumpOpcPackets(open62541_client_ReadRequest_ack)

    print("\n--- Parsing open62541 Client SecMSG CloseSessionRequest as Ether ---\n")
    dumpOpcPackets(open62541_client_CloseSessionRequest)

    print(
        "\n--- Parsing open62541 Client SecMSG CloseSessionRequest ACK as Ether ---\n"
    )
    dumpOpcPackets(open62541_client_CloseSessionRequest_ack)

    print("\n--- Parsing open62541 Client CloseSecureChannelRequest as Ether ---\n")
    dumpOpcPackets(open62541_client_CloseSecureChannelRequest)

    print("\n--- Parsing open62541 Client CloseSecureChannelRequest ACK as Ether ---\n")
    dumpOpcPackets(open62541_client_CloseSecureChannelRequest_ack)

    # ---------------------------------------------------------------------------- #

    # print("\n--- Parsing python opc Client Hello as Ether ---\n")
    # dumpOpcPackets(pythonopc_client_hello)

    # print("\n--- Parsing python opc Client Hello ACK as Ether ---\n")
    # dumpOpcPackets(pythonopc_client_hello_ack)

    # print("\n--- Parsing python opc Client OpenSecureChannel as Ether ---\n")
    # dumpOpcPackets(pythonopc_client_OpenSecureChannel)

    # print("\n--- Parsing python opc Client OpenSecureChannel ACK as Ether ---\n")
    # dumpOpcPackets(pythonopc_client_OpenSecureChannel_ack)

    # print("\n--- Parsing python opc Client SecMSG CreateSessionRequest as Ether ---\n")
    # dumpOpcPackets(pythonopc_client_CreateSessionRequest)

    # print("\n--- Parsing python opc Client SecMSG CreateSessionRequest ACK Ether ---\n")
    # dumpOpcPackets(pythonopc_client_CreateSessionRequest_ack)

    # print(
    #     "\n--- Parsing python opc Client SecMSG ActivateSessionRequest as Ether ---\n"
    # )
    # dumpOpcPackets(pythonopc_client_ActivateSessionRequest)

    # print(
    #     "\n--- Parsing python opc Client SecMSG ActivateSessionRequest ACK as Ether ---\n"
    # )
    # dumpOpcPackets(pythonopc_client_ActivateSessionRequest_ack)

    # print("\n--- Parsing python opc Client SecMSG ReadRequest as Ether ---\n")
    # dumpOpcPackets(pythonopc_client_ReadRequest)

    # print("\n--- Parsing python opc Client SecMSG ReadRequest ACK as Ether ---\n")
    # dumpOpcPackets(pythonopc_client_ReadRequest_ack)

    # print("\n--- Parsing python opc Client SecMSG CloseSessionRequest as Ether ---\n")
    # dumpOpcPackets(pythonopc_client_CloseSessionRequest)

    # print(
    #     "\n--- Parsing python opc Client SecMSG CloseSessionRequest ACK as Ether ---\n"
    # )
    # dumpOpcPackets(pythonopc_client_CloseSessionRequest_ack)

    # print("\n--- Parsing python opc Client CloseSecureChannelRequest as Ether ---\n")
    # dumpOpcPackets(pythonopc_client_CloseSecureChannelRequest)

    # ---------------------------------------------------------------------------- #

    # print("\n--- Parsing nodejs Client Hello as Ether ---\n")
    # dumpOpcPackets(nodejs_client_hello)

    # print("\n--- Parsing nodejs Client Hello ACK as Ether ---\n")
    # dumpOpcPackets(nodejs_client_hello_ack)

    # print("\n--- Parsing nodejs Client OpenSecureChannel as Ether ---\n")
    # dumpOpcPackets(nodejs_client_OpenSecureChannel)

    # print("\n--- Parsing nodejs Client OpenSecureChannel ACK as Ether ---\n")
    # dumpOpcPackets(nodejs_client_OpenSecureChannel_ack)

    # print("\n--- Parsing nodejs Client SecMSG CreateSessionRequest as Ether ---\n")
    # dumpOpcPackets(nodejs_client_CreateSessionRequest)

    # print("\n--- Parsing nodejs Client SecMSG CreateSessionRequest ACK Ether ---\n")
    # dumpOpcPackets(nodejs_client_CreateSessionRequest_ack)

    # print("\n--- Parsing nodejs Client SecMSG ActivateSessionRequest as Ether ---\n")
    # dumpOpcPackets(nodejs_client_ActivateSessionRequest)

    # print(
    #     "\n--- Parsing nodejs Client SecMSG ActivateSessionRequest ACK as Ether ---\n"
    # )
    # dumpOpcPackets(nodejs_client_ActivateSessionRequest_ack)

    # print("\n--- Parsing nodejs Client SecMSG ReadRequest as Ether ---\n")
    # dumpOpcPackets(nodejs_client_ReadRequest)

    # print("\n--- Parsing nodejs Client SecMSG ReadRequest ACK as Ether ---\n")
    # dumpOpcPackets(nodejs_client_ReadRequest_ack)

    # print("\n--- Parsing nodejs Client SecMSG CloseSessionRequest as Ether ---\n")
    # dumpOpcPackets(nodejs_client_CloseSessionRequest)

    # print("\n--- Parsing nodejs Client SecMSG CloseSessionRequest ACK as Ether ---\n")
    # dumpOpcPackets(nodejs_client_CloseSessionRequest_ack)

    # print("\n--- Parsing nodejs Client CloseSecureChannelRequest as Ether ---\n")
    # dumpOpcPackets(nodejs_client_CloseSecureChannelRequest)

    # print("\n--- Parsing nodejs Client CloseSecureChannelRequest ACK as Ether ---\n")
    # dumpOpcPackets(nodejs_client_CloseSecureChannelRequest_ack)

    # ---------------------------------------------------------------------------- #

    # print("\n--- Parsing dotnetstd Client Hello as Ether ---\n")
    # dumpOpcPackets(dotnetstd_client_hello)

    # print("\n--- Parsing dotnetstd Client Hello ACK as Ether ---\n")
    # dumpOpcPackets(dotnetstd_client_hello_ack)

    # print("\n--- Parsing dotnetstd Client OpenSecureChannel as Ether ---\n")
    # dumpOpcPackets(dotnetstd_client_OpenSecureChannel)

    # print("\n--- Parsing dotnetstd Client OpenSecureChannel ACK as Ether ---\n")
    # dumpOpcPackets(dotnetstd_client_OpenSecureChannel_ack)

    # print("\n--- Parsing dotnetstd Client SecMSG CreateSessionRequest as Ether ---\n")
    # dumpOpcPackets(dotnetstd_client_CreateSessionRequest)

    # print("\n--- Parsing dotnetstd Client SecMSG CreateSessionRequest ACK Ether ---\n")
    # dumpOpcPackets(dotnetstd_client_CreateSessionRequest_ack)

    # print("\n--- Parsing dotnetstd Client SecMSG ActivateSessionRequest as Ether ---\n")
    # dumpOpcPackets(dotnetstd_client_ActivateSessionRequest)

    # print(
    #     "\n--- Parsing dotnetstd Client SecMSG ActivateSessionRequest ACK as Ether ---\n"
    # )
    # dumpOpcPackets(dotnetstd_client_ActivateSessionRequest_ack)

    # print("\n--- Parsing dotnetstd Client SecMSG ReadRequest as Ether ---\n")
    # dumpOpcPackets(dotnetstd_client_ReadRequest)

    # print("\n--- Parsing dotnetstd Client SecMSG ReadRequest ACK as Ether ---\n")
    # dumpOpcPackets(dotnetstd_client_ReadRequest_ack)

    # print("\n--- Parsing dotnetstd Client SecMSG CloseSessionRequest as Ether ---\n")
    # dumpOpcPackets(dotnetstd_client_CloseSessionRequest)

    # print(
    #     "\n--- Parsing dotnetstd Client SecMSG CloseSessionRequest ACK as Ether ---\n"
    # )
    # dumpOpcPackets(dotnetstd_client_CloseSessionRequest_ack)

    # print("\n--- Parsing dotnetstd Client CloseSecureChannelRequest as Ether ---\n")
    # dumpOpcPackets(dotnetstd_client_CloseSecureChannelRequest)


def dumpOpcPackets(rawPackage: bytes):
    parsed_ack = Ether(rawPackage)
    print("/>>>> dump ")
    hexdump(parsed_ack)
    print("end dump <<<</ \n")
    parsed_ack.show()


if __name__ == "__main__":
    main
