import os
import sys
import time
import struct
import socket
import select
from socket import AF_INET, SOCK_RAW, getprotobyname, gethostbyname, htons

ICMP_ECHO_REQUEST = 8


# ----------------- CHECKSUM FUNCTION -----------------
def checksum(source):
    sum = 0
    count = 0
    countTo = (len(source) // 2) * 2

    while count < countTo:
        thisVal = source[count + 1] * 256 + source[count]
        sum += thisVal
        sum &= 0xffffffff
        count += 2

    if countTo < len(source):
        sum += source[-1]
        sum &= 0xffffffff

    sum = (sum >> 16) + (sum & 0xffff)
    sum += (sum >> 16)
    answer = ~sum & 0xffff
    return socket.htons(answer)


# ----------------- SEND ONE PING -----------------
def sendOnePing(sock, destAddr, ID):
    # Header fields: Type (8), Code (0), Checksum (0), ID, Sequence
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, ID, 1)
    data = struct.pack("d", time.time())

    # Compute the checksum on the header + data
    real_checksum = checksum(header + data)

    # macOS requires masking to 16 bits
    if sys.platform == "darwin":
        real_checksum = htons(real_checksum) & 0xffff
    else:
        real_checksum = htons(real_checksum)

    # Repack with correct checksum
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, real_checksum, ID, 1)
    packet = header + data

    sock.sendto(packet, (destAddr, 1))


# ----------------- RECEIVE ONE PING -----------------
def receiveOnePing(sock, ID, timeout, destAddr):
    timeLeft = timeout

    while True:
        startSelect = time.time()
        ready = select.select([sock], [], [], timeLeft)
        selectTime = time.time() - startSelect

        if ready[0] == []:  # Timeout
            return None

        timeReceived = time.time()
        recPacket, addr = sock.recvfrom(1024)

        # ICMP header starts after the 20-byte IP header
        icmpHeader = recPacket[20:28]
        type, code, checksum, packetID, sequence = struct.unpack("bbHHh", icmpHeader)

        # -------- ICMP ERROR HANDLING --------
        if type == 3:  # Destination Unreachable
            errors = {
                0: "Destination Network Unreachable",
                1: "Destination Host Unreachable",
                2: "Destination Protocol Unreachable",
                3: "Destination Port Unreachable",
                4: "Fragmentation Needed (DF Set)",
                5: "Source Route Failed"
            }
            msg = errors.get(code, f"Unknown Unreachable Error (code {code})")
            print(f"ICMP Error: {msg}")
            return None

        # Valid echo reply
        if packetID == ID:
            timeSent = struct.unpack("d", recPacket[28:36])[0]
            return timeReceived - timeSent

        timeLeft -= selectTime
        if timeLeft <= 0:
            return None


# ----------------- DO ONE PING -----------------
def doOnePing(destAddr, timeout):
    icmp = getprotobyname("icmp")
    sock = socket.socket(AF_INET, SOCK_RAW, icmp)
    myID = os.getpid() & 0xFFFF

    sendOnePing(sock, destAddr, myID)
    rtt = receiveOnePing(sock, myID, timeout, destAddr)

    sock.close()
    return rtt


# ----------------- PING MAIN FUNCTION -----------------
def ping(host, timeout=1, count=5):
    dest = gethostbyname(host)
    resps = []

    print(f"Pinging {dest} using Python:\n")

    for i in range(count):
        rtt = doOnePing(dest, timeout)
        resps.append(rtt)

        if rtt is None:
            print("Request timed out.")
        else:
            print(f"Reply {i+1}: RTT = {rtt*1000:.3f} ms")

        time.sleep(1)

    # ------- STATISTICS -------
    received = [r for r in resps if r is not None]
    sent = len(resps)
    loss = (1 - len(received) / sent) * 100

    print("\n--- Ping statistics ---")
    print(f"{sent} packets transmitted, {len(received)} received, {loss:.1f}% packet loss")

    if received:
        print("rtt min/avg/max = "
              f"{min(received)*1000:.3f}/"
              f"{(sum(received)/len(received))*1000:.3f}/"
              f"{max(received)*1000:.3f} ms")

    return resps


# ----------------- MAIN -----------------
if __name__ == "__main__":
    ping("google.com")
