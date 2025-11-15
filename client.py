import os
import sys
import time
import struct
import socket
from socket import AF_INET, SOCK_RAW, getprotobyname, gethostbyname, htons
import select
ICMP_ECHO_REQUEST = 8

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
    answer = socket.htons(answer)
    return answer

def sendOnePing(sock, destAddr, ID):
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, ID, 1)
    data = struct.pack("d", time.time())
    real_checksum = checksum(header + data)

    if sys.platform == "darwin":
        real_checksum = htons(real_checksum) & 0xffff
    else:
        real_checksum = htons(real_checksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, real_checksum, ID, 1)
    packet = header + data

    sock.sendto(packet, (destAddr, 1))

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

        # Extract ICMP header from IP packet (offset 20)
        icmpHeader = recPacket[20:28]
        type, code, checksum, packetID, sequence = struct.unpack(
            "bbHHh", icmpHeader
        )

        if packetID == ID:
            # Extract timestamp
            bytesInDouble = struct.calcsize("d")
            timeSent = struct.unpack("d", recPacket[28:28 + bytesInDouble])[0]
            return timeReceived - timeSent

        timeLeft -= selectTime
        if timeLeft <= 0:
            return None

def doOnePing(destAddr, timeout):
    icmp = getprotobyname("icmp")
    sock = socket.socket(AF_INET, SOCK_RAW, icmp)
    myID = os.getpid() & 0xFFFF

    sendOnePing(sock, destAddr, myID)
    result = receiveOnePing(sock, myID, timeout, destAddr)
    sock.close()
    return result

def ping(host, timeout=1):
    dest = gethostbyname(host)
    resps = []

    print(f"Pinging {dest} using Python:\n")

    for i in range(5):
        result = doOnePing(dest, timeout)
        resps.append(result)
        print(f"Reply {i+1}: {result} sec")
        time.sleep(1)

    return resps

if __name__ == "__main__":
    ping("google.co.il")
