import struct
import os

class ICMPPacket:
    def __init__(self, data=None, packet=None):
        self.type = 47
        self.code = 0
        self.checksum = 0
        self.id = os.getpid() & 0xFFFF
        self.seq = 0
        self.data = data

        if packet:
            self.unpack(packet)

    def pack(self):
        checksum = 0
        header = struct.pack('!BBHHH', self.type, self.code, checksum, self.id, self.seq)

        # calculate checksum
        if self.data:
            packet = header + self.data
        else:
            packet = header

        checksum = self.calculate_checksum(packet)

        # repack with the correct checksum
        header = struct.pack('!BBHHH', self.type, self.code, checksum, self.id, self.seq)

        if self.data:
            return header + self.data
        return header

    def calculate_checksum(self, data):
        if len(data) % 2 != 0:
            data += b'\x00'
        s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        return ~s & 0xffff

    def unpack(self, packet):
        icmp_part = packet[20:]
        icmp_header = icmp_part[:8]
        self.type, self.code, received_checksum, self.id, self.seq = struct.unpack('!BBHHH', icmp_header)

        # have checksum calulation here as well
        header_with_zero_checksum = struct.pack('!BBHHH', self.type, self.code, 0, self.id, self.seq)
        data = icmp_part[8:] if len(icmp_part) > 8 else b''
        pseudo_packet = header_with_zero_checksum + data

        calculated_checksum = self.calculate_checksum(pseudo_packet)

        if calculated_checksum != received_checksum:
            raise ValueError(f"Invalid checksum. Expected {received_checksum}, got {calculated_checksum}")

        self.checksum = received_checksum
        if len(packet) > 28:
            self.data = packet[28:]
        else:
            self.data = None