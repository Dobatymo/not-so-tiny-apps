from unittest import TestCase

from portscanner.shared import IcmpHeader, IcmpType, IPv4Header, TcpFlags, TCPv4Header


class SharedTest(TestCase):
    def test_ipv4header(self):
        data = b"\x45\x00\x00\x73\x00\x00\x40\x00\x40\x11\xb8\x61\xc0\xa8\x00\x01\xc0\xa8\x00\xc7"
        assert IPv4Header.from_bytes(data).to_bytes() == data

    def test_tcpflags(self):
        flags = TcpFlags(syn=1, ack=1)
        byte = flags.to_byte()
        assert byte == 18  # 0b00010010
        flags2 = TcpFlags.from_byte(byte)
        assert repr(flags2) == "TcpFlags(syn=1, ack=1)"

    def test_tcpv4_header(self):
        header1b = TCPv4Header(1234, 80).to_bytes()
        assert header1b == TCPv4Header.from_bytes(header1b).to_bytes()

    def test_icmp_header(self):
        header1b = IcmpHeader(IcmpType.ECHO_REQUEST, 0, identifier=1, sequence=2).to_bytes()
        assert header1b == IcmpHeader.from_bytes(header1b).to_bytes()
