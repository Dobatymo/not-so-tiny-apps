import errno
import ipaddress
import logging
import random
import re
import socket
import time
from collections.abc import Iterable, Iterator
from enum import Enum, auto
from struct import calcsize, pack, unpack
from typing import Self

from genutility.callbacks import Progress
from genutility.iter import no_dupes

IpAddrT = ipaddress.IPv4Address | ipaddress.IPv6Address

logger = logging.getLogger(__name__)

ICMP_ECHO_IDENTIFIER = random.randrange(0, 2**16)


class IpProtocols(Enum):
    IP = 0
    ICMP = 1
    GGP = 3
    TCP = 6
    EGP = 8
    PUP = 12
    UDP = 17
    HMP = 20
    XNS_IDP = 22
    RDP = 27
    IPV6 = 41
    IPV6_ROUTE = 43
    IPV6_FRAG = 44
    ESP = 50
    AH = 51
    IPV6_ICMP = 58
    IPV6_NONXT = 59
    IPV6_OPTS = 60
    RVD = 66


class PortStatus(Enum):
    OPEN = auto()
    OPEN_OR_FILTERED = auto()
    CLOSED = auto()
    FILTERED = auto()
    ERROR = auto()


class IpStatus(Enum):
    REACHABLE = auto()
    UNREACHABLE = auto()
    ERROR = auto()


class ScanType(Enum):
    TCP_SYN = "TCP SYN Scan"
    TCP_CONNECT = "TCP Connect Scan"
    UDP = "UDP Scan"
    ICMP_ECHO = "ICMP Echo"


class IterableWithLength:
    def __init__(self, iterable: Iterable, length: int) -> None:
        self._iterable = iterable
        self._length = length

    def __iter__(self) -> Iterator:
        return iter(self._iterable)

    def __len__(self) -> int:
        return self._length


def is_valid_hostname(host: str) -> bool:
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return False

    if len(host) > 255:
        return False

    if host.endswith("."):
        host = host[:-1]

    label_regex = re.compile(r"^[A-Z0-9-]{1,63}$", re.IGNORECASE)

    def is_valid_label(label: str) -> bool:
        if label[0] == "-" or label[-1] == "-":
            return False
        return label_regex.match(label) is not None

    return all(is_valid_label(label) for label in host.split("."))


def calc_checksum(msg: bytes) -> int:
    s = 0

    for i in range(0, len(msg), 2):
        w = msg[i] + (msg[i + 1] << 8)
        s += w

    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    s = ~s & 0xFFFF

    return s


def calc_checksum_2(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


class SlotsReprMixin:
    def __repr__(self):
        d = {name: getattr(self, name) for name in self.__slots__}

        args = ", ".join(f"{k}={v}" for k, v in d.items() if v is not None)
        return f"{self.__class__.__name__}({args})"


class IPv4Header(SlotsReprMixin):
    __slots__ = (
        "version",
        "ihl",
        "tos",
        "total_length",
        "identification",
        "flags_fragment_offset",
        "ttl",
        "protocol",
        "header_checksum",
        "source_addr",
        "destination_addr",
    )

    format = "!BBHHHBBH4s4s"

    def __init__(
        self,
        destination_addr: ipaddress.IPv4Address,
        source_addr: ipaddress.IPv4Address,
        version=4,
        ihl=5,
        tos=0,
        total_length=0,
        identification: int | None = None,
        flags_fragment_offset=0,
        ttl=255,
        protocol=IpProtocols.TCP,
        header_checksum=0,
    ):
        self.version = version
        self.ihl = ihl
        self.tos = tos
        self.total_length = total_length
        self.identification = identification if identification is not None else 54321
        self.flags_fragment_offset = flags_fragment_offset
        self.ttl = ttl
        self.protocol = protocol
        self.header_checksum = header_checksum
        self.source_addr = source_addr
        self.destination_addr = destination_addr

    def to_bytes(self) -> bytes:
        ip_ihl_ver = (self.version << 4) + self.ihl

        return pack(
            self.format,
            ip_ihl_ver,
            self.tos,
            self.total_length,  # kernel will fill the correct total length
            self.identification,
            self.flags_fragment_offset,
            self.ttl,
            self.protocol.value,
            self.header_checksum,  # kernel will fill the correct checksum
            socket.inet_aton(str(self.source_addr)),
            socket.inet_aton(str(self.destination_addr)),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        (
            ihl_ver,
            tos,
            total_length,
            identification,
            flags_fragment_offset,
            ttl,
            protocol,
            header_checksum,
            source_addr,
            destination_addr,
        ) = unpack(cls.format, data)

        assert ihl_ver == 69

        version = 4
        ihl = 5
        source_addr = ipaddress.IPv4Address(socket.inet_ntoa(source_addr))
        destination_addr = ipaddress.IPv4Address(socket.inet_ntoa(destination_addr))

        return cls(
            destination_addr,
            source_addr,
            version,
            ihl,
            tos,
            total_length,
            identification,
            flags_fragment_offset,
            ttl,
            IpProtocols(protocol),
            header_checksum,
        )


def resolve(hosts: Iterable[str]) -> Iterator[tuple[str, IpAddrT]]:
    for host in hosts:
        try:
            start_time = time.time()
            results = socket.getaddrinfo(host, None)
        except socket.gaierror as e:
            elapsed = time.time() - start_time
            logger.error("Failed to resolve %s in %f seconds: %s", host, elapsed, e)
        else:
            for family, _type, _proto, _canonname, sockaddr in results:
                # print(family, _type, _proto, _canonname, sockaddr)
                if family == socket.AF_INET:
                    yield host, ipaddress.IPv4Address(sockaddr[0])
                elif family == socket.AF_INET6:
                    yield host, ipaddress.IPv6Address(sockaddr[0])
                # else ignore


class TcpFlags:
    __slots__ = ("fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr")

    def __init__(
        self,
        fin: int = 0,
        syn: int = 0,
        rst: int = 0,
        psh: int = 0,
        ack: int = 0,
        urg: int = 0,
        ece: int = 0,
        cwr: int = 0,
    ) -> None:
        self.fin = fin
        self.syn = syn
        self.rst = rst
        self.psh = psh
        self.ack = ack
        self.urg = urg
        self.ece = ece
        self.cwr = cwr

    def __eq__(self, other):
        return (
            self.fin == other.fin
            and self.syn == other.syn
            and self.rst == other.rst
            and self.psh == other.psh
            and self.ack == other.ack
            and self.urg == other.urg
            and self.ece == other.ece
            and self.cwr == other.cwr
        )

    def to_byte(self) -> int:
        return (
            self.fin
            + (self.syn << 1)
            + (self.rst << 2)
            + (self.psh << 3)
            + (self.ack << 4)
            + (self.urg << 5)
            + (self.ece << 6)
            + (self.cwr << 7)
        )

    @classmethod
    def from_byte(cls, flags: int) -> Self:
        fin = (flags >> 0) & 1
        syn = (flags >> 1) & 1
        rst = (flags >> 2) & 1
        psh = (flags >> 3) & 1
        ack = (flags >> 4) & 1
        urg = (flags >> 5) & 1
        ece = (flags >> 6) & 1
        cwr = (flags >> 7) & 1

        return cls(fin, syn, rst, psh, ack, urg, ece, cwr)

    def __repr__(self):
        args = ", ".join(f"{name}=1" for name in self.__slots__ if getattr(self, name) == 1)
        return f"TcpFlags({args})"


class TCPv4Header(SlotsReprMixin):
    __slots__ = (
        "src_port",
        "dst_port",
        "sequence_number",
        "acknowledgement_number",
        "data_offset",
        "flags",
        "window",
        "tcp_check",
        "urgent_pointer",
    )

    def __init__(
        self,
        src_port: int,
        dst_port: int,
        sequence_number: int | None = None,
        acknowledgement_number: int = 0,
        data_offset: int = 5,
        flags: TcpFlags = TcpFlags(syn=1),  # noqa: B008
        window: int = 5840,
        tcp_check: int = 0,
        urgent_pointer: int = 0,
    ):
        self.src_port = src_port
        self.dst_port = dst_port
        self.sequence_number = sequence_number or 454
        self.acknowledgement_number = acknowledgement_number
        self.data_offset = data_offset
        self.flags = flags
        self.window = window
        self.tcp_check = tcp_check
        self.urgent_pointer = urgent_pointer

    def __len__(self) -> int:
        return calcsize("HHLLBBHHH")

    def to_bytes(self) -> bytes:
        data_offset_reserved = self.data_offset << 4

        # remember checksum is NOT in network byte order
        return (
            pack(
                "!HHLLBBH",
                self.src_port,
                self.dst_port,
                self.sequence_number,
                self.acknowledgement_number,
                data_offset_reserved,
                self.flags.to_byte(),
                socket.htons(self.window),
            )
            + pack("H", self.tcp_check)
            + pack("!H", self.urgent_pointer)
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        src_port, dst_port, sequence_number, acknowledgement_number, data_offset_reserved, flags, window = unpack(
            "!HHLLBBH", data[:16]
        )
        (tcp_check,) = unpack("H", data[16:18])
        (urgent_pointer,) = unpack("!H", data[18:20])

        data_offset = data_offset_reserved >> 4

        return cls(
            src_port,
            dst_port,
            sequence_number,
            acknowledgement_number,
            data_offset,
            TcpFlags.from_byte(flags),
            socket.ntohs(window),
            tcp_check,
            urgent_pointer,
        )

    def __repr__(self):
        d = {name: getattr(self, name) for name in self.__slots__}

        args = ", ".join(f"{k}={v}" for k, v in d.items())
        return f"TCPv4Header({args})"


def make_tcp_packet(
    user_data: bytes, src_ip: ipaddress.IPv4Address, dst_ip: ipaddress.IPv4Address, src_port: int, dst_port: int
):
    ip_header = IPv4Header(dst_ip, src_ip)
    tcp_header = TCPv4Header(src_port, dst_port)

    source_address = socket.inet_aton(str(src_ip))
    dest_address = socket.inet_aton(str(dst_ip))
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header) + len(user_data)

    psh = pack("!4s4sBBH", source_address, dest_address, placeholder, protocol, tcp_length)
    psh = psh + tcp_header.to_bytes() + user_data

    tcp_header = TCPv4Header(src_port, dst_port, tcp_check=calc_checksum(psh))

    # final full packet - syn packets don't have any data
    return ip_header.to_bytes() + tcp_header.to_bytes() + user_data


class IcmpType(Enum):
    ECHO_REPLY = 0
    RESERVED1 = 1
    RESERVED2 = 2
    DESTINATION_UNREACHABLE = 3
    SOURCE_QUENCH = 4
    REDIRECT_MESSAGE = 5
    ECHO_REQUEST = 8
    ROUTER_ADVERTISEMENT = 9
    ROUTER_SOLICITATION = 10
    TIME_EXCEEDED = 11
    PARAMETER_PROBLEM_BAD_IP_HEADER = 12
    TIMESTAMP = 13
    TIMESTAMP_REPLY = 14
    INFORMATION_REQUEST = 15
    INFORMATION_REPLY = 16
    ADDRESS_MASK_REQUEST = 17
    ADDRESS_MASK_REPLY = 18
    TRACEROUTE = 30
    EXTENDED_ECHO_REQUEST = 42
    EXTENDED_ECHO_REPLY = 43


class Icmpv6Type(Enum):
    DESTINATION_UNREACHABLE = 1
    PACKET_TOO_BIG = 2
    TIME_EXCEEDED = 3
    PARAMETER_PROBLEM = 4
    ECHO_REQUEST = 128
    ECHO_REPLY = 129
    MULTICAST_LISTENER_QUERY = 130
    MULTICAST_LISTENER_REPORT = 131
    MULTICAST_LISTENER_DONE = 132
    ROUTER_SOLICITATION = 133
    ROUTER_ADVERTISEMENT = 134
    NEIGHBOR_SOLICITATION = 135
    NEIGHBOR_ADVERTISEMEN = 136
    REDIRECT_MESSAGE = 137
    ROUTER_RENUMBERING = 138
    ICMP_NODE_INFORMATION_QUERY = 139
    ICMP_NODE_INFORMATION_RESPONSE = 140
    INVERSE_NEIGHBOR_DISCOVERY_SOLICITATION_MESSAGE = 141
    INVERSE_NEIGHBOR_DISCOVERY_ADVERTISEMENT_MESSAGE = 142
    MULTICAST_LISTENER_DISCOVERY_REPORTS = 143
    HOME_AGENT_ADDRESS_DISCOVERY_REQUEST_MESSAGE = 144
    HOME_AGENT_ADDRESS_DISCOVERY_REPLY_MESSAGE = 145
    MOBILE_PREFIX_SOLICITATION = 146
    MOBILE_PREFIX_ADVERTISEMENT = 147
    CERTIFICATION_PATH_SOLICITATION = 148
    CERTIFICATION_PATH_ADVERTISEMENT = 149
    MULTICAST_ROUTER_ADVERTISEMENT = 151
    MULTICAST_ROUTER_SOLICITATION = 152
    MULTICAST_ROUTER_TERMINATION = 153
    RPL_CONTROL_MESSAGE = 155
    EXTENDED_ECHO_REQUEST = 160
    EXTENDED_ECHO_REPLY = 161


class DestinationUnreachable(Enum):
    NET_UNREACHABLE = 0
    HOST_UNREACHABLE = 1
    PROTOCOL_UNREACHABLE = 2
    PORT_UNREACHABLE = 3
    FRAGMENTATION_NEEDED = 4
    SOURCE_ROUTE_FAILED = 5
    DESTINATION_NETWORK_UNKNOWN = 6
    DESTINATION_HOST_UNKNOWN = 7
    SOURCE_HOST_ISOLATED = 8
    COMMUNICATION_WITH_DESTINATION_NETWORK_IS_ADMINISTRATIVELY_PROHIBITED = 9
    COMMUNICATION_WITH_DESTINATION_HOST_IS_ADMINISTRATIVELY_PROHIBITED = 10
    DESTINATION_NETWORK_UNREACHABLE_FOR_TYPE_OF_SERVICE = 11
    DESTINATION_HOST_UNREACHABLE_FOR_TYPE_OF_SERVICE = 12
    COMMUNICATION_ADMINISTRATIVELY_PROHIBITED = 13
    HOST_PRECEDENCE_VIOLATION = 14
    PRECEDENCE_CUTOFF_IN_EFFECT = 15


class IcmpHeader(SlotsReprMixin):
    __slots__ = (
        "type",
        "code",
        "checksum",
        "identifier",
        "sequence",
    )

    def __init__(
        self,
        icmp_type: IcmpType,
        code: int,
        checksum: int = 0,
        *,
        identifier: int | None = None,
        sequence: int | None = None,
        length: int | None = None,
        next_hop_mtu: int | None = None,
    ):
        self.type = icmp_type
        self.code = code
        self.checksum = checksum
        self.identifier = identifier
        self.sequence = sequence
        self.length = length
        self.next_hop_mtu = next_hop_mtu

    def to_bytes(self) -> bytes:
        if self.type in (IcmpType.ECHO_REQUEST, IcmpType.ECHO_REPLY):
            assert self.code == 0
            assert self.identifier is not None
            assert self.sequence is not None
            return pack("!BBHHH", self.type.value, self.code, self.checksum, self.identifier, self.sequence)
        elif self.type in (IcmpType.DESTINATION_UNREACHABLE,):
            return pack("!BBHBBH", self.type.value, self.code, self.checksum, 0, self.length, self.next_hop_mtu)
        else:
            raise ValueError(f"Unsupported type: {self.type}")

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        _type, code, checksum, rest = unpack("!BBH4s", data)

        icmp_type = IcmpType(_type)

        if icmp_type in (IcmpType.ECHO_REQUEST, IcmpType.ECHO_REPLY):
            assert code == 0
            identifier, sequence = unpack("!HH", rest)
            return cls(icmp_type, code, checksum, identifier=identifier, sequence=sequence)
        if icmp_type in (IcmpType.DESTINATION_UNREACHABLE,):
            _code = DestinationUnreachable(code)
            _unused, length, next_hop_mtu = unpack("!BBH", rest)
            return cls(icmp_type, _code.value, checksum, length=length, next_hop_mtu=next_hop_mtu)
        else:
            raise ValueError(f"Unsupported type: {icmp_type}")


class Icmpv6Header(SlotsReprMixin):
    __slots__ = (
        "type",
        "code",
        "checksum",
        "identifier",
        "sequence",
    )

    def __init__(
        self,
        icmp_type: Icmpv6Type,
        code: int,
        checksum: int = 0,
        *,
        identifier: int | None = None,
        sequence: int | None = None,
    ):
        self.type = icmp_type
        self.code = code
        self.checksum = checksum
        self.identifier = identifier
        self.sequence = sequence

    def to_bytes(self) -> bytes:
        if self.type in (Icmpv6Type.ECHO_REQUEST, Icmpv6Type.ECHO_REPLY):
            assert self.code == 0
            assert self.identifier is not None
            assert self.sequence is not None
            return pack("!BBHHH", self.type.value, self.code, self.checksum, self.identifier, self.sequence)
        else:
            raise ValueError(f"Unsupported type: {self.type}")

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        _type, code, checksum, rest = unpack("!BBH4s", data)

        icmp_type = Icmpv6Type(_type)

        if icmp_type in (Icmpv6Type.ECHO_REQUEST, Icmpv6Type.ECHO_REPLY):
            assert code == 0
            identifier, sequence = unpack("!HH", rest)
            return cls(icmp_type, code, checksum, identifier=identifier, sequence=sequence)
        else:
            raise ValueError(f"Unsupported type: {icmp_type}")


def create_icmp_echo_request(identifier: int, sequence: int, payload: bytes) -> bytes:
    """Build ICMP Echo Request packet"""

    header = IcmpHeader(IcmpType.ECHO_REQUEST, 0, 0, identifier=identifier, sequence=sequence).to_bytes()
    packet = header + payload
    checksum = calc_checksum_2(packet)
    header = IcmpHeader(IcmpType.ECHO_REQUEST, 0, checksum, identifier=identifier, sequence=sequence).to_bytes()
    return header + payload


def create_icmp6_echo_request(identifier: int, sequence: int, payload: bytes) -> bytes:
    """Build ICMPv6 Echo Request packet"""

    header = Icmpv6Header(Icmpv6Type.ECHO_REQUEST, 0, 0, identifier=identifier, sequence=sequence).to_bytes()
    packet = header + payload
    checksum = calc_checksum_2(packet)  # checksum might be wrong?
    header = Icmpv6Header(Icmpv6Type.ECHO_REQUEST, 0, checksum, identifier=identifier, sequence=sequence).to_bytes()
    return header + payload


def pingv4(ip: ipaddress.IPv4Address, sequence: int, payload: bytes, timeout: float | None = None) -> IpStatus:
    host = str(ip)

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    if timeout is not None:
        sock.settimeout(timeout)

    identifier = ICMP_ECHO_IDENTIFIER
    packet = create_icmp_echo_request(identifier, sequence, payload)

    sock.sendto(packet, (host, 0))

    try:
        data, (dest_host, dest_port) = sock.recvfrom(1024)
        # IPv4 headers are included
        icmp_header = IcmpHeader.from_bytes(data[20:28])
        icmp_payload = data[28:]
        if icmp_header.type == IcmpType.ECHO_REPLY:
            if identifier != icmp_header.identifier:
                logger.warning(
                    "ICMP echo reply identifier doesn't match request identifier: %r / %r",
                    identifier,
                    icmp_header.identifier,
                )
            if sequence != icmp_header.sequence:
                logger.warning(
                    "ICMP echo reply sequence doesn't match request sequence: %r / %r", sequence, icmp_header.sequence
                )
            if payload != icmp_payload:
                logger.warning("ICMP echo reply payload doesn't match request payload: %r / %r", payload, icmp_payload)
            return IpStatus.REACHABLE
        elif icmp_header.type == IcmpType.DESTINATION_UNREACHABLE:
            logger.debug(
                "%s: destination unreachable (code=%d: %s)",
                dest_host,
                icmp_header.code,
                DestinationUnreachable(icmp_header.code).name,
            )
            return IpStatus.UNREACHABLE
        else:
            ipv4_header = IPv4Header.from_bytes(data[0:20])
            logger.error(
                "%s: unexpected ICMP response (type=%d: %s)", dest_host, icmp_header.type.value, icmp_header.type.name
            )
            logger.debug("IPv4 header: %s", ipv4_header)
            logger.debug("ICMP header: %s", icmp_header)
            return IpStatus.ERROR

    except TimeoutError:
        return IpStatus.UNREACHABLE


def pingv6(ip: ipaddress.IPv6Address, sequence: int, payload: bytes, timeout: float | None = None) -> IpStatus:
    host = str(ip)

    sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    if timeout is not None:
        sock.settimeout(timeout)

    identifier = ICMP_ECHO_IDENTIFIER
    packet = create_icmp6_echo_request(identifier, sequence, payload)

    sock.sendto(packet, (host, 0))

    try:
        data, addr = sock.recvfrom(1024)
        # IPv6 headers are not included
        icmp_header = Icmpv6Header.from_bytes(data[:8])
        icmp_payload = data[8:]
        if icmp_header.type == Icmpv6Type.ECHO_REPLY:
            if identifier != icmp_header.identifier:
                logger.warning(
                    "ICMPv6 echo reply identifier doesn't match request identifier: %r / %r",
                    identifier,
                    icmp_header.identifier,
                )
            if sequence != icmp_header.sequence:
                logger.warning(
                    "ICMPv6 echo reply sequence doesn't match request sequence: %r / %r", sequence, icmp_header.sequence
                )
            if payload != icmp_payload:
                logger.warning(
                    "ICMPv6 echo reply payload doesn't match request payload: %r / %r", payload, icmp_payload
                )
            return IpStatus.REACHABLE
        else:
            print(addr, icmp_header)
            return IpStatus.ERROR

    except TimeoutError:
        return IpStatus.UNREACHABLE


def ping(ip: IpAddrT, sequence: int = 0, payload: bytes | None = None, timeout: float | None = None) -> IpStatus:
    if payload is None:
        payload = random.randbytes(32)

    if isinstance(ip, ipaddress.IPv4Address):
        return pingv4(ip, sequence, payload, timeout)
    elif isinstance(ip, ipaddress.IPv6Address):
        return pingv6(ip, sequence, payload, timeout)
    else:
        raise ValueError(f"Unsupported IP: {ip}")


def scan(
    ip: IpAddrT,
    port: int,
    scan_type: ScanType,
    timeout: float | None = None,
    src_ip: IpAddrT | None = None,
    src_port: int | None = None,
) -> PortStatus:
    host = str(ip)

    if scan_type == ScanType.TCP_CONNECT:
        if isinstance(ip, ipaddress.IPv4Address):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        elif isinstance(ip, ipaddress.IPv6Address):
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            assert False

        if timeout is not None:
            sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        if result == 0:
            status = PortStatus.OPEN
        elif result in (errno.ECONNREFUSED,):
            status = PortStatus.CLOSED
        elif result in (errno.EAGAIN, errno.EWOULDBLOCK):
            status = PortStatus.FILTERED
        elif result in (errno.ENETUNREACH,):
            status = PortStatus.ERROR
        else:
            logger.warning("TCP connect scan result: %d", result)
            status = PortStatus.FILTERED
        sock.close()
    elif scan_type == ScanType.UDP:
        if isinstance(ip, ipaddress.IPv4Address):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        elif isinstance(ip, ipaddress.IPv6Address):
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        else:
            assert False

        if timeout is not None:
            sock.settimeout(timeout)
        try:
            sock.sendto(b"", (host, port))
            sock.recvfrom(1024)
            status = PortStatus.OPEN
        except TimeoutError:
            status = PortStatus.OPEN_OR_FILTERED  # UDP: no response could mean open or filtered
        except Exception as e:
            print(type(e), e)
            status = PortStatus.FILTERED
        finally:
            sock.close()
    elif scan_type == ScanType.TCP_SYN:
        if not isinstance(ip, ipaddress.IPv4Address) or not isinstance(src_ip, ipaddress.IPv4Address):
            raise ValueError("Only IPv4 is currently supported for TCP SYN scan")

        if src_ip is None:
            raise ValueError("src_ip required for TCP SYN scan")

        if isinstance(ip, ipaddress.IPv4Address):
            # sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)  # IPPROTO_RAW is kinda broken
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        elif isinstance(ip, ipaddress.IPv6Address):
            # sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)  # IPPROTO_RAW is kinda broken
            sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IPV6_HDRINCL, 1)
        else:
            assert False

        if timeout is not None:
            sock.settimeout(timeout)

        if src_port is None:
            src_port = random.randint(49152, 65535)
        packet = make_tcp_packet(b"", src_ip, ip, src_port, port)
        size = sock.sendto(packet, (host, 0))
        assert size == 40

        try:
            # data = sock.recv(1024)
            data, address = sock.recvfrom(1024)
            assert len(data) in (40, 60)
            tcpv4_header = TCPv4Header.from_bytes(data[20:40])
            if tcpv4_header.flags == TcpFlags(syn=1, ack=1):
                status = PortStatus.OPEN
            elif tcpv4_header.flags == TcpFlags(rst=1):
                status = PortStatus.CLOSED
            else:
                ipv4_header = IPv4Header.from_bytes(data[0:20])
                print(address, ipv4_header)
                print(tcpv4_header)
                print("---")
                status = PortStatus.ERROR
        except TimeoutError:
            status = PortStatus.FILTERED
        finally:
            sock.close()
    else:
        raise ValueError(f"Unsupported scan_type {scan_type}")

    return status


def get_source_ip(dest_ip: IpAddrT) -> IpAddrT:
    if isinstance(dest_ip, ipaddress.IPv4Address):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # connect() doesn't send packets in UDP — it's just for setting the local IP
            sock.connect((str(dest_ip), 80))
            return ipaddress.IPv4Address(sock.getsockname()[0])
        finally:
            sock.close()
    elif isinstance(dest_ip, ipaddress.IPv6Address):
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        try:
            # connect() doesn't send packets in UDP — it's just for setting the local IP
            sock.connect((str(dest_ip), 80))
            return ipaddress.IPv6Address(sock.getsockname()[0])
        finally:
            sock.close()
    else:
        raise ValueError(f"Unsupported IP: {dest_ip}")


ScanReturnT = tuple[IpAddrT, int | None, float, PortStatus | IpStatus]


def ping_ips(
    ips: Iterable[IpAddrT], progress: Progress | None = None, timeout: float | None = None
) -> Iterator[ScanReturnT]:
    progress = progress or Progress()

    for host in progress.track(ips, description="IPs", transient=True):
        logger.debug("Pinging %s", host)
        try:
            start_time = time.time()
            status = ping(host, timeout=timeout)
            elapsed = time.time() - start_time
            yield (host, None, elapsed, status)
        except ValueError as e:
            print("ping failed", e)


def ping_hosts(
    hosts: Iterable[str],
    progress: Progress | None = None,
    timeout: float | None = None,
) -> Iterator[ScanReturnT]:
    ips = list(no_dupes(ip for hostname, ip in resolve(hosts)))

    yield from ping_ips(ips, progress, timeout)


def ping_network(
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
    progress: Progress | None = None,
    timeout: float | None = None,
) -> Iterator[ScanReturnT]:
    yield from ping_ips(IterableWithLength(network.hosts(), network.num_addresses), progress, timeout)


def scan_ports_ips(
    ips: Iterable[IpAddrT],
    port_range: tuple[int, int],
    progress: Progress | None = None,
    scan_type: ScanType = ScanType.TCP_CONNECT,
    timeout: float | None = None,
    src_ip: IpAddrT | None = None,
    src_port: int | None = None,
) -> Iterator[ScanReturnT]:
    """
    Yields (host, port, elapsed, status) for each scanned port in the given list of hosts.
    Status is a PortStatus enum: OPEN, OPEN_OR_FILTERED, CLOSED, FILTERED.
    Supports TCP Connect and UDP scanning (set scan_type to ScanType.TCP_CONNECT or ScanType.UDP).
    Optional timeout (in seconds) for socket operations. If None, uses system default.
    If a rich Progress instance is provided, shows nested progress bars per host and per port.
    """
    min_port, max_port = port_range
    num_ports = max_port - min_port + 1
    status: PortStatus | IpStatus
    progress = progress or Progress()

    for host in progress.track(ips, description="IPs"):
        if src_ip is None:
            try:
                src_ip = get_source_ip(host)
            except ValueError as e:
                logger.warning("Skipping %s: %s", host, e)
                continue

        try:
            start_time = time.time()
            status = ping(host, timeout=timeout)
            elapsed = time.time() - start_time
            yield (host, None, elapsed, status)
        except ValueError as e:
            print("ping failed", e)

        with progress.task(num_ports, f"Scanning {host}") as port_task:
            for port in range(min_port, max_port + 1):
                try:
                    start_time = time.time()
                    status = scan(host, port, scan_type, timeout, src_ip, src_port)
                    elapsed = time.time() - start_time
                    yield (host, port, elapsed, status)
                except ValueError as e:
                    print("scan failed", e)
                port_task.advance(1)


def scan_ports_hosts(
    hosts: Iterable[str],
    port_range: tuple[int, int],
    progress: Progress | None = None,
    scan_type: ScanType = ScanType.TCP_CONNECT,
    timeout: float | None = None,
    src_ip: IpAddrT | None = None,
    src_port: int | None = None,
) -> Iterator[ScanReturnT]:
    """
    Yields (host, port, elapsed, status) for each scanned port in the given list of ips.
    Status is a PortStatus enum: OPEN, OPEN_OR_FILTERED, CLOSED, FILTERED.
    Supports TCP Connect and UDP scanning (set scan_type to ScanType.TCP_CONNECT or ScanType.UDP).
    Optional timeout (in seconds) for socket operations. If None, uses system default.
    If a rich Progress instance is provided, shows nested progress bars per host and per port.
    """
    ips = list(no_dupes(ip for hostname, ip in resolve(hosts)))

    yield from scan_ports_ips(ips, port_range, progress, scan_type, timeout, src_ip, src_port)


def scan_ports_network(
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
    port_range: tuple[int, int],
    progress: Progress | None = None,
    scan_type: ScanType = ScanType.TCP_CONNECT,
    timeout: float | None = None,
    src_ip: IpAddrT | None = None,
    src_port: int | None = None,
) -> Iterator[ScanReturnT]:
    """
    Yields (host, port, elapsed, status) for each scanned port in the given ipaddress network.
    Status is a PortStatus enum: OPEN, OPEN_OR_FILTERED, CLOSED, FILTERED.
    Supports TCP Connect and UDP scanning (set scan_type to ScanType.TCP_CONNECT or ScanType.UDP).
    Optional timeout (in seconds) for socket operations. If None, uses system default.
    If a rich Progress instance is provided, shows nested progress bars per host and per port.
    """
    yield from scan_ports_ips(list(network.hosts()), port_range, progress, scan_type, timeout, src_ip, src_port)
