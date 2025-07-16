import errno
import ipaddress
import logging
import os
import random
import re
import socket
import time
from collections.abc import Iterator, Sequence
from enum import Enum, auto
from struct import calcsize, pack, unpack
from typing import Self

from genutility.callbacks import Progress
from genutility.iter import no_dupes
from scapy.all import IP_PROTOS

IpAddrT = ipaddress.IPv4Address | ipaddress.IPv6Address

logger = logging.getLogger(__name__)


class PortStatus(Enum):
    OPEN = auto()
    OPEN_OR_FILTERED = auto()
    CLOSED = auto()
    FILTERED = auto()
    ERROR = auto()


class IpStatus(Enum):
    AVAILABLE = auto()
    UNAVAILABLE = auto()
    ERROR = auto()


class ScanType(Enum):
    TCP_SYN = "TCP SYN Scan"
    TCP_CONNECT = "TCP Connect Scan"
    UDP = "UDP Scan"


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


class IPv4Header:
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
        protocol=IP_PROTOS.tcp,
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
            self.protocol,
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
            protocol,
            header_checksum,
        )

    def __repr__(self):
        d = {name: getattr(self, name) for name in self.__slots__}

        try:
            d["protocol"] = IP_PROTOS[d["protocol"]]
        except KeyError:
            d["protocol"] = f"UNKNOWN({d['protocol']})"

        args = ", ".join(f"{k}={v}" for k, v in d.items())
        return f"IPv4Header({args})"


def resolve(hosts: Sequence[str]) -> Iterator[tuple[str, IpAddrT]]:
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


class TCPv4Header:
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

    def __len__(self) -> int:
        return calcsize("HHLLBBHHH")

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


class IcmpHeader:
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
        identifier: int | None = None,
        sequence: int | None = None,
    ):
        self.type = icmp_type
        self.code = code
        self.checksum = checksum
        self.identifier = identifier
        self.sequence = sequence

    def to_bytes(self) -> bytes:
        if self.type == IcmpType.ECHO_REQUEST:
            assert self.identifier is not None
            assert self.sequence is not None
            return pack("!BBHHH", self.type.value, self.code, self.checksum, self.identifier, self.sequence)
        else:
            raise ValueError(f"Unsupported type: {self.type}")

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        _type, code, checksum, rest = unpack("!BBH4s", data)

        icmp_type = IcmpType(_type)

        if icmp_type in (IcmpType.ECHO_REQUEST, IcmpType.ECHO_REPLY):
            identifier, sequence = unpack("!HH", rest)
            return cls(icmp_type, code, checksum, identifier, sequence)
        else:
            raise ValueError(f"Unsupported type: {icmp_type}")

    def __repr__(self):
        d = {name: getattr(self, name) for name in self.__slots__}

        args = ", ".join(f"{k}={v}" for k, v in d.items() if v is not None)
        return f"IcmpHeader({args})"


def create_icmp_echo_request(identifier: int, sequence: int, payload: bytes) -> bytes:
    """Build ICMP Echo Request packet"""

    header = IcmpHeader(IcmpType.ECHO_REQUEST, 0, 0, identifier, sequence).to_bytes()
    packet = header + payload
    checksum = calc_checksum_2(packet)
    header = IcmpHeader(IcmpType.ECHO_REQUEST, 0, checksum, identifier, sequence).to_bytes()
    return header + payload


def ping(ip: IpAddrT, timeout: float | None = None) -> IpStatus:
    host = str(ip)

    if isinstance(ip, ipaddress.IPv4Address):
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        if timeout is not None:
            sock.settimeout(timeout)

        # Packet parameters
        identifier = os.getpid() & 0xFFFF
        sequence = 1
        payload = b"hello from raw ICMP"  # any payload

        packet = create_icmp_echo_request(identifier, sequence, payload)
    else:
        raise ValueError(f"Unsupported IP: {ip}")

    sock.sendto(packet, (host, 0))

    try:
        data, addr = sock.recvfrom(1024)
        ipv4_header = IPv4Header.from_bytes(data[0:20])
        icmp_header = IcmpHeader.from_bytes(data[20:28])
        if icmp_header.type == IcmpType.ECHO_REPLY:
            return IpStatus.AVAILABLE
        else:
            print(addr, ipv4_header, icmp_header)
            return IpStatus.ERROR
    except TimeoutError:
        return IpStatus.UNAVAILABLE


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
        elif result in (errno.EAGAIN,):
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
            # sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        elif isinstance(ip, ipaddress.IPv6Address):
            # sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
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


def scan_ports_ips(
    ips: Sequence[IpAddrT],
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

    with progress.task(len(ips), "IPs") as host_task:
        for host in ips:
            if src_ip is None:
                try:
                    src_ip = get_source_ip(host)
                except ValueError as e:
                    logger.warning("Skipping %s: %s", host, e)
                    if progress is not None:
                        host_task.advance(1)
                    continue

            try:
                start_time = time.time()
                status = ping(host, timeout)
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

            host_task.advance(1)


def scan_ports_hosts(
    hosts: Sequence[str],
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
