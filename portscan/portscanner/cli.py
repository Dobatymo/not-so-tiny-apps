import argparse
import errno
import ipaddress
import logging

from genutility.rich import Progress
from rich.logging import RichHandler
from rich.progress import Progress as RichProgress

from portscanner.shared import (
    IpStatus,
    PortStatus,
    ScanType,
    is_valid_hostname,
    ping_hosts,
    ping_ips,
    ping_network,
    scan_ports_hosts,
    scan_ports_ips,
    scan_ports_network,
)


def arg_network(s: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    try:
        return ipaddress.ip_network(s, strict=False)
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"Invalid subnet: {e}") from None


def arg_host(s: str) -> str:
    if is_valid_hostname(s):
        return s

    raise argparse.ArgumentTypeError(f"Invalid hostname: {s}") from None


def main():
    parser = argparse.ArgumentParser(description="Port Scanner CLI")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--subnet",
        type=arg_network,
        help="Subnet to scan in CIDR notation (e.g. 192.168.1.0/24)",
    )
    group.add_argument(
        "--ips",
        type=ipaddress.ip_address,
        nargs="+",
        help="List of IP addresses to scan (e.g. 192.168.1.10 192.168.1.11)",
    )
    group.add_argument(
        "--hosts",
        type=arg_host,
        nargs="+",
        help="List of hostnames to scan (e.g. example.com localhost)",
    )
    parser.add_argument("--min-port", type=int, default=1, help="Minimum port number")
    parser.add_argument("--max-port", type=int, default=65535, help="Maximum port number")
    parser.add_argument(
        "--scan-type",
        choices=[s.name.lower() for s in ScanType],
        default=ScanType.TCP_SYN.name.lower(),
        help="Scan type",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="Socket timeout in seconds (default: system default)",
    )
    parser.add_argument(
        "--src-ip",
        type=ipaddress.ip_address,
        help="Source IP to be used for scanning for supported scan types. If the IP is not correct, the scan might not receive a response and timeout. Usually the source IP is determined by the OS.",
    )
    parser.add_argument(
        "--src-port",
        type=int,
        help="Source port to be used for scanning for supported scan types. Usually a random high digit port will be used.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug output",
    )
    args = parser.parse_args()

    FORMAT = "%(message)s"
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format=FORMAT, handlers=[RichHandler()])
    else:
        logging.basicConfig(level=logging.INFO, format=FORMAT, handlers=[RichHandler()])

    min_port = args.min_port
    max_port = args.max_port
    scan_type = args.scan_type
    timeout = args.timeout

    scan_type = ScanType[scan_type.upper()]

    with RichProgress() as p:
        progress = Progress(p)
        try:
            if scan_type == ScanType.ICMP_ECHO:
                if args.subnet:
                    scan_iter = ping_network(
                        args.subnet,
                        progress=progress,
                        timeout=timeout,
                    )
                elif args.ips:
                    scan_iter = ping_ips(
                        args.ips,
                        progress=progress,
                        timeout=timeout,
                    )
                elif args.hosts:
                    scan_iter = ping_hosts(
                        args.hosts,
                        progress=progress,
                        timeout=timeout,
                    )
                else:
                    parser.error("You must specify one of --subnet, --ips, or --hosts.")
            else:
                if args.subnet:
                    scan_iter = scan_ports_network(
                        args.subnet,
                        (min_port, max_port),
                        progress=progress,
                        scan_type=scan_type,
                        timeout=timeout,
                        src_ip=args.src_ip,
                        src_port=args.src_port,
                    )
                elif args.ips:
                    scan_iter = scan_ports_ips(
                        args.ips,
                        (min_port, max_port),
                        progress=progress,
                        scan_type=scan_type,
                        timeout=timeout,
                        src_ip=args.src_ip,
                        src_port=args.src_port,
                    )
                elif args.hosts:
                    scan_iter = scan_ports_hosts(
                        args.hosts,
                        (min_port, max_port),
                        progress=progress,
                        scan_type=scan_type,
                        timeout=timeout,
                        src_ip=args.src_ip,
                        src_port=args.src_port,
                    )
                else:
                    parser.error("You must specify one of --subnet, --ips, or --hosts.")

            last_host = None
            for host, port, elapsed, status in scan_iter:
                if host != last_host:
                    progress.print(f"[bold]Results for {host}:[/bold]")
                    last_host = host
                if status == PortStatus.OPEN:
                    status_str = "[green]open[/green]"
                elif status == PortStatus.OPEN_OR_FILTERED:
                    status_str = "[yellow]open or filtered[/yellow]"
                elif status == PortStatus.CLOSED:
                    status_str = "[red]closed[/red]"
                elif status == PortStatus.FILTERED:
                    status_str = "[magenta]filtered[/magenta]"
                elif status == IpStatus.REACHABLE:
                    status_str = "[green]reachable[/green]"
                elif status == IpStatus.UNREACHABLE:
                    status_str = "[red]unreachable[/red]"
                else:
                    status_str = f"[white]{status.name.lower()}[/white]"

                if port is None:
                    progress.print(f"  Ping {status_str} (scanned in {elapsed:.4f}s)")
                else:
                    progress.print(f"  Port {port}: {status_str} (scanned in {elapsed:.4f}s)")

        except PermissionError as e:
            if e.winerror == errno.WSAEACCES:
                progress.print(f"[red]Admin right are required for scan-type {args.scan_type}: {e}")
            else:
                raise
        except OSError as e:
            if e.errno == errno.ENETUNREACH:
                logging.exception(f"[red]Unreachable network. Maybe IPv6 is not supported: {e}", extra={"markup": True})
            else:
                raise
        except KeyboardInterrupt:
            progress.print("[red]KeyboardInterrupt")


if __name__ == "__main__":
    main()
