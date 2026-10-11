"""Local interface, route, resolver and explicitly requested connection checks."""

from __future__ import annotations

import ipaddress
import socket
import sys
from pathlib import Path
from queue import Empty, Queue
from threading import Thread

import psutil

from fastvps_doctor.models import CheckStatus, DiagnosticCheck
from fastvps_doctor.runner import safe_hostname


def _has_default_route() -> bool | None:
    if not sys.platform.startswith("linux"):
        return None
    try:
        with Path("/proc/net/route").open("rb") as route_file:
            route_text = route_file.read(16384).decode("ascii", "ignore")
        lines = route_text.splitlines()[1:]
        for line in lines:
            fields = line.split()
            if len(fields) > 3 and fields[1] == "00000000":
                try:
                    flags = int(fields[3], 16)
                except ValueError:
                    continue
                # RTF_UP is bit 0 and RTF_REJECT is bit 9.
                if flags & 0x1 and not flags & 0x200:
                    return True
        return False
    except OSError:
        return None


def _has_ipv6_default_route() -> bool | None:
    if not sys.platform.startswith("linux"):
        return None
    try:
        with Path("/proc/net/ipv6_route").open("rb") as route_file:
            route_text = route_file.read(16384).decode("ascii", "ignore")
        for line in route_text.splitlines():
            fields = line.split()
            if len(fields) < 10 or fields[0] != "0" * 32 or fields[1] != "00":
                continue
            try:
                flags = int(fields[8], 16)
            except ValueError:
                continue
            # Linux IPv6 route flags use RTF_UP (bit 0) and RTF_REJECT (bit 9).
            if flags & 0x1 and not flags & 0x200:
                return True
        return False
    except OSError:
        return None


def collect_network(
    resolve: str | None = None,
    connect: tuple[str, int] | None = None,
    include_addresses: bool = False,
) -> list[DiagnosticCheck]:
    if not sys.platform.startswith("linux"):
        return [
            DiagnosticCheck(
                check_id="network.local",
                category="network",
                status=CheckStatus.SKIPPED,
                summary="Linux interface, route and resolver checks are unavailable on this platform.",
                metrics={
                    "interface_count": None,
                    "interfaces_up": None,
                    "local_ipv4_address_count": None,
                    "local_ipv6_address_count": None,
                    "default_route_present": None,
                    "ipv6_default_route_present": None,
                    "resolver_readable": None,
                    "resolver_nameserver_count": None,
                    "dns_test_requested": resolve is not None,
                    "dns_test_succeeded": None,
                    "dns_test_timed_out": None,
                    "dns_answer_count": None,
                    "tcp_test_requested": connect is not None,
                    "tcp_test_succeeded": None,
                    "tcp_test_timed_out": None,
                },
                note="No network lookup or connection was attempted because this is not Linux.",
            )
        ]
    try:
        stats = psutil.net_if_stats()
        address_data = psutil.net_if_addrs()
        interfaces_available = True
    except (psutil.Error, OSError, RuntimeError):
        stats = {}
        address_data = {}
        interfaces_available = False
    up_count = sum(1 for item in stats.values() if item.isup)
    ipv4_count = sum(
        1
        for entries in address_data.values()
        for address in entries
        if address.family == socket.AF_INET
    )
    ipv6_count = sum(
        1
        for entries in address_data.values()
        for address in entries
        if address.family == socket.AF_INET6
    )
    resolver_count = 0
    resolver_readable = False
    if sys.platform.startswith("linux"):
        try:
            with Path("/etc/resolv.conf").open("rb") as resolver_file:
                resolver_data = resolver_file.read(16384).decode("ascii", "ignore")
            resolver_readable = True
            resolver_count = 0
            for line in resolver_data.splitlines():
                fields = line.partition("#")[0].split()
                if len(fields) < 2 or fields[0].lower() != "nameserver":
                    continue
                try:
                    ipaddress.ip_address(fields[1].split("%", maxsplit=1)[0])
                except ValueError:
                    continue
                resolver_count += 1
        except OSError:
            pass

    route = _has_default_route()
    ipv6_route = _has_ipv6_default_route()
    check_metrics: dict[str, str | int | float | bool | None] = {
        "interface_count": len(stats),
        "interfaces_up": up_count,
        "local_ipv4_address_count": ipv4_count,
        "local_ipv6_address_count": ipv6_count,
        "default_route_present": route,
        "ipv6_default_route_present": ipv6_route,
        "resolver_readable": resolver_readable,
        "resolver_nameserver_count": resolver_count,
        "dns_test_requested": resolve is not None,
        "dns_test_succeeded": None,
        "dns_test_timed_out": None,
        "tcp_test_requested": connect is not None,
        "tcp_test_succeeded": None,
        "tcp_test_timed_out": None,
    }
    if include_addresses:
        address_index = 0
        for interface, entries in address_data.items():
            for address in entries:
                if address.family not in {socket.AF_INET, socket.AF_INET6}:
                    continue
                family = "IPv4" if address.family == socket.AF_INET else "IPv6"
                check_metrics[f"address_{address_index}"] = (
                    f"{interface} {family} {address.address.split('%', maxsplit=1)[0]}"
                )
                address_index += 1
    if resolve:
        hostname = safe_hostname(resolve)
        lookup_result: Queue[int] = Queue(maxsize=1)

        def lookup() -> None:
            try:
                lookup_result.put(len(socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)))
            except (OSError, UnicodeError):
                lookup_result.put(0)

        resolver_thread = Thread(target=lookup, name="fastvps-dns-check", daemon=True)
        resolver_thread.start()
        resolver_thread.join(timeout=3.0)
        if resolver_thread.is_alive():
            check_metrics["dns_test_succeeded"] = None
            check_metrics["dns_test_timed_out"] = True
            check_metrics["dns_answer_count"] = None
        else:
            try:
                answer_count = lookup_result.get_nowait()
            except Empty:
                answer_count = 0
            check_metrics["dns_test_succeeded"] = answer_count > 0
            check_metrics["dns_test_timed_out"] = False
            check_metrics["dns_answer_count"] = min(answer_count, 999)
    if connect:
        hostname, port = connect
        hostname = safe_hostname(hostname)
        if not 1 <= port <= 65535:
            raise ValueError("Port must be between 1 and 65535.")
        connect_result: Queue[bool] = Queue(maxsize=1)

        def connect_once() -> None:
            try:
                with socket.create_connection((hostname, port), timeout=2.0):
                    connect_result.put(True)
            except OSError:
                connect_result.put(False)

        connect_thread = Thread(target=connect_once, name="fastvps-tcp-check", daemon=True)
        connect_thread.start()
        connect_thread.join(timeout=2.0)
        if connect_thread.is_alive():
            check_metrics["tcp_test_succeeded"] = None
            check_metrics["tcp_test_timed_out"] = True
        else:
            try:
                check_metrics["tcp_test_succeeded"] = connect_result.get_nowait()
            except Empty:
                check_metrics["tcp_test_succeeded"] = False
            check_metrics["tcp_test_timed_out"] = False

    route_found = route is True or ipv6_route is True
    route_missing = route is False and ipv6_route is False
    route_inconclusive = not route_found and not route_missing
    if not interfaces_available or (route_inconclusive or not resolver_readable):
        status = CheckStatus.UNKNOWN
    elif (
        (up_count == 0)
        or route_missing
        or (resolver_readable and resolver_count == 0)
        or check_metrics.get("dns_test_succeeded") is False
        or check_metrics.get("dns_test_timed_out") is True
        or check_metrics.get("tcp_test_succeeded") is False
        or check_metrics.get("tcp_test_timed_out") is True
    ):
        status = CheckStatus.WARNING
    else:
        status = CheckStatus.PASS
    return [
        DiagnosticCheck(
            check_id="network.local",
            category="network",
            status=status,
            summary="Collected local interface, route and resolver indicators."
            if interfaces_available
            else "Local interface information could not be read.",
            metrics=check_metrics,
            note=(
                "Local addresses are shown only with --show-addresses and are excluded from support reports."
                if include_addresses
                else "Hostname resolution and TCP checks run only when the user supplies one destination."
            ),
        )
    ]


def collect_listeners(ports: set[int] | None = None) -> DiagnosticCheck:
    watched = ports if ports is not None else {22, 53, 80, 443, 3306, 5432, 6379, 8080}
    if any(
        not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535
        for port in watched
    ):
        raise ValueError("Listener ports must be integers between 1 and 65535.")
    if not sys.platform.startswith("linux"):
        return DiagnosticCheck(
            check_id="network.listeners",
            category="network",
            status=CheckStatus.SKIPPED,
            summary="Linux listening-port inventory is unavailable on this platform.",
            metrics={f"port_{port}_listeners": None for port in watched},
            note="Use a supported Linux VPS to inspect local listeners.",
        )
    try:
        connections = psutil.net_connections(kind="inet")
        counts: dict[int, int | None] = {port: 0 for port in watched}
        for connection in connections:
            if connection.status == psutil.CONN_LISTEN and connection.laddr:
                local_port = connection.laddr.port
                current_count = counts.get(local_port)
                if current_count is not None:
                    counts[local_port] = current_count + 1
        status = CheckStatus.PASS
        note = None
    except (psutil.Error, OSError, RuntimeError):
        counts = {port: None for port in watched}
        status = CheckStatus.SKIPPED
        note = "The operating system did not permit a local listening-port inventory."
    return DiagnosticCheck(
        check_id="network.listeners",
        category="network",
        status=status,
        summary="Counted local listeners on selected common ports."
        if status == CheckStatus.PASS
        else "Local listener inventory was unavailable.",
        metrics={f"port_{port}_listeners": count for port, count in counts.items()},
        note=note,
    )
