import ipaddress
import sys
from collections.abc import Sequence

from PySide6.QtCore import QObject, QThread, Signal
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from portscanner.shared import PortStatus, ScanType, scan_ports_hosts


class ScanWorker(QObject):
    result_signal = Signal(str, int, float, PortStatus)
    finished_signal = Signal()

    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    port_range: tuple[int, int]
    scan_type: ScanType
    timeout: float | None
    _is_running: bool

    def __init__(
        self,
        hosts: Sequence[str],
        port_range: tuple[int, int],
        scan_type: ScanType,
        timeout: float | None,
    ) -> None:
        super().__init__()
        self.hosts = hosts
        self.port_range = port_range
        self.scan_type = scan_type
        self.timeout = timeout
        self._is_running = True

    def run(self) -> None:
        for host, port, elapsed, status in scan_ports_hosts(
            self.hosts,
            self.port_range,
            progress=None,
            scan_type=self.scan_type,
            timeout=self.timeout,
        ):
            self.result_signal.emit(host, port, elapsed, status)
            if not self._is_running:
                break
        self.finished_signal.emit()

    def stop(self) -> None:
        self._is_running = False


class PortScannerGUI(QWidget):
    worker: ScanWorker | None
    thread: QThread | None
    last_host: str | None

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Port Scanner GUI")
        self.layout = QVBoxLayout()

        self.subnet_label = QLabel("Subnet (CIDR, e.g. 192.168.1.0/24):")
        self.subnet_input = QLineEdit()
        self.layout.addWidget(self.subnet_label)
        self.layout.addWidget(self.subnet_input)

        port_layout = QHBoxLayout()
        self.min_port_label = QLabel("Min Port:")
        self.min_port_input = QSpinBox()
        self.min_port_input.setRange(1, 65535)
        self.min_port_input.setValue(1)
        self.max_port_label = QLabel("Max Port:")
        self.max_port_input = QSpinBox()
        self.max_port_input.setRange(1, 65535)
        self.max_port_input.setValue(1024)
        port_layout.addWidget(self.min_port_label)
        port_layout.addWidget(self.min_port_input)
        port_layout.addWidget(self.max_port_label)
        port_layout.addWidget(self.max_port_input)
        self.layout.addLayout(port_layout)

        proto_layout = QHBoxLayout()
        self.scantype_label = QLabel("Scan type:")
        self.scantype_combo = QComboBox()
        self.scantype_combo.addItems([i.value for i in ScanType])
        proto_layout.addWidget(self.scantype_label)
        proto_layout.addWidget(self.scantype_combo)
        self.timeout_label = QLabel("Timeout (s, blank=default):")
        self.timeout_input = QLineEdit()
        proto_layout.addWidget(self.timeout_label)
        proto_layout.addWidget(self.timeout_input)
        self.layout.addLayout(proto_layout)

        button_layout = QHBoxLayout()
        self.scan_button = QPushButton("Scan")
        self.scan_button.clicked.connect(self.run_scan)
        button_layout.addWidget(self.scan_button)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self.cancel_scan)
        button_layout.addWidget(self.cancel_button)
        self.layout.addLayout(button_layout)

        self.results = QTextEdit()
        self.results.setReadOnly(True)
        self.layout.addWidget(self.results)

        self.setLayout(self.layout)
        self.thread = None
        self.worker = None
        self.last_host = None

    def run_scan(self) -> None:
        network_str = self.subnet_input.text().strip()
        if network_str:
            if "/" in network_str:
                try:
                    network = ipaddress.ip_network(network_str, strict=False)
                except ValueError as e:
                    QMessageBox.warning(self, "Invalid subnet", f"Invalid subnet: {e}")
                    return
                hosts = [str(ip) for ip in network.hosts()]
            else:
                hosts = network_str.split(",")
        else:
            network = ipaddress.ip_network("127.0.0.1/32")
            hosts = [str(ip) for ip in network.hosts()]

        min_port = self.min_port_input.value()
        max_port = self.max_port_input.value()
        scan_type = ScanType(self.scantype_combo.currentText())

        timeout_str = self.timeout_input.text().strip()
        if timeout_str:
            try:
                timeout = float(timeout_str)
            except ValueError:
                QMessageBox.warning(
                    self,
                    "Invalid timeout",
                    f"Invalid timeout: {self.timeout_input.text().strip()}",
                )
                return
        else:
            timeout = None

        if not hosts:
            self.results.setText("No hosts found.")
            return

        self.results.clear()
        self.last_host = None
        self.scan_button.setEnabled(False)
        self.cancel_button.setEnabled(True)

        self.thread = QThread()
        self.worker = ScanWorker(hosts, (min_port, max_port), scan_type, timeout)
        self.worker.moveToThread(self.thread)
        self.worker.result_signal.connect(self.handle_result)
        self.worker.finished_signal.connect(self.scan_finished)
        self.thread.started.connect(self.worker.run)
        self.thread.start()

    def cancel_scan(self) -> None:
        if self.worker is not None:
            self.worker.stop()
        self.cancel_button.setEnabled(False)

    def handle_result(self, host: str, port: int, elapsed: float, status: PortStatus) -> None:
        if host != self.last_host:
            self.results.append(f"Results for {host}:")
            self.last_host = host
        if status == PortStatus.OPEN:
            status_str = '<span style="color:green;">open</span>'
        elif status == PortStatus.OPEN_OR_FILTERED:
            status_str = '<span style="color:orange;">open or filtered</span>'
        elif status == PortStatus.CLOSED:
            status_str = '<span style="color:red;">closed</span>'
        elif status == PortStatus.FILTERED:
            status_str = '<span style="color:magenta;">filtered</span>'
        else:
            status_str = f'<span style="color:gray;">{status.name.lower()}</span>'
        self.results.append(f"  Port {port}: {status_str} (scanned in {elapsed:.4f}s)")

    def scan_finished(self) -> None:
        self.results.append("")
        self.scan_button.setEnabled(True)
        self.cancel_button.setEnabled(False)

        if self.thread is not None:
            assert self.worker is not None

            self.thread.quit()
            self.thread.wait()
            self.thread = None
            self.worker = None

    def closeEvent(self, event):
        if self.worker is not None:
            self.worker.stop()
        if self.thread is not None:
            self.thread.quit()
            self.thread.wait()
            self.thread = None
            self.worker = None
        event.accept()


def main():
    app = QApplication(sys.argv)
    window = PortScannerGUI()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
