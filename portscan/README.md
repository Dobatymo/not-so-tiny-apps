# Portscanner

A simple Python port scanner with both CLI and GUI interfaces.

## Features
- Scan a range of ports on one or more hosts
- Command-line interface with progress bars (using rich)
- PySide6 GUI with real-time results and cancel support

## Installation

1. Install dependencies (in a virtual environment is recommended):
   ```sh
   pip install .
   # or, if running from source:
   pip install -r requirements.txt
   ```
   (Dependencies: `pyside6`, `rich`)

2. (Optional) Install as a script:
   ```sh
   pip install .
   ```

## Usage

### CLI
Run from the command line:
```sh
portscanner-cli --hosts 127.0.0.1 192.168.1.1 --min-port 1 --max-port 1024
```

### GUI
Run the GUI:
```sh
portscanner-gui
```

Or, if running from source:
```sh
python -m portscanner.gui
```

---
Licensed under the Mozilla Public License 2.0 (MPLv2).
