import os
import sys
from pathlib import Path

from pillow_heif import register_heif_opener
from PySide6.QtCore import QObject, Qt, QThread, Signal
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QProgressDialog,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from utils import IMAGE_EXTENSIONS_READ, IMAGE_EXTENSIONS_WRITE, convert_image

register_heif_opener()


class ConverterWorker(QObject):
    progress = Signal(int, str)
    finished = Signal(int)
    error = Signal(str)
    log = Signal(str)

    def __init__(self, input_files, output_dir, dst_ext, use_source_folder):
        super().__init__()
        self.input_files = input_files
        self.output_dir = output_dir
        self.dst_ext = dst_ext
        self.use_source_folder = use_source_folder

    def run(self):
        total = len(self.input_files)
        if total == 0:
            self.finished.emit(0)
            return

        for i, img_path in enumerate(self.input_files):
            try:
                input_path = Path(img_path)
                if self.use_source_folder:
                    output_path = input_path.parent / (input_path.stem + self.dst_ext)
                else:
                    output_path = Path(self.output_dir) / (input_path.stem + self.dst_ext)

                if input_path.resolve() == output_path.resolve():
                    self.log.emit(f"Skipping {img_path}: input and output paths are the same.")
                else:
                    convert_image(input_path, output_path)
            except Exception as e:
                self.error.emit(f"Error processing {img_path}: {str(e)}")
            self.progress.emit(i + 1, input_path.name)

        self.finished.emit(total)


class DropListWidget(QListWidget):
    def __init__(self, extensions: set[str], parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setDragDropMode(QListWidget.InternalMove)
        self.added_paths: set[Path] = set()
        self.extensions: set[str] = extensions

    def _add_path(self, path: Path) -> None:
        assert path.is_file()
        if path not in self.added_paths:
            self.addItem(os.fspath(path))
            self.added_paths.add(path)

    def add_path(self, path: Path) -> None:
        if path.is_dir():
            for subpath in path.iterdir():
                if subpath.is_file() and subpath.suffix.lower() in self.extensions:
                    self._add_path(subpath)
        elif path.is_file() and path.suffix.lower() in self.extensions:
            self._add_path(path)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        if event.mimeData().hasUrls():
            for url in event.mimeData().urls():
                path = Path(url.toLocalFile())
                self.add_path(path)

        event.acceptProposedAction()

    def items(self) -> list[str]:
        return [self.input_list.item(i).text() for i in range(self.input_list.count())]


class ImageConverter(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Batch Image Converter")

        layout = QVBoxLayout()

        self.input_label = QLabel("Input Files or Folders:")
        self.input_path = QLineEdit()
        self.input_add_button = QPushButton("Add Path")
        self.input_add_button.clicked.connect(self.add_input_path)
        self.input_list = DropListWidget(IMAGE_EXTENSIONS_READ)

        input_path_layout = QHBoxLayout()
        input_path_layout.addWidget(self.input_path)
        input_path_layout.addWidget(self.input_add_button)

        layout.addWidget(self.input_label)
        layout.addLayout(input_path_layout)
        layout.addWidget(self.input_list)

        self.output_label = QLabel("Output Folder:")
        self.output_path = QLineEdit()
        self.output_button = QPushButton("Browse...")
        self.output_button.clicked.connect(self.select_output_folder)
        self.use_source_checkbox = QCheckBox("Use source folder")
        self.use_source_checkbox.stateChanged.connect(self.toggle_output_path)

        output_path_layout = QHBoxLayout()
        output_path_layout.addWidget(self.output_path)
        output_path_layout.addWidget(self.output_button)
        output_path_layout.addWidget(self.use_source_checkbox)

        layout.addWidget(self.output_label)
        layout.addLayout(output_path_layout)

        self.dst_ext_label = QLabel("Target Extension:")
        self.dst_ext_combo = QComboBox()
        self.dst_ext_combo.addItems(IMAGE_EXTENSIONS_WRITE)
        layout.addWidget(self.dst_ext_label)
        layout.addWidget(self.dst_ext_combo)

        self.convert_button = QPushButton("Convert Images")
        self.convert_button.clicked.connect(self.convert_images)
        layout.addWidget(self.convert_button)

        self.error_log = QTextEdit()
        self.error_log.setReadOnly(True)
        layout.addWidget(QLabel("Error Log:"))
        layout.addWidget(self.error_log)

        self.setLayout(layout)

    def toggle_output_path(self):
        state = self.use_source_checkbox.isChecked()
        self.output_path.setDisabled(state)
        self.output_button.setDisabled(state)

    def add_input_path(self) -> None:
        path = self.input_path.text()
        if not path:
            return
        self.input_list.add_path(Path(path))

    def select_output_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Output Folder")
        if folder:
            self.output_path.setText(folder)

    def convert_images(self):
        input_files = self.input_list.items()
        use_source = self.use_source_checkbox.isChecked()
        output_dir = self.output_path.text() if not use_source else ""
        dst_ext = self.dst_ext_combo.currentText().lower()

        if not input_files or (not output_dir and not use_source):
            QMessageBox.warning(
                self,
                "Error",
                "Please provide input files and output folder or select 'use source folder'",
            )
            return

        if not use_source:
            Path(output_dir).mkdir(parents=True, exist_ok=True)

        self.progress_dialog = QProgressDialog("Converting images...", "Cancel", 0, len(input_files), self)
        self.progress_dialog.setWindowTitle("Progress")
        self.progress_dialog.setWindowModality(Qt.WindowModal)
        self.progress_dialog.setValue(0)
        self.progress_dialog.show()

        self.error_log.clear()

        self.thread = QThread()
        self.worker = ConverterWorker(input_files, output_dir, dst_ext, use_source)
        self.worker.moveToThread(self.thread)

        self.worker.progress.connect(self.update_progress)
        self.worker.error.connect(self.append_error)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.worker.finished.connect(self.on_finished)

        self.thread.started.connect(self.worker.run)
        self.thread.start()

    def update_progress(self, value, filename):
        self.progress_dialog.setLabelText(f"Processing: {filename}")
        self.progress_dialog.setValue(value)

    def append_error(self, msg):
        self.error_log.append(msg)

    def on_finished(self, total):
        self.progress_dialog.close()
        QMessageBox.information(self, "Done", f"Successfully converted {total} images.")


def main():
    app = QApplication(sys.argv)
    converter = ImageConverter()
    converter.resize(600, 600)
    converter.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
