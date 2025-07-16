import logging
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from pillow_heif import register_heif_opener
from PySide6.QtCore import QObject, Qt, QThread, Signal
from PySide6.QtGui import QKeyEvent
from PySide6.QtWidgets import (
    QAbstractItemView,
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

from .shared import IMAGE_EXTENSIONS_READ, IMAGE_EXTENSIONS_WRITE, convert_image

logger = logging.getLogger(__name__)

register_heif_opener()


class ConverterWorker(QObject):
    progress = Signal(int, str)
    finished = Signal(int)
    log = Signal(str)

    def __init__(self, input_files: Sequence[Path], output_dir: Path | None, dst_ext, use_source_folder: bool):
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

        for i, input_path in enumerate(self.input_files):
            try:
                if self.use_source_folder:
                    output_path = input_path.parent / (input_path.stem + self.dst_ext)
                else:
                    output_path = Path(self.output_dir) / (input_path.stem + self.dst_ext)

                if input_path.resolve() == output_path.resolve():
                    self.log.emit(f"Skipping {input_path}: input and output paths are the same.")
                else:
                    convert_image(input_path, output_path)
            except Exception as e:
                self.log.emit(f"Error processing {input_path}: {str(e)}")
                logger.exception("Error processing %s", input_path)

            self.progress.emit(i + 1, input_path.name)

        self.finished.emit(total)


class DropListWidget(QListWidget):
    def __init__(self, extensions: set[str], parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setDragDropMode(QListWidget.DragDropMode.InternalMove)
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
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

    def items(self) -> list[Path]:
        return [Path(self.item(i).text()) for i in range(self.count())]

    def keyPressEvent(self, event: QKeyEvent):
        if event.key() == Qt.Key.Key_Delete:
            for item in self.selectedItems():
                self.added_paths.discard(Path(item.text()))
                self.takeItem(self.row(item))
        else:
            super().keyPressEvent(event)


class ImageConverter(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Batch Image Converter")

        layout = QVBoxLayout()

        self.input_label = QLabel("Input Files or Folders:")

        # New input buttons
        self.add_dirs_button = QPushButton("Add files from directory")
        self.add_dirs_button.clicked.connect(self.add_from_directory)
        self.add_dirs_button.setToolTip("Add all image files from a selected directory.")

        self.add_files_button = QPushButton("Add files")
        self.add_files_button.clicked.connect(self.add_files)
        self.add_files_button.setToolTip("Add individual image files to the input list.")

        self.add_from_file_button = QPushButton("Add files from file")
        self.add_from_file_button.clicked.connect(self.add_from_file)
        self.add_from_file_button.setToolTip("Add image files listed in a text file (one path per line).")

        self.input_clear_button = QPushButton("Clear")
        self.input_clear_button.clicked.connect(self.clear_input_list)
        self.input_clear_button.setToolTip("Clear all files from the input list.")

        input_buttons_layout = QHBoxLayout()
        input_buttons_layout.addWidget(self.add_dirs_button)
        input_buttons_layout.addWidget(self.add_files_button)
        input_buttons_layout.addWidget(self.add_from_file_button)
        input_buttons_layout.addWidget(self.input_clear_button)

        self.input_ext_label = QLabel("Input Extension Filter:")
        self.input_ext_combo = QComboBox()
        self.input_ext_combo.addItem("All")
        for ext in sorted(IMAGE_EXTENSIONS_READ):
            self.input_ext_combo.addItem(ext)
        self.input_ext_combo.currentTextChanged.connect(self.update_input_extension_filter)

        self.input_list = DropListWidget(set(IMAGE_EXTENSIONS_READ))
        self.input_list.setToolTip("You can drag and drop files or folders here to add them to the list.")

        # Add extension filter above the input list
        ext_filter_layout = QHBoxLayout()
        ext_filter_layout.addWidget(self.input_ext_label)
        ext_filter_layout.addWidget(self.input_ext_combo)

        layout.addWidget(self.input_label)
        layout.addLayout(input_buttons_layout)
        layout.addLayout(ext_filter_layout)
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

        self.error_count = 0

        self.setLayout(layout)

    def toggle_output_path(self):
        state = self.use_source_checkbox.isChecked()
        self.output_path.setDisabled(state)
        self.output_button.setDisabled(state)

    def add_from_directory(self):
        dialog = QFileDialog(self, "Select Directory")
        dialog.setFileMode(QFileDialog.FileMode.Directory)
        dialog.setOption(QFileDialog.Option.ShowDirsOnly, True)

        if dialog.exec():
            dirs = dialog.selectedFiles()
            for d in dirs:
                self.input_list.add_path(Path(d))

    def add_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select Files")
        for f in files:
            self.input_list.add_path(Path(f))

    def add_from_file(self):
        file, _ = QFileDialog.getOpenFileName(
            self, "Select Text File with Paths", filter="Text Files (*.txt);;All Files (*)"
        )
        if file:
            try:
                with open(file, encoding="utf-8") as fr:
                    for line in fr:
                        path = Path(line.strip())
                        self.input_list.add_path(path)
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Error reading file {file}: {str(e)}")

    def select_output_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Output Folder")
        if folder:
            self.output_path.setText(folder)

    def convert_images(self):
        input_files = self.input_list.items()
        use_source = self.use_source_checkbox.isChecked()
        output_dir = Path(self.output_path.text()) if not use_source else None
        dst_ext = self.dst_ext_combo.currentText().lower()

        if not input_files or (output_dir is None and not use_source):
            QMessageBox.warning(
                self,
                "Error",
                "Please provide input files and output folder or select 'use source folder'",
            )
            return

        if output_dir is not None:
            output_dir.mkdir(parents=True, exist_ok=True)

        self.progress_dialog = QProgressDialog("Converting images...", "Cancel", 0, len(input_files), self)
        self.progress_dialog.setWindowTitle("Progress")
        self.progress_dialog.setWindowModality(Qt.WindowModal)
        self.progress_dialog.setValue(0)
        self.progress_dialog.show()

        self.error_log.clear()
        self.error_count = 0

        self.worker_thread = QThread()
        self.worker = ConverterWorker(input_files, output_dir, dst_ext, use_source)
        self.worker.moveToThread(self.worker_thread)

        self.worker.progress.connect(self.update_progress)
        self.worker.log.connect(self.append_error)
        self.worker.finished.connect(self.worker_thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.worker_thread.finished.connect(self.worker_thread.deleteLater)
        self.worker.finished.connect(self.on_finished)

        self.worker_thread.started.connect(self.worker.run)
        self.worker_thread.start()

    def update_progress(self, value, filename):
        self.progress_dialog.setLabelText(f"Processing: {filename}")
        self.progress_dialog.setValue(value)

    def append_error(self, msg):
        self.error_log.append(msg)
        self.error_count += 1

    def on_finished(self, total):
        self.progress_dialog.close()
        success_count = total - self.error_count
        QMessageBox.information(
            self, "Done", f"Successfully converted {success_count} images. Failed: {self.error_count} images."
        )

    def update_input_extension_filter(self):
        selected = self.input_ext_combo.currentText()
        if selected == "All":
            self.input_list.extensions = set(IMAGE_EXTENSIONS_READ)
        else:
            self.input_list.extensions = {selected}

    def clear_input_list(self):
        self.input_list.clear()
        self.input_list.added_paths.clear()


def main():
    app = QApplication(sys.argv)
    converter = ImageConverter()
    converter.resize(600, 600)
    converter.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
