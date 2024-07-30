from PySide6.QtWidgets import QApplication, QWidget, QPushButton, QFileDialog, QVBoxLayout, QMessageBox

class FileSelectionDialog(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.selected_file = None
        self.select_button = QPushButton("Select File")
        self.select_button.clicked.connect(self.select_file)

        layout = QVBoxLayout()
        layout.addWidget(self.select_button)
        self.setLayout(layout)

    def select_file(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "Select File", "", "All Files (*)", options=options)
        if file_name:
            self.selected_file = file_name
            QMessageBox.information(self, "File Selected", f"Selected File: {file_name}")

if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    dialog = FileSelectionDialog()
    dialog.show()
    sys.exit(app.exec())
