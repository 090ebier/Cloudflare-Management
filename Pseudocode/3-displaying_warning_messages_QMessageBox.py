from PySide6.QtWidgets import QApplication, QWidget, QPushButton, QMessageBox, QVBoxLayout

class SSLSettingsDialog(QWidget):
    def __init__(self, zone_id, parent=None):
        super().__init__(parent)
        self.zone_id = zone_id

        self.button = QPushButton("Update SSL Settings")
        self.button.clicked.connect(self.show_success_message)

        self.layout = QVBoxLayout(self)
        self.layout.addWidget(self.button)

    def show_success_message(self):
        QMessageBox.information(self, "Success", "SSL Settings updated successfully")

if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    zone_id = "your_zone_id_here"
    dialog = SSLSettingsDialog(zone_id)
    dialog.show()
    sys.exit(app.exec())
