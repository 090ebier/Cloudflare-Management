from PySide6.QtWidgets import QApplication, QWidget, QPushButton, QMessageBox, QLineEdit, QVBoxLayout, QDialog
import requests

class RecordFormDialog(QDialog):
    def __init__(self, zone_id, email, api_key, parent=None):
        super().__init__(parent)
        self.zone_id = zone_id
        self.email = email
        self.api_key = api_key

        self.name_input = QLineEdit()
        self.type_input = QLineEdit()
        self.content_input = QLineEdit()
        self.save_button = QPushButton("Save")
        self.save_button.clicked.connect(self.save_record)

        layout = QVBoxLayout()
        layout.addWidget(self.name_input)
        layout.addWidget(self.type_input)
        layout.addWidget(self.content_input)
        layout.addWidget(self.save_button)
        self.setLayout(layout)

    def save_record(self):
        name = self.name_input.text()
        record_type = self.type_input.text()
        content = self.content_input.text()

        # Perform API call to create DNS record
        try:
            response = requests.post(
                f"https://api.cloudflare.com/client/v4/zones/{self.zone_id}/dns_records",
                json={"type": record_type, "name": name, "content": content},
                headers={
                    'X-Auth-Email': self.email,
                    'X-Auth-Key': self.api_key,
                    'Content-Type': 'application/json'
                }
            )

            if response.status_code == 200:
                QMessageBox.information(self, "Success", "DNS record created successfully")
                self.accept()  # Close dialog on success
            else:
                QMessageBox.warning(self, "Error", "Failed to create DNS record")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    zone_id = "your_zone_id_here"
    email = "your_email_here"
    api_key = "your_api_key_here"
    dialog = RecordFormDialog(zone_id, email, api_key)
    dialog.show()
    sys.exit(app.exec())
