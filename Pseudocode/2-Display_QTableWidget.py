from PySide6.QtWidgets import QApplication, QWidget, QTableWidget, QTableWidgetItem, QVBoxLayout

class DNSRecordsDialog(QWidget):
    def __init__(self, zone_id, parent=None):
        super().__init__(parent)
        self.zone_id = zone_id

        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Name", "Type", "Content"])

        self.layout = QVBoxLayout(self)
        self.layout.addWidget(self.table)

        self.load_dns_records()

    def load_dns_records(self):
        # Assume dns_records is a list of dictionaries containing record details
        dns_records = [
            {"name": "example.com", "type": "A", "content": "192.0.2.1"},
            {"name": "www.example.com", "type": "CNAME", "content": "example.com"}
        ]

        self.table.setRowCount(len(dns_records))
        for row, record in enumerate(dns_records):
            name_item = QTableWidgetItem(record["name"])
            type_item = QTableWidgetItem(record["type"])
            content_item = QTableWidgetItem(record["content"])
            self.table.setItem(row, 0, name_item)
            self.table.setItem(row, 1, type_item)
            self.table.setItem(row, 2, content_item)

if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    zone_id = "your_zone_id_here"
    dialog = DNSRecordsDialog(zone_id)
    dialog.show()
    sys.exit(app.exec())
