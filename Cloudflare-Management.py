from PySide6.QtCore import Qt, QSize, QEvent, QPoint, QTimer
import os
import sys
import requests
import winreg
import ctypes
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton,
    QMessageBox, QListWidget, QListWidgetItem, QDialog, QHBoxLayout,
    QComboBox, QCheckBox, QFormLayout, QInputDialog, QTableWidget, QHeaderView, QTableWidgetItem, QStackedWidget, QGroupBox, QSpacerItem, QSizePolicy, QToolTip, QFileDialog, QPlainTextEdit, QDialogButtonBox, QAbstractItemView, QMenu, QScrollBar
)
import qdarktheme
from PySide6.QtGui import QFont, QIcon, QCursor, QAction, QPalette
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography import x509


class CloudflareApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowFlags(
            self.windowFlags() | Qt.WindowMinimizeButtonHint | Qt.WindowMaximizeButtonHint)
        self.setWindowTitle("Cloudflare Management")
        self.setGeometry(300, 300, 500, 350)

        current_dir = os.path.dirname(os.path.realpath(__file__))
        icon_path = os.path.join(current_dir, 'icons', 'icon.png')

        icon = QIcon(icon_path)
        self.setWindowIcon(icon)
        self.show_tooltips = True
        main_layout = QVBoxLayout()

        login_group = QGroupBox("Login Option")
        login_layout = QVBoxLayout()

        self.email_label = QLabel("Email :")
        self.email_input = QLineEdit()
        self.email_input.setToolTip("Enter your Cloudflare Email")
        self.email_input.installEventFilter(self)
        self.email_input.setReadOnly(False)  
        login_layout.addWidget(self.email_label)
        login_layout.addWidget(self.email_input)

        self.api_key_label = QLabel("API Key :")
        self.api_key_input = QLineEdit()
        self.api_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.api_key_input.setToolTip(
            "1. Log in to the Cloudflare dashboard and go to User Profile > API Tokens.\n"
            "2. In the API Keys section, click View button of Global API Key.")
        self.api_key_input.installEventFilter(self)
        self.api_key_input.setReadOnly(False)  
        login_layout.addWidget(self.api_key_label)
        login_layout.addWidget(self.api_key_input)

        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.login)
        login_layout.addWidget(self.login_button)

        login_group.setLayout(login_layout)
        main_layout.addWidget(login_group)

        domain_group = QGroupBox("Domain Options")
        domain_layout = QVBoxLayout()

        self.domain_list_button = QPushButton("Domain List")
        self.domain_list_button.clicked.connect(self.show_domain_list)
        self.domain_list_button.setEnabled(False)
        domain_layout.addWidget(self.domain_list_button)

        self.add_domain_button = QPushButton("Add New Domain")
        self.add_domain_button.clicked.connect(self.add_domain)
        self.add_domain_button.setEnabled(False)
        domain_layout.addWidget(self.add_domain_button)

        domain_group.setLayout(domain_layout)
        main_layout.addWidget(domain_group)

        self.setLayout(main_layout)

        self.email = None
        self.api_key = None
        self.origin_ca_key = None
        self.show_tooltips = True
        self.dark_mode = self.is_dark_mode()
        self.apply_stylesheet(self.dark_mode)

        self.timer = QTimer()
        self.timer.timeout.connect(self.check_for_theme_change)
        self.timer.start(1000)  

    def is_dark_mode(self):
        try:
            registry = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)
            key = winreg.OpenKey(
                registry, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize')
            value, regtype = winreg.QueryValueEx(key, 'AppsUseLightTheme')
            winreg.CloseKey(key)
            return value == 0
        except Exception:
            return False

    def apply_stylesheet(self, dark_mode):
        if dark_mode:
            self.setStyleSheet(qdarktheme.load_stylesheet("dark") + """
                /* Custom styles for buttons */
                QGroupBox::title {
                    subcontrol-origin: margin;
                    subcontrol-position: top center;
                    padding: 0 3px;
                    background-color: #404040;
                    color: #f0f0f0;
                    border: 1px solid #404040;
                    border-top-left-radius: 5px;
                    border-top-right-radius: 5px;
                }
                QPushButton {
                    background-color: #ff8800;
                    border: none;
                    color: #ffffff;
                    padding: 8px 16px;
                    border-radius: 8px;
                    font-weight: bold;
                    font-size: 12px;
                }
                QPushButton:disabled {
                    background-color: #333333;
                    color: #888888;
                }
                QPushButton:hover {
                    background-color: #ff9900;
                }
                QLabel {
                    border-radius: 8px;
                    font-weight: bold;
                    font-size: 12px;
                }
                QComboBox {
                    background-color: #404040;
                    border: 1px solid #555555;
                    border-radius: 5px;
                    color: #f0f0f0;
                    padding: 5px;
                }
                QComboBox QAbstractItemView {
                    background-color: #404040;
                    border: 1px solid #555555;
                    selection-background-color: #555555;
                    color: #f0f0f0;
                }
                QCheckBox {
                    color: #f0f0f0;
                }
                QCheckBox::indicator {
                    width: 16px;
                    height: 16px;
                }
                QCheckBox::indicator:unchecked {
                    border: 1px solid #555555;
                    background-color: #404040;
                }
            """)
        else:
            self.setStyleSheet(qdarktheme.load_stylesheet("light") + """
                /* Custom styles for buttons */
                QGroupBox::title {
                    subcontrol-origin: margin;
                    subcontrol-position: top center;
                    padding: 0 3px;
                    background-color: #e0e0e0;
                    color: #404040;
                    border: 1px solid #e0e0e0;
                    border-top-left-radius: 5px;
                    border-top-right-radius: 5px;
                }
                QPushButton {
                    background-color: #ff8800;
                    border: none;
                    color: #ffffff;
                    padding: 8px 16px;
                    border-radius: 8px;
                    font-weight: bold;
                    font-size: 12px;
                }
                QPushButton:disabled {
                    background-color: #cccccc;
                    color: #888888;
                }
                QPushButton:hover {
                    background-color: #ff9900;
                }
                QLabel {
                    border-radius: 8px;
                    font-weight: bold;
                    font-size: 12px;
                }
                QComboBox {
                    background-color: #ffffff;
                    border: 1px solid #cccccc;
                    border-radius: 5px;
                    color: #404040;
                    padding: 5px;
                }
                QComboBox QAbstractItemView {
                    background-color: #ffffff;
                    border: 1px solid #cccccc;
                    selection-background-color: #cccccc;
                    color: #404040;
                }
                QCheckBox {
                    color: #404040;
                }
                QCheckBox::indicator {
                    width: 16px;
                    height: 16px;
                }
                QCheckBox::indicator:unchecked {
                    border: 1px solid #cccccc;
                    background-color: #ffffff;
                }
            """)

    def check_for_theme_change(self):
        new_dark_mode = self.is_dark_mode()
        if new_dark_mode != self.dark_mode:
            self.dark_mode = new_dark_mode
            self.apply_stylesheet(self.dark_mode)

    def eventFilter(self, source, event):
        if self.show_tooltips:
            if event.type() == QEvent.Enter:
                if source == self.email_input:
                    QToolTip.showText(
                        QCursor.pos(), "Enter your Cloudflare email", self.email_input)
                elif source == self.api_key_input:
                    QToolTip.showText(
                        QCursor.pos(),
                        "1. Log in to the Cloudflare dashboard and go to User Profile > API Tokens.\n"
                        "2. In the API Keys section, click View button of Global API Key.",
                        self.api_key_input)
            elif event.type() == QEvent.Leave:
                QToolTip.hideText()
        return super().eventFilter(source, event)

    def login(self):
        self.email = self.email_input.text().strip()
        self.api_key = self.api_key_input.text().strip()

        headers = {
            'X-Auth-Email': self.email,
            'X-Auth-Key': self.api_key,
            'Content-Type': 'application/json'
        }

        response = requests.get(
            'https://api.cloudflare.com/client/v4/user', headers=headers)

        if response.status_code == 200:
            QMessageBox.information(
                self, "Login Successful", "Successfully logged in!")
            self.domain_list_button.setEnabled(True)
            self.add_domain_button.setEnabled(True)
            self.login_button.setText("Logout")
            self.login_button.clicked.disconnect()
            self.login_button.clicked.connect(self.logout)

            self.email_input.setReadOnly(False)
            self.api_key_input.setReadOnly(False)

            self.email_input.setReadOnly(True)
            self.api_key_input.setReadOnly(True)

            self.show_tooltips = False  
        else:
            QMessageBox.critical(self, "Login Failed",
                                 "Invalid API Key or Email.")

    def logout(self):
        self.email_input.clear()
        self.api_key_input.clear()
        self.domain_list_button.setEnabled(False)
        self.add_domain_button.setEnabled(False)

        self.email_input.setReadOnly(False)
        self.api_key_input.setReadOnly(False)

        self.login_button.setText("Login")
        self.login_button.clicked.disconnect()
        self.login_button.clicked.connect(self.login)
        QMessageBox.information(self, "Logout", "Successfully logged out.")
        self.show_tooltips = True 

    def show_domain_list(self):
        if not self.email or not self.api_key:
            QMessageBox.critical(self, "Error", "Please login first.")
            return

        headers = {
            'X-Auth-Email': self.email,
            'X-Auth-Key': self.api_key,
            'Content-Type': 'application/json'
        }

        response = requests.get(
            'https://api.cloudflare.com/client/v4/zones', headers=headers)

        if response.status_code == 200:
            zones = response.json().get('result', [])
            self.zone_list_dialog = ZoneListDialog(zones, self)
            self.zone_list_dialog.exec()
        else:
            QMessageBox.critical(
                self, "Error", "Failed to retrieve domain list.")

    def add_domain(self):
        if not self.email or not self.api_key:
            QMessageBox.critical(self, "Error", "Please login first.")
            return

        new_domain, ok = QInputDialog.getText(
            self, "Add New Domain", "Enter the new domain name:")
        if ok:
            headers = {
                'X-Auth-Email': self.email,
                'X-Auth-Key': self.api_key,
                'Content-Type': 'application/json'
            }

            data = {
                'name': new_domain
            }

            response = requests.post(
                'https://api.cloudflare.com/client/v4/zones', headers=headers, json=data)

            if response.status_code == 200:
                result = response.json().get('result')
                ns_needed = ', '.join(result['name_servers'])
                message_box = QMessageBox(self)
                message_box.setIcon(QMessageBox.Information)
                message_box.setWindowTitle("Success")
                message_box.setText(
                    f"Domain '{new_domain}' added successfully!")
                message_box.setInformativeText(f"Name Servers: {ns_needed}")
                message_box.setStandardButtons(QMessageBox.Ok)
                message_box.exec()
            else:
                error_message = response.json().get('errors', [{}])[
                    0].get('message', 'Unknown error')
                message_box = QMessageBox(self)
                message_box.setIcon(QMessageBox.Critical)
                message_box.setWindowTitle("Error")
                message_box.setText("Failed to add domain.")
                message_box.setInformativeText(f"Error: {error_message}")
                message_box.setStandardButtons(QMessageBox.Ok)
                message_box.exec()

    def closeEvent(self, event):
        reply = QMessageBox.question(
            self, 'Message', "Are you sure you want to exit the program?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            event.accept()
        else:
            event.ignore()


class ZoneListDialog(QDialog):
    def __init__(self, zones, parent=None):
        super().__init__(parent)
        self.setWindowFlags(
            self.windowFlags() | Qt.WindowMinimizeButtonHint | Qt.WindowMaximizeButtonHint)
        self.setWindowTitle("Cloudflare Management")
        self.setGeometry(300, 300, 500, 350)
        self.zones = zones
        self.layout = QVBoxLayout()

        self.create_zone_list_group()
        self.create_buttons()

        self.setLayout(self.layout)

    def create_zone_list_group(self):
        self.zone_list_group = QGroupBox("Domain List")
        self.setGeometry(300, 300, 500, 350)
        self.zone_list_layout = QVBoxLayout()

        self.list_widget = QListWidget()
        self.list_widget.setIconSize(QSize(60, 60))  # Set icon size as needed

        for index, zone in enumerate(self.zones):
            item = QListWidgetItem(zone['name'])
            if zone['status'] == 'pending':
                item.setText(f"{zone['name']} (pending)")
            item.setData(Qt.UserRole, zone)
            self.list_widget.addItem(item)


            if index < len(self.zones) - 1:
                separator_item = QListWidgetItem(25*"-")
                separator_item.setFlags(Qt.NoItemFlags)
                self.list_widget.addItem(separator_item)

        font = self.list_widget.font()
        font.setPointSize(14)  
        self.list_widget.setFont(font)

        self.list_widget.itemDoubleClicked.connect(self.show_zone_options)
        self.zone_list_layout.addWidget(self.list_widget)
        self.zone_list_group.setLayout(self.zone_list_layout)

        self.layout.addWidget(self.zone_list_group)

    def create_buttons(self):
        self.button_layout = QHBoxLayout()

        self.back_button = QPushButton("Back")
        self.back_button.clicked.connect(self.close)
        self.button_layout.addWidget(self.back_button)

        self.layout.addLayout(self.button_layout)

    def show_zone_options(self, item):
        zone_data = item.data(Qt.UserRole)
        if zone_data:  
            self.zone_options_dialog = ZoneOptionsDialog(
                zone_data, parent=self.parent())

            self.zone_options_dialog.finished.connect(self.show)
            self.zone_options_dialog.show()
            self.accept()  

    def closeEvent(self, event):
        self.parent().show()  
        event.accept()


class ZoneOptionsDialog(QDialog):
    def __init__(self, zone_data, parent=None):
        super().__init__(parent)
        self.setWindowFlags(
            self.windowFlags() | Qt.WindowMinimizeButtonHint | Qt.WindowMaximizeButtonHint)
        self.setWindowTitle(f"Manage {zone_data['name']}")
        self.setGeometry(300, 300, 500, 350)

        main_layout = QVBoxLayout()
        self.zone_data = zone_data

        self.layout = QVBoxLayout()

        self.create_buttons_group()
        self.create_name_servers_group()

        self.back_button = QPushButton("Back")
        self.back_button.clicked.connect(self.close)
        self.layout.addWidget(self.back_button)

        self.setLayout(self.layout)

    def create_buttons_group(self):
        buttons_group = QGroupBox("Options")
        buttons_layout = QVBoxLayout()

        font = QFont()
        font.setPointSize(12)

        self.dns_button = QPushButton("DNS")
        self.dns_button.setFont(font)
        self.dns_button.clicked.connect(self.show_dns_records)
        buttons_layout.addWidget(self.dns_button)

        self.ssl_button = QPushButton("SSL/TLS")
        self.ssl_button.setFont(font)
        self.ssl_button.clicked.connect(self.show_ssl_settings)
        buttons_layout.addWidget(self.ssl_button)

        self.network_button = QPushButton("Network")
        self.network_button.setFont(font)
        self.network_button.clicked.connect(self.show_network_settings)
        buttons_layout.addWidget(self.network_button)

        self.delete_button = QPushButton("Delete Domain")
        self.delete_button.setFont(font)
        self.delete_button.clicked.connect(self.delete_domain)
        buttons_layout.addWidget(self.delete_button)

        buttons_group.setLayout(buttons_layout)
        self.layout.addWidget(buttons_group)

    def create_name_servers_group(self):
        if self.zone_data['status'] == 'pending':
            ns_group = QGroupBox("Nameservers")
            ns_layout = QVBoxLayout()

            font = QFont()
            font.setPointSize(12)

            ns_label = QLabel(
                "Update your nameservers:\nFind the list of nameservers at your registrar.\n "
                "Add both of your assigned Cloudflare nameservers, remove any other nameservers, "
                "and save your changes.\nYour assigned Cloudflare nameservers :\n "
            )
            ns_label.setFont(font)
            ns_layout.addWidget(ns_label)

            ns_text = '\n'.join(self.zone_data['name_servers'])
            self.ns_display = QLabel(ns_text)
            self.ns_display.setFont(font)
            self.ns_display.setTextInteractionFlags(Qt.TextSelectableByMouse)
            ns_layout.addWidget(self.ns_display)

            ns_group.setLayout(ns_layout)
            self.layout.addWidget(ns_group)

    def show_dns_records(self):
        self.hide()
        self.dns_records_dialog = DNSRecordsDialog(
            self.zone_data['id'], self.parent())
        self.dns_records_dialog.exec()
        self.show()

    def show_ssl_settings(self):
        self.hide()
        self.ssl_settings_dialog = SSLSettingsDialog(
            self.zone_data['id'], self.parent())
        self.ssl_settings_dialog.exec()
        self.show()

    def show_network_settings(self):
        self.hide()
        self.network_settings_dialog = NetworkSettingsDialog(
            self.zone_data['id'], self.parent())
        self.network_settings_dialog.exec()
        self.show()

    def delete_domain(self):
        confirmation = QMessageBox.question(
            self, "Confirm Delete", "Are you sure you want to delete this domain?",
            QMessageBox.Yes | QMessageBox.No
        )
        if confirmation == QMessageBox.Yes:
            headers = {
                'X-Auth-Email': self.parent().email,
                'X-Auth-Key': self.parent().api_key,
                'Content-Type': 'application/json'
            }

            response = requests.delete(
                f'https://api.cloudflare.com/client/v4/zones/{self.zone_data["id"]}', headers=headers)

            if response.status_code == 200:
                QMessageBox.information(
                    self, "Success", "Domain deleted successfully.")
                self.close()
                self.parent().show_domain_list()
            else:
                QMessageBox.critical(self, "Error", "Failed to delete domain.")


class DNSRecordsDialog(QDialog):
    def __init__(self, zone_id, parent=None):
        super().__init__(parent)
        self.setWindowFlags(
            self.windowFlags() | Qt.WindowMinimizeButtonHint | Qt.WindowMaximizeButtonHint | Qt.WindowCloseButtonHint)
        self.setWindowTitle(f"DNS Settings")
        self.zone_id = zone_id
        self.setGeometry(300, 300, 1000, 500)

        main_layout = QVBoxLayout()

        # GroupBox for Records Table
        self.records_groupbox = QGroupBox("DNS Records")
        self.records_layout = QVBoxLayout()
        self.records_groupbox.setLayout(self.records_layout)

        self.create_records_table()
        self.records_layout.addWidget(self.records_table)

        main_layout.addWidget(self.records_groupbox)

        # GroupBox for Buttons
        self.buttons_groupbox = QGroupBox("Actions")
        self.buttons_layout = QVBoxLayout()

        self.create_buttons()
        self.buttons_groupbox.setLayout(self.buttons_layout)

        main_layout.addWidget(self.buttons_groupbox)

        # Add Back Button Separately
        self.back_button = QPushButton("Back")
        self.back_button.clicked.connect(self.close_and_show_previous)
        main_layout.addWidget(self.back_button)

        self.setLayout(main_layout)

    def create_records_table(self):
        self.records_table = QTableWidget()
        self.records_table.setColumnCount(8)
        self.records_table.setHorizontalHeaderLabels(
            ["ID", "Type", "Name", "Content", "Proxied", "TTL", "Edit Action", "Delete Action"])

        # Enable column resizing
        self.records_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)

        # Stretch specific columns to fit window
        self.records_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.records_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.records_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.records_table.horizontalHeader().setSectionResizeMode(
            6, QHeaderView.Stretch)  
        self.records_table.horizontalHeader().setSectionResizeMode(
            7, QHeaderView.Stretch)  

        self.records_table.setSortingEnabled(True) 
        self.records_table.setEditTriggers(
            QTableWidget.NoEditTriggers)  
        self.records_table.setSelectionBehavior(
            QTableWidget.SelectRows)  
        self.records_table.setSelectionMode(
            QTableWidget.SingleSelection)  
        self.records_table.setContextMenuPolicy(
            Qt.CustomContextMenu)  

        self.records_table.customContextMenuRequested.connect(
            self.context_menu)

        self.clicked_row = -1
        self.clicked_column = -1

    def context_menu(self, pos: QPoint):
        index = self.records_table.indexAt(pos)
        if not index.isValid():
            return

        self.clicked_row = index.row()
        self.clicked_column = index.column()

        menu = QMenu()
        copy_action = QAction("Copy", self)
        copy_action.triggered.connect(self.copy_selection)
        menu.addAction(copy_action)
        menu.exec(self.records_table.viewport().mapToGlobal(pos))

    def copy_selection(self):
        if self.clicked_row >= 0 and self.clicked_column >= 0:
            item = self.records_table.item(
                self.clicked_row, self.clicked_column)
            if item is not None:
                clipboard = QApplication.clipboard()
                clipboard.setText(item.text())

            self.clicked_row = -1
            self.clicked_column = -1

    def create_buttons(self):
        self.load_records_button = QPushButton("Load Records")
        self.load_records_button.clicked.connect(self.load_records)
        self.buttons_layout.addWidget(self.load_records_button)

        self.add_record_button = QPushButton("Add Record")
        self.add_record_button.clicked.connect(self.add_record)
        self.buttons_layout.addWidget(self.add_record_button)

    def load_records(self):
        try:
            headers = {
                'X-Auth-Email': self.parent().email,
                'X-Auth-Key': self.parent().api_key,
                'Content-Type': 'application/json'
            }

            response = requests.get(
                f'https://api.cloudflare.com/client/v4/zones/{self.zone_id}/dns_records', headers=headers)

            response.raise_for_status()  

            self.records_table.clearContents()
            self.records_table.setRowCount(0)
            records = response.json().get('result', [])
            for record in records:
                row_position = self.records_table.rowCount()
                self.records_table.insertRow(row_position)
                self.populate_table_row(row_position, record)

        except requests.RequestException as e:
            QMessageBox.critical(
                self, "Error", f"Failed to load DNS records: {str(e)}")

    def populate_table_row(self, row_position, record):
        self.records_table.setItem(
            row_position, 0, QTableWidgetItem(record.get('id', '')))
        self.records_table.setItem(
            row_position, 1, QTableWidgetItem(record.get('type', '')))
        self.records_table.setItem(
            row_position, 2, QTableWidgetItem(record.get('name', '')))
        self.records_table.setItem(
            row_position, 3, QTableWidgetItem(record.get('content', '')))

        ttl_text = self.format_ttl_value(record.get('ttl', ''))
        self.records_table.setItem(row_position, 4, QTableWidgetItem(ttl_text))

        self.records_table.setItem(row_position, 5, QTableWidgetItem(
            "Proxied" if record.get('proxied') else "Not Proxied"))

        # Add edit button
        edit_button = QPushButton("Edit")
        edit_button.clicked.connect(lambda _, r=record: self.edit_record(r))
        self.records_table.setCellWidget(row_position, 6, edit_button)

        # Add delete button
        delete_button = QPushButton("Delete")
        delete_button.clicked.connect(
            lambda _, r=record: self.delete_record(r))
        self.records_table.setCellWidget(row_position, 7, delete_button)

    def format_ttl_value(self, ttl_seconds):
        ttl_mapping = {
            1: "Auto", 60: "1 min", 120: "2 min", 300: "5 min",
            600: "10 min", 900: "15 min", 1800: "30 min",
            3600: "1 hr", 7200: "2 hr", 18000: "5 hr",
            43200: "12 hr", 86400: "1 day"
        }
        return ttl_mapping.get(ttl_seconds, f"{ttl_seconds} sec")

    def add_record(self):
        self.record_form_dialog = RecordFormDialog(self.zone_id, "add", self)
        if self.record_form_dialog.exec() == QDialog.Accepted:
            self.load_records()

    def edit_record(self, record):
        try:
            headers = {
                'X-Auth-Email': self.parent().email,
                'X-Auth-Key': self.parent().api_key,
                'Content-Type': 'application/json'
            }

            response = requests.get(
                f'https://api.cloudflare.com/client/v4/zones/{self.zone_id}/dns_records/{record["id"]}', headers=headers)

            response.raise_for_status()

            record_data = response.json().get('result')
            self.record_form_dialog = RecordFormDialog(
                self.zone_id, "edit", self, record_data)
            if self.record_form_dialog.exec() == QDialog.Accepted:
                self.load_records()

        except requests.RequestException as e:
            QMessageBox.critical(
                self, "Error", f"Failed to retrieve record details: {str(e)}")

    def delete_record(self, record):
        confirmation = QMessageBox.question(
            self, "Confirm Delete", "Are you sure you want to delete this record?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if confirmation == QMessageBox.StandardButton.Yes:
            try:
                headers = {
                    'X-Auth-Email': self.parent().email,
                    'X-Auth-Key': self.parent().api_key,
                    'Content-Type': 'application/json'
                }

                response = requests.delete(
                    f'https://api.cloudflare.com/client/v4/zones/{self.zone_id}/dns_records/{record["id"]}', headers=headers)

                response.raise_for_status()

                QMessageBox.information(
                    self, "Success", "Record deleted successfully.")
                self.load_records()

            except requests.RequestException as e:
                QMessageBox.critical(
                    self, "Error", f"Failed to delete record: {str(e)}")

    def close_and_show_previous(self):
        self.close()

    def resizeEvent(self, event):
        self.records_table.setGeometry(
            0, 0, self.width(), self.records_table.height())

        super().resizeEvent(event)


class RecordFormDialog(QDialog):
    def __init__(self, zone_id, mode, parent=None, record=None):
        super().__init__(parent)
        self.setWindowFlags(
            self.windowFlags() | Qt.WindowMinimizeButtonHint | Qt.WindowMaximizeButtonHint)
        self.setWindowTitle(f"{mode.capitalize()} Record")
        self.zone_id = zone_id
        self.mode = mode
        self.record = record

        self.initUI()

        if self.mode == "edit" and self.record:
            self.load_record_data()

        # Adjusting the dialog size
        self.resize(500, 400)  

    def initUI(self):
        self.layout = QVBoxLayout(self)
        self.setGeometry(300, 300, 350, 300)
        self.group_box = QGroupBox("Record Details")
        self.group_layout = QFormLayout()

        self.type_label = QLabel("Type:")
        self.type_combo = QComboBox()
        self.type_combo.addItems(["A", "AAAA", "CNAME", "MX", "TXT", "SRV", "NS", "PTR", "LOC",
                                  "SPF", "CERT", "DNSKEY", "DS", "NAPTR", "SMIMEA", "SSHFP", "SVCB", "TLSA", "URI"])
        self.group_layout.addRow(self.type_label, self.type_combo)

        self.name_label = QLabel("Name:")
        self.name_input = QLineEdit()
        self.group_layout.addRow(self.name_label, self.name_input)

        self.content_label = QLabel("Content:")
        self.content_input = QLineEdit()
        self.group_layout.addRow(self.content_label, self.content_input)

        self.ttl_label = QLabel("TTL:")
        self.ttl_combo = QComboBox()
        self.ttl_combo.addItems(["Auto", "1 min", "2 min", "5 min", "10 min",
                                 "15 min", "30 min", "1 hr", "2 hr", "5 hr", "12 hr", "1 day"])
        self.group_layout.addRow(self.ttl_label, self.ttl_combo)

        self.proxied_checkbox = QCheckBox("Proxied")
        self.group_layout.addRow("", self.proxied_checkbox)

        self.group_box.setLayout(self.group_layout)
        self.layout.addWidget(self.group_box)

        self.save_button = QPushButton("Save")
        self.save_button.clicked.connect(self.save_record)
        self.layout.addWidget(self.save_button)

        self.setLayout(self.layout)

    def load_record_data(self):
        self.type_combo.setCurrentText(self.record['type'])
        self.name_input.setText(self.record['name'])
        self.content_input.setText(self.record['content'])
        self.ttl_combo.setCurrentText(
            self.format_ttl_value(self.record['ttl']))
        self.proxied_checkbox.setChecked(self.record.get('proxied', False))

    def format_ttl_value(self, ttl_seconds):
        ttl_mapping = {
            1: "Auto", 60: "1 min", 120: "2 min", 300: "5 min", 600: "10 min",
            900: "15 min", 1800: "30 min", 3600: "1 hr", 7200: "2 hr",
            18000: "5 hr", 43200: "12 hr", 86400: "1 day"
        }
        return ttl_mapping.get(ttl_seconds, "")

    def save_record(self):
        headers = {
            'X-Auth-Email': self.parent().parent().email,
            'X-Auth-Key': self.parent().parent().api_key,
            'Content-Type': 'application/json'
        }

        data = {
            'type': self.type_combo.currentText(),
            'name': self.name_input.text().strip(),
            'content': self.content_input.text().strip(),
            'ttl': self.get_ttl_seconds(self.ttl_combo.currentText()),
            'proxied': self.proxied_checkbox.isChecked()
        }

        try:
            if self.mode == "add":
                response = requests.post(f'https://api.cloudflare.com/client/v4/zones/{
                                         self.zone_id}/dns_records', headers=headers, json=data)
            elif self.mode == "edit" and self.record:
                response = requests.put(f'https://api.cloudflare.com/client/v4/zones/{
                    self.zone_id}/dns_records/{self.record["id"]}', headers=headers, json=data)

            response.raise_for_status()

            if response.status_code in [200, 201]:
                QMessageBox.information(
                    self, "Success", "Record saved successfully.")
                self.accept()
            else:
                QMessageBox.critical(self, "Error", "Failed to save record.")
        except requests.exceptions.RequestException as e:
            QMessageBox.critical(self, "Error", f"Failed to connect: {e}")

    def get_ttl_seconds(self, ttl_text):
        ttl_mapping = {
            "Auto": 1, "1 min": 60, "2 min": 120, "5 min": 300,
            "10 min": 600, "15 min": 900, "30 min": 1800,
            "1 hr": 3600, "2 hr": 7200, "5 hr": 18000,
            "12 hr": 43200, "1 day": 86400
        }
        return ttl_mapping.get(ttl_text, 3600)


class SSLSettingsDialog(QDialog):
    def __init__(self, zone_id, parent=None):
        super().__init__(parent)
        self.setWindowFlags(
            self.windowFlags() | Qt.WindowMinimizeButtonHint | Qt.WindowMaximizeButtonHint)
        self.setWindowTitle("SSL/TLS Settings")
        self.setGeometry(300, 300, 500, 350)
        self.zone_id = zone_id

        self.layout = QVBoxLayout()
        self.initial_load = True  # فلگ برای بارگذاری اولیه

        # SSL and Universal SSL Layout
        ssl_universal_layout = QVBoxLayout()

        # SSL Mode Group Box
        self.ssl_mode_groupbox = QGroupBox("SSL Mode")
        ssl_mode_layout = QVBoxLayout()
        self.ssl_mode_combo = QComboBox()
        self.ssl_mode_combo.addItem("Off", "off")
        self.ssl_mode_combo.addItem("Flexible", "flexible")
        self.ssl_mode_combo.addItem("Full", "full")
        self.ssl_mode_combo.addItem("Full (strict)", "strict")
        self.ssl_mode_combo.currentIndexChanged.connect(self.update_ssl_mode)
        ssl_mode_layout.addWidget(self.ssl_mode_combo)
        self.ssl_mode_groupbox.setLayout(ssl_mode_layout)
        ssl_universal_layout.addWidget(self.ssl_mode_groupbox)

        # Universal SSL Group Box
        self.universal_ssl_groupbox = QGroupBox("Universal SSL")
        universal_ssl_layout = QVBoxLayout()
        self.universal_ssl_combo = QComboBox()
        self.universal_ssl_combo.addItem("Off", False)
        self.universal_ssl_combo.addItem("On", True)
        self.universal_ssl_combo.currentIndexChanged.connect(
            self.update_universal_ssl)

        universal_ssl_layout.addWidget(self.universal_ssl_combo)
        self.universal_ssl_groupbox.setLayout(universal_ssl_layout)
        ssl_universal_layout.addWidget(self.universal_ssl_groupbox)

        self.layout.addLayout(ssl_universal_layout)

        # Actions Group Box
        self.actions_groupbox = QGroupBox("Actions")
        actions_layout = QVBoxLayout()

        self.edge_certificates_button = QPushButton(
            "Edge Certificates Settings")
        self.edge_certificates_button.clicked.connect(
            self.show_edge_certificates)
        actions_layout.addWidget(self.edge_certificates_button)

        self.origin_server_button = QPushButton("Origin Server Settings")
        self.origin_server_button.clicked.connect(
            self.show_origin_server_settings)
        actions_layout.addWidget(self.origin_server_button)

        self.actions_groupbox.setLayout(actions_layout)
        self.layout.addWidget(self.actions_groupbox)

        # Add Back Button Separately
        self.back_button = QPushButton("Back")
        self.back_button.clicked.connect(self.close)
        self.layout.addWidget(self.back_button)

        self.setLayout(self.layout)

        self.load_ssl_settings()

    def load_ssl_settings(self):
        headers = {
            'X-Auth-Email': self.parent().email,
            'X-Auth-Key': self.parent().api_key,
            'Content-Type': 'application/json'
        }

        # Load SSL mode
        response_ssl_mode = requests.get(
            f'https://api.cloudflare.com/client/v4/zones/{self.zone_id}/settings/ssl', headers=headers)

        if response_ssl_mode.status_code == 200:
            ssl_mode_settings = response_ssl_mode.json().get('result', {})
            current_ssl_mode = ssl_mode_settings.get('value', 'off')

            index = self.ssl_mode_combo.findData(current_ssl_mode)
            if index != -1:
                self.ssl_mode_combo.setCurrentIndex(index)
            self.initial_ssl_mode = current_ssl_mode
        else:
            QMessageBox.critical(
                self, "Error", "Failed to load SSL/TLS settings.")

        # Load Universal SSL
        response_universal_ssl = requests.get(
            f'https://api.cloudflare.com/client/v4/zones/{self.zone_id}/ssl/universal/settings', headers=headers)

        if response_universal_ssl.status_code == 200:
            universal_ssl_settings = response_universal_ssl.json().get('result', {})
            universal_ssl_enabled = universal_ssl_settings.get(
                'enabled', False)
 
            index = self.universal_ssl_combo.findData(universal_ssl_enabled)
            if index != -1:
                self.universal_ssl_combo.setCurrentIndex(index)
            self.initial_universal_ssl = universal_ssl_enabled
        else:
            QMessageBox.critical(
                self, "Error", "Failed to load Universal SSL setting.")

        self.initial_load = False  

    def update_ssl_mode(self):
        if self.initial_load:
            return  

        headers = {
            'X-Auth-Email': self.parent().email,
            'X-Auth-Key': self.parent().api_key,
            'Content-Type': 'application/json'
        }

        ssl_mode = self.ssl_mode_combo.currentData()
        if ssl_mode == self.initial_ssl_mode:
            return

        ssl_data = {'value': ssl_mode}
        response_ssl_mode = requests.patch(
            f'https://api.cloudflare.com/client/v4/zones/{self.zone_id}/settings/ssl', headers=headers, json=ssl_data)

        if response_ssl_mode.status_code != 200:
            QMessageBox.critical(self, "Error", "Failed to update SSL mode.")
        else:
            self.initial_ssl_mode = ssl_mode
            QMessageBox.information(
                self, "Success", "SSL mode updated successfully.")

    def update_universal_ssl(self):
        if self.initial_load:
            return  # اگر بارگذاری اولیه است، هیچ کاری انجام نشود

        headers = {
            'X-Auth-Email': self.parent().email,
            'X-Auth-Key': self.parent().api_key,
            'Content-Type': 'application/json'
        }

        universal_ssl_enabled = self.universal_ssl_combo.currentData()
        if universal_ssl_enabled == self.initial_universal_ssl:
            return

        universal_ssl_data = {'enabled': universal_ssl_enabled}
        response_universal_ssl = requests.patch(
            f'https://api.cloudflare.com/client/v4/zones/{self.zone_id}/ssl/universal/settings', headers=headers, json=universal_ssl_data)

        if response_universal_ssl.status_code != 200:
            QMessageBox.critical(
                self, "Error", "Failed to update Universal SSL setting.")
        else:
            self.initial_universal_ssl = universal_ssl_enabled
            QMessageBox.information(
                self, "Success", "Universal SSL setting updated successfully.")

    def show_edge_certificates(self):
        self.edge_certificates_dialog = EdgeCertificatesDialog(
            self.zone_id, self)
        self.edge_certificates_dialog.exec()

    def show_origin_server_settings(self):
        self.origin_server_dialog = OriginServerDialog(self.zone_id, self)
        self.origin_server_dialog.exec()


class EdgeCertificatesDialog(QDialog):
    def __init__(self, zone_id, parent=None):
        super().__init__(parent)
        self.setWindowFlags(
            self.windowFlags() | Qt.WindowMinimizeButtonHint | Qt.WindowMaximizeButtonHint)
        self.setWindowTitle("Edge Certificates Settings")
        self.setGeometry(300, 300, 500, 350)
        self.zone_id = zone_id

        self.current_min_tls_version = None
        self.initial_load = True

        self.layout = QVBoxLayout()
        self.init_ui()
        self.setLayout(self.layout)

        self.load_edge_certificate_settings()

    def init_ui(self):
        self.certificate_packs_button = QPushButton("List Certificate Packs")
        self.certificate_packs_button.clicked.connect(
            self.list_certificate_packs)
        self.layout.addWidget(self.certificate_packs_button)

        self.always_use_https_checkbox = QCheckBox("Always Use HTTPS")
        self.opportunistic_encryption_checkbox = QCheckBox(
            "Opportunistic Encryption")
        self.automatic_https_rewrites_checkbox = QCheckBox(
            "Automatic HTTPS Rewrites")
        self.min_tls_combo = QComboBox()
        self.min_tls_combo.addItems(["1.0", "1.1", "1.2", "1.3"])
        self.min_tls_combo.currentTextChanged.connect(
            self.update_min_tls_version)
        self.tls_1_3_checkbox = QCheckBox("Enable TLS 1.3")

        self.add_setting_group("HTTPS Settings", [
            self.always_use_https_checkbox,
            self.opportunistic_encryption_checkbox,
            self.automatic_https_rewrites_checkbox,
        ])

        self.add_setting_group("TLS Settings", [
            QLabel("Minimum TLS Version"),
            self.min_tls_combo,
            self.tls_1_3_checkbox,
        ])

        self.back_button = QPushButton("Back")
        self.back_button.clicked.connect(self.close)
        self.layout.addWidget(self.back_button)

    def add_setting_group(self, title, settings):
        group_box = QGroupBox(title)
        group_layout = QVBoxLayout()

        for widget in settings:
            group_layout.addWidget(widget)
            if isinstance(widget, QCheckBox):
                widget.clicked.connect(
                    lambda checked, w=widget: self.update_setting(w))

        group_box.setLayout(group_layout)
        self.layout.addWidget(group_box)

    def get_url_from_widget(self, widget):
        url_map = {
            self.always_use_https_checkbox: 'always_use_https',
            self.opportunistic_encryption_checkbox: 'opportunistic_encryption',
            self.automatic_https_rewrites_checkbox: 'automatic_https_rewrites',
            self.tls_1_3_checkbox: 'tls_1_3',
        }
        return f'https://api.cloudflare.com/client/v4/zones/{self.zone_id}/settings/{url_map.get(widget)}'

    def list_certificate_packs(self):
        self.api_request(f'https://api.cloudflare.com/client/v4/zones/{
                         self.zone_id}/ssl/certificate_packs', 'get', 'Certificate Packs')

    def load_edge_certificate_settings(self):
        headers = self.get_headers()
        self.get_setting(self.get_url_from_widget(
            self.always_use_https_checkbox), self.always_use_https_checkbox, headers)
        self.initial_min_tls_version = self.get_min_tls_version_setting(
            headers)
        self.current_min_tls_version = self.initial_min_tls_version
        self.get_setting(self.get_url_from_widget(
            self.opportunistic_encryption_checkbox), self.opportunistic_encryption_checkbox, headers)
        self.get_setting(self.get_url_from_widget(
            self.tls_1_3_checkbox), self.tls_1_3_checkbox, headers)
        self.get_setting(self.get_url_from_widget(
            self.automatic_https_rewrites_checkbox), self.automatic_https_rewrites_checkbox, headers)
        self.initial_load = False

    def get_setting(self, url, widget, headers):
        response = self.api_request(url, 'get', headers=headers)
        if response and response.status_code == 200:
            value = response.json().get('result', {}).get('value', False)
            if isinstance(widget, QCheckBox):
                widget.setChecked(value == 'on')

    def update_setting(self, widget):
        url = self.get_url_from_widget(widget)
        value = 'on' if widget.isChecked() else 'off'
        response = self.patch_setting(url, value)
        if response and response.status_code == 200:
            status = 'Enabled' if widget.isChecked() else 'Disabled'
            self.show_success_message(f'Successfully updated {
                                      widget.text()} to {status}')

    def patch_setting(self, url, value):
        return self.api_request(url, 'patch', data={'value': value})

    def get_min_tls_version_setting(self, headers):
        url = f'https://api.cloudflare.com/client/v4/zones/{
            self.zone_id}/settings/min_tls_version'
        response = self.api_request(url, 'get', headers=headers)
        if response and response.status_code == 200:
            value = response.json().get('result', {}).get('value', '1.0')
            self.min_tls_combo.setCurrentText(value)
            return value
        return '1.0'

    def update_min_tls_version(self):
        if self.initial_load:
            return

        new_value = self.min_tls_combo.currentText()
        if new_value != self.current_min_tls_version:
            url = f'https://api.cloudflare.com/client/v4/zones/{
                self.zone_id}/settings/min_tls_version'
            response = self.patch_setting(url, new_value)
            if response and response.status_code == 200:
                self.show_success_message(
                    f'Successfully updated Minimum TLS Version to {new_value}')
            self.current_min_tls_version = new_value

    def get_headers(self):
        return {
            'X-Auth-Email': self.parent().parent().email,
            'X-Auth-Key': self.parent().parent().api_key,
            'Content-Type': 'application/json'
        }

    def api_request(self, url, method, title=None, data=None, headers=None):
        headers = headers or self.get_headers()
        try:
            if method == 'get':
                response = requests.get(url, headers=headers)
            elif method == 'patch':
                response = requests.patch(url, headers=headers, json=data)
            else:
                return None

            if response.status_code == 200:
                if title:
                    result = response.json().get('result', [])
                    info = "\n".join(
                        [f"ID: {item['id']} - Status: {item['status']}" for item in result])
                    self.show_message_box('information', title, info)
                return response
            else:
                self.show_message_box('critical', 'Error', f"Failed to {method} data from {
                                      url}. Status code: {response.status_code}")
        except Exception as e:
            self.show_message_box('critical', 'Error',
                                  f"An error occurred: {str(e)}")
        return None

    def show_message_box(self, icon, title, text):
        msg_box = QMessageBox()
        if icon == 'information':
            msg_box.setIcon(QMessageBox.Information)
        elif icon == 'critical':
            msg_box.setIcon(QMessageBox.Critical)
        msg_box.setWindowTitle(title)
        msg_box.setText(text)
        msg_box.exec()

    def show_success_message(self, text):
        self.show_message_box('information', 'Success', text)


class OriginServerDialog(QDialog):
    def __init__(self, zone_id, parent=None):
        super().__init__(parent)
        self.setWindowFlags(
            self.windowFlags() | Qt.WindowMinimizeButtonHint | Qt.WindowMaximizeButtonHint)
        self.setWindowTitle("Origin Server Settings")
        self.setGeometry(300, 300, 630, 350)

        self.zone_id = zone_id

        self.layout = QVBoxLayout()
        self.initial_load = True

        self.setup_tls_settings()
        self.setup_certificate_management()
        self.setup_back_button()

        self.setLayout(self.layout)

        self.load_origin_server_settings()
        self.load_origin_certificates()

    def setup_tls_settings(self):
        self.tls_group_box = QGroupBox("TLS Settings")
        self.tls_layout = QHBoxLayout()
        self.tls_client_auth_checkbox = QCheckBox("TLS Client Auth")
        self.tls_client_auth_checkbox.stateChanged.connect(
            self.save_origin_server_settings)
        self.tls_layout.addWidget(self.tls_client_auth_checkbox)
        self.tls_group_box.setLayout(self.tls_layout)
        self.layout.addWidget(self.tls_group_box)

    def setup_certificate_management(self):
        self.certificates_group_box = QGroupBox("Origin Certificates")
        self.certificates_layout = QVBoxLayout()

        self.certificates_table = QTableWidget()
        self.certificates_table.setColumnCount(3)
        self.certificates_table.setHorizontalHeaderLabels(
            ["ID", "Hostnames", "Expire time"])
        self.certificates_table.horizontalHeader().setStretchLastSection(True)
        self.certificates_layout.addWidget(self.certificates_table)

        self.certificates_table.setSelectionBehavior(
            QAbstractItemView.SelectRows)

        self.setup_certificate_buttons()
        self.certificates_layout.addLayout(self.button_layout)
        self.certificates_group_box.setLayout(self.certificates_layout)
        self.layout.addWidget(self.certificates_group_box)

    def setup_certificate_buttons(self):
        self.button_layout = QHBoxLayout()
        self.add_certificate_button = QPushButton("Add Certificate")
        self.add_certificate_button.clicked.connect(
            self.add_certificate_dialog)
        self.view_certificate_button = QPushButton("View Certificate")
        self.view_certificate_button.clicked.connect(self.view_certificate)
        self.revoke_certificate_button = QPushButton("Revoke Certificate")
        self.revoke_certificate_button.clicked.connect(self.revoke_certificate)

        self.button_layout.addWidget(self.add_certificate_button)
        self.button_layout.addWidget(self.view_certificate_button)
        self.button_layout.addWidget(self.revoke_certificate_button)

    def setup_back_button(self):
        self.back_button = QPushButton("Back")
        self.back_button.clicked.connect(self.close_dialog)
        self.layout.addWidget(self.back_button, alignment=Qt.AlignCenter)

    def close_dialog(self):
        self.close()
        self.parent().show()

    def load_origin_server_settings(self):
        try:
            headers = {
                'X-Auth-Email': self.parent().parent().email,
                'X-Auth-Key': self.parent().parent().api_key,
                'Content-Type': 'application/json'
            }

            response = requests.get(
                f'https://api.cloudflare.com/client/v4/zones/{self.zone_id}/settings/tls_client_auth', headers=headers)

            if response.status_code == 200:
                setting = response.json().get('result', {})
                value = setting.get('value', False)
                self.tls_client_auth_checkbox.setChecked(value == 'on')
            else:
                self.show_api_error_message(
                    "Failed to load TLS Client Auth setting.")
        except Exception as e:
            self.show_api_error_message(
                f"Failed to load TLS Client Auth setting: {str(e)}")

        self.initial_load = False

    def save_origin_server_settings(self):
        if self.initial_load:
            return

        try:
            headers = {
                'X-Auth-Email': self.parent().parent().email,
                'X-Auth-Key': self.parent().parent().api_key,
                'Content-Type': 'application/json'
            }

            value = 'on' if self.tls_client_auth_checkbox.isChecked() else 'off'
            data = {'value': value}

            response = requests.patch(
                f'https://api.cloudflare.com/client/v4/zones/{self.zone_id}/settings/tls_client_auth', headers=headers, json=data)

            if response.status_code == 200:
                QMessageBox.information(
                    self, "Success", "TLS Client Auth setting updated successfully.")
            else:
                self.show_api_error_message(
                    "Failed to update TLS Client Auth setting.")
        except Exception as e:
            self.show_api_error_message(
                f"Failed to update TLS Client Auth setting: {str(e)}")

    def load_origin_certificates(self):
        try:
            headers = {
                'X-Auth-Email': self.parent().parent().email,
                'X-Auth-Key': self.parent().parent().api_key,
                'Content-Type': 'application/json'
            }

            response = requests.get(
                f'https://api.cloudflare.com/client/v4/certificates?zone_id={self.zone_id}', headers=headers)

            if response.status_code == 200:
                certificates = response.json().get('result', [])
                self.certificates_table.setRowCount(len(certificates))

                for index, cert in enumerate(certificates):
                    self.populate_certificate_table_row(index, cert)

                self.certificates_table.resizeColumnsToContents()

            else:
                self.show_api_error_message("Failed to load certificates.")
        except Exception as e:
            self.show_api_error_message(
                f"Failed to load certificates: {str(e)}")

    def populate_certificate_table_row(self, index, cert):
        id_item = QTableWidgetItem(cert.get('id', ''))
        id_item.setFlags(id_item.flags() & ~Qt.ItemIsEditable)
        hostnames_item = QTableWidgetItem(', '.join(cert.get('hostnames', [])))
        hostnames_item.setFlags(hostnames_item.flags() & ~Qt.ItemIsEditable)
        expire_time_item = QTableWidgetItem(cert.get('expires_on', ''))
        expire_time_item.setFlags(
            expire_time_item.flags() & ~Qt.ItemIsEditable)

        self.certificates_table.setItem(index, 0, id_item)
        self.certificates_table.setItem(index, 1, hostnames_item)
        self.certificates_table.setItem(index, 2, expire_time_item)

    def add_certificate_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Add Certificate")

        main_layout = QVBoxLayout()

        # GroupBox for Certificate Validity
        validity_groupbox = QGroupBox("Certificate Validity")
        validity_layout = QVBoxLayout()

        validity_options = [
            ("7 days", 7),
            ("30 days", 30),
            ("90 days", 90),
            ("1 year", 365),
            ("2 years", 730),
            ("3 years", 1095),
            ("15 years", 5475)
        ]

        self.validity_combo = QComboBox()
        for text, _ in validity_options:
            self.validity_combo.addItem(text)

        validity_layout.addWidget(self.validity_combo)
        validity_groupbox.setLayout(validity_layout)
        main_layout.addWidget(validity_groupbox)

        # GroupBox for Add Certificate with Custom CSR
        custom_csr_groupbox = QGroupBox()
        custom_csr_layout = QVBoxLayout()

        create_with_custom_csr_button = QPushButton(
            "Add certificate with Custom CSR")
        create_with_custom_csr_button.clicked.connect(
            lambda: self.create_certificate(dialog, generate_csr=False))

        custom_csr_layout.addWidget(create_with_custom_csr_button)
        custom_csr_groupbox.setLayout(custom_csr_layout)
        main_layout.addWidget(custom_csr_groupbox)

        dialog.setLayout(main_layout)
        dialog.exec()

    def create_certificate(self, parent_dialog, generate_csr):
        parent_dialog.accept()
        validity_text = self.validity_combo.currentText()
        validity_days = next(days for text, days in [
            ("7 days", 7),
            ("30 days", 30),
            ("90 days", 90),
            ("1 year", 365),
            ("2 years", 730),
            ("3 years", 1095),
            ("15 years", 5475)
        ] if text == validity_text)

        if generate_csr:
            self.generate_and_create_certificate(validity_days)
        else:
            self.create_certificate_with_custom_csr(validity_days)

    def generate_and_create_certificate(self, requested_validity):
        headers = {
            'X-Auth-Email': self.parent().parent().email,
            'X-Auth-Key': self.parent().parent().api_key,
            'Content-Type': 'application/json'
        }

        response = requests.get(
            f'https://api.cloudflare.com/client/v4/zones/{self.zone_id}', headers=headers)
        if response.status_code == 200:
            zone_info = response.json().get('result', {})
            domain_name = zone_info.get('name', '')
            default_hostnames = [domain_name, f"*.{domain_name}"]

            hostnames, ok = QInputDialog.getText(
                self, "Create Certificate", "Enter Hostnames (comma-separated):", text=",".join(default_hostnames))
            if ok and hostnames:
                key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                )

                csr = x509.CertificateSigningRequestBuilder().subject_name(
                    x509.Name([
                        x509.NameAttribute(NameOID.COMMON_NAME, domain_name),
                    ])
                ).sign(key, hashes.SHA256())

                csr_pem = csr.public_bytes(serialization.Encoding.PEM)
                key_pem = key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )

                data = {
                    'csr': csr_pem.decode(),
                    'hostnames': hostnames.split(','),
                    'request_type': 'origin-rsa',
                    'requested_validity': requested_validity
                }

                response = requests.post(
                    'https://api.cloudflare.com/client/v4/certificates', headers=headers, json=data)

                if response.status_code == 200:
                    result = response.json().get('result', {})
                    self.save_key_and_certificate(result, key_pem.decode())
                    self.load_origin_certificates()
                    QMessageBox.information(
                        self, "Success", "Certificate created successfully.")
                else:
                    error_message = response.json().get('errors', [{}])[0].get(
                        'message', 'Failed to create certificate.')
                    QMessageBox.critical(
                        self, "Error", f"Failed to create certificate: {error_message}")
        else:
            QMessageBox.critical(
                self, "Error", "Failed to retrieve zone information.")

    def create_certificate_with_custom_csr(self, requested_validity):
        headers = {
            'X-Auth-Email': self.parent().parent().email,
            'X-Auth-Key': self.parent().parent().api_key,
            'Content-Type': 'application/json'
        }

        response = requests.get(
            f'https://api.cloudflare.com/client/v4/zones/{self.zone_id}', headers=headers)
        if response.status_code == 200:
            zone_info = response.json().get('result', {})
            domain_name = zone_info.get('name', '')
            default_hostnames = [domain_name, f"*.{domain_name}"]

            csr, key = self.generate_csr_and_key(domain_name)

            hostnames, ok = QInputDialog.getText(
                self, "Create Certificate", "Enter Hostnames (comma-separated):", text=",".join(default_hostnames))
            if ok and hostnames:
                data = {
                    'csr': csr,
                    'hostnames': hostnames.split(','),
                    'request_type': 'origin-rsa',
                    'requested_validity': requested_validity
                }

                response = requests.post(
                    'https://api.cloudflare.com/client/v4/certificates', headers=headers, json=data)

                if response.status_code == 200:
                    result = response.json().get('result', {})
                    self.save_key_and_certificate(result, key)
                    self.load_origin_certificates()
                    QMessageBox.information(
                        self, "Success", "Certificate created successfully.")
                else:
                    error_message = response.json().get('errors', [{}])[0].get(
                        'message', 'Failed to create certificate.')
                    QMessageBox.critical(
                        self, "Error", f"Failed to create certificate: {error_message}")
        else:
            QMessageBox.critical(
                self, "Error", "Failed to retrieve zone information.")

    def save_key_and_certificate(self, certificate_info, key):
        reply = QMessageBox.question(self, 'Save Key and Certificate', 'Do you want to save the Private Key and Certificate?',
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            default_cert_file = "Cert.crt"
            default_key_file = "Private.key"

            cert_path, _ = QFileDialog.getSaveFileName(
                self, "Save Certificate", default_cert_file, "Certificate Files (*.crt)")
            if cert_path:
                with open(cert_path, 'w') as cert_file:
                    cert_file.write(certificate_info.get('certificate', ''))

            key_path, _ = QFileDialog.getSaveFileName(
                self, "Save Private Key", default_key_file, "Key Files (*.key)")
            if key_path:
                with open(key_path, 'w') as key_file:
                    key_file.write(key)

            QMessageBox.information(
                self, "Success", "Key and Certificate saved successfully.")
        else:
            QMessageBox.information(
                self, "Cancelled", "Saving Key and Certificate cancelled.")

    def view_certificate(self):
        selected_items = self.certificates_table.selectedItems()
        if not selected_items:
            QMessageBox.warning(
                self, "Warning", "Please select a certificate to view.")
            return

        certificate_id = selected_items[0].text()

        headers = {
            'X-Auth-Email': self.parent().parent().email,
            'X-Auth-Key': self.parent().parent().api_key,
            'Content-Type': 'application/json'
        }

        response = requests.get(
            f'https://api.cloudflare.com/client/v4/certificates/{certificate_id}', headers=headers)

        if response.status_code == 200:
            certificate_info = response.json().get('result', {})
            certificate = certificate_info.get('certificate', '')

            dialog = QDialog(self)
            dialog.setWindowTitle("View Certificate")
            dialog_layout = QVBoxLayout()

            certificate_text_edit = QPlainTextEdit()
            certificate_text_edit.setPlainText(certificate)
            certificate_text_edit.setReadOnly(True)
            dialog_layout.addWidget(certificate_text_edit)

            dialog_button_box = QDialogButtonBox(QDialogButtonBox.Ok)
            dialog_button_box.accepted.connect(dialog.accept)
            dialog_layout.addWidget(dialog_button_box)

            dialog.setLayout(dialog_layout)
            dialog.exec()
        else:
            QMessageBox.critical(
                self, "Error", "Failed to retrieve certificate information.")

    def revoke_certificate(self):
        selected_items = self.certificates_table.selectedItems()
        if not selected_items:
            QMessageBox.warning(
                self, "Warning", "Please select a certificate to revoke.")
            return

        certificate_id = selected_items[0].text()

        confirm = QMessageBox.question(
            self, "Revoke Certificate", "Are you sure you want to revoke this certificate?", QMessageBox.Yes | QMessageBox.No)
        if confirm == QMessageBox.Yes:
            headers = {
                'X-Auth-Email': self.parent().parent().email,
                'X-Auth-Key': self.parent().parent().api_key,
                'Content-Type': 'application/json'
            }

            response = requests.delete(
                f'https://api.cloudflare.com/client/v4/certificates/{certificate_id}', headers=headers)

            if response.status_code == 200:
                self.load_origin_certificates()
                QMessageBox.information(
                    self, "Success", "Certificate revoked successfully.")
            else:
                QMessageBox.critical(
                    self, "Error", "Failed to revoke certificate.")

    def show_api_error_message(self, message):
        QMessageBox.critical(self, "API Error", message)

    def generate_csr_and_key(self, domain_name):
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, domain_name),
        ])

        csr = x509.CertificateSigningRequestBuilder(
        ).subject_name(name).sign(key, hashes.SHA256())

        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        return csr_pem.decode(), key_pem.decode()


class NetworkSettingsDialog(QDialog):
    def __init__(self, zone_id, parent=None):
        super().__init__(parent)
        self.zone_id = zone_id
        self.api_key = parent.api_key
        self.email = parent.email
        self.initial_load = True

        self.setWindowFlags(
            self.windowFlags() | Qt.WindowMinimizeButtonHint | Qt.WindowMaximizeButtonHint)
        self.setWindowTitle("Network")
        self.setGeometry(300, 300, 500, 350)

        self.layout = QVBoxLayout()
        self.create_network_group()
        self.create_ip_settings_group()
        self.setLayout(self.layout)

        self.back_button = QPushButton("Back")
        self.back_button.clicked.connect(self.close)
        self.layout.addWidget(self.back_button)

        self.load_settings()

    def create_network_group(self):
        group = QGroupBox("Network Action")
        layout = QVBoxLayout()
        layout.setSpacing(10)
        layout.setContentsMargins(10, 10, 10, 10)

        self.websockets_toggle = QCheckBox(" WebSockets ")
        self.ip_geolocation_toggle = QCheckBox(" IP Geolocation ")
        self.onion_routing_toggle = QCheckBox(" Onion Routing ")

        layout.addWidget(self.websockets_toggle)
        layout.addWidget(self.ip_geolocation_toggle)
        layout.addWidget(self.onion_routing_toggle)

        group.setLayout(layout)
        self.layout.addWidget(group)

        self.websockets_toggle.stateChanged.connect(
            lambda: self.update_setting("websockets", self.websockets_toggle))
        self.ip_geolocation_toggle.stateChanged.connect(
            lambda: self.update_setting("ip_geolocation", self.ip_geolocation_toggle))
        self.onion_routing_toggle.stateChanged.connect(
            lambda: self.update_setting("opportunistic_onion", self.onion_routing_toggle))

    def create_ip_settings_group(self):
        group = QGroupBox("IP Settings")
        layout = QVBoxLayout()

        self.ipv6_toggle = QCheckBox(" IPv6 Compatibility")
        layout.addWidget(self.ipv6_toggle)
        layout.addWidget(QLabel("Pseudo IPv4 Status"))

        self.pseudo_ipv4_toggle = QComboBox()
        self.pseudo_ipv4_toggle.addItems(
            ["off", "add_header", "overwrite_header"])

        group.setLayout(layout)
        self.layout.addWidget(group)
        layout.addWidget(self.pseudo_ipv4_toggle)
        self.ipv6_toggle.stateChanged.connect(
            lambda: self.update_setting("ipv6", self.ipv6_toggle))
        self.pseudo_ipv4_toggle.currentTextChanged.connect(
            self.update_pseudo_ipv4_setting)

    def load_settings(self):
        self.fetch_setting("ipv6", self.ipv6_toggle)
        self.fetch_setting("websockets", self.websockets_toggle)
        self.fetch_setting("pseudo_ipv4", self.pseudo_ipv4_toggle)
        self.fetch_setting("ip_geolocation", self.ip_geolocation_toggle)
        self.fetch_setting("opportunistic_onion", self.onion_routing_toggle)
        self.initial_load = False  # Set to False after initial load

    def fetch_setting(self, setting_name, widget):
        if not self.api_key or not self.email:
            return

        url = f"https://api.cloudflare.com/client/v4/zones/{
            self.zone_id}/settings/{setting_name}"
        headers = {
            'X-Auth-Email': self.email,
            'X-Auth-Key': self.api_key,
            'Content-Type': 'application/json'
        }

        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            value = data['result']['value']
            if isinstance(widget, QCheckBox):
                widget.setChecked(value == "on")
            elif isinstance(widget, QComboBox):
                widget.setCurrentText(value)

    def update_setting(self, setting_name, widget):
        if not self.api_key or not self.email:
            return

        new_value = "on" if isinstance(
            widget, QCheckBox) and widget.isChecked() else "off"
        if isinstance(widget, QComboBox):
            new_value = widget.currentText()

        url = f"https://api.cloudflare.com/client/v4/zones/{
            self.zone_id}/settings/{setting_name}"
        headers = {
            'X-Auth-Email': self.email,
            'X-Auth-Key': self.api_key,
            'Content-Type': 'application/json'
        }
        data = {"value": new_value}

        response = requests.patch(url, headers=headers, json=data)
        if response.status_code == 200:
            if not self.initial_load:  
                QMessageBox.information(
                    self, "Success", "Setting updated successfully")
        else:
            QMessageBox.warning(self, "Error", "Failed to update setting")

    def update_pseudo_ipv4_setting(self):
        self.update_setting("pseudo_ipv4", self.pseudo_ipv4_toggle)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CloudflareApp()
    window.show()
    sys.exit(app.exec())
