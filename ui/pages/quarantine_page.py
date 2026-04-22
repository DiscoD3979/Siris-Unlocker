import os
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView, QMessageBox, QLabel
)
from PySide6.QtCore import Qt

from core.quarantine import load_quarantine, remove_from_quarantine, restore_from_quarantine


class QuarantinePage(QWidget):
    def __init__(self):
        super().__init__()

        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)

        title = QLabel("Карантин автозагрузок")
        title.setObjectName("quarantineTitle")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Тип", "Местоположение", "Имя", "Значение", "Дата удаления"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.MultiSelection)
        layout.addWidget(self.table)

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        self.restore_btn = QPushButton("Восстановить выбранное")
        self.restore_btn.clicked.connect(self.restore_selected)
        btn_layout.addWidget(self.restore_btn)
        self.delete_btn = QPushButton("Удалить из карантина")
        self.delete_btn.clicked.connect(self.delete_selected)
        btn_layout.addWidget(self.delete_btn)
        self.restore_all_btn = QPushButton("Восстановить всё")
        self.restore_all_btn.clicked.connect(self.restore_all)
        btn_layout.addWidget(self.restore_all_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        self.setLayout(layout)

        self.entries = []
        self.refresh()

    def refresh(self):
        self.entries = load_quarantine()
        self.table.setRowCount(len(self.entries))
        for row, e in enumerate(self.entries):
            self.table.setItem(row, 0, QTableWidgetItem(e.get('type', '')))
            self.table.setItem(row, 1, QTableWidgetItem(e.get('location', '')))
            self.table.setItem(row, 2, QTableWidgetItem(e.get('name', '')))
            self.table.setItem(row, 3, QTableWidgetItem(e.get('command', '')))
            self.table.setItem(row, 4, QTableWidgetItem(e.get('quarantine_date', '')))

        self.table.resizeColumnsToContents()
        self.table.horizontalHeader().setStretchLastSection(True)

    def get_selected_ids(self):
        rows = set()
        for item in self.table.selectedItems():
            rows.add(item.row())
        return [self.entries[r]['id'] for r in rows if r < len(self.entries)]

    def restore_selected(self):
        ids = self.get_selected_ids()
        if not ids:
            QMessageBox.information(self, "Информация", "Не выбрано ни одной записи.")
            return

        success = []
        for eid in ids:
            entry = next((e for e in self.entries if e['id'] == eid), None)
            if entry and restore_from_quarantine(entry):
                remove_from_quarantine(eid)
                success.append(eid)
        self.refresh()
        QMessageBox.information(self, "Результат", f"Восстановлено {len(success)} из {len(ids)}.")

    def delete_selected(self):
        ids = self.get_selected_ids()
        if not ids:
            QMessageBox.information(self, "Информация", "Не выбрано ни одной записи.")
            return
        reply = QMessageBox.question(self, "Подтверждение", "Удалить выбранные записи из карантина без восстановления?")
        if reply != QMessageBox.Yes:
            return
        for eid in ids:
            remove_from_quarantine(eid)
        self.refresh()

    def restore_all(self):
        if not self.entries:
            QMessageBox.information(self, "Информация", "Карантин пуст.")
            return
        reply = QMessageBox.question(self, "Подтверждение", "Восстановить все записи из карантина?")
        if reply != QMessageBox.Yes:
            return
        success = []
        for entry in self.entries:
            if restore_from_quarantine(entry):
                remove_from_quarantine(entry['id'])
                success.append(entry['id'])
        self.refresh()
        QMessageBox.information(self, "Результат", f"Восстановлено {len(success)} из {len(self.entries)}.")