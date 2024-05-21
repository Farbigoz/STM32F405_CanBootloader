# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'cpu_widget_2JEgeIK.ui'
##
## Created by: Qt User Interface Compiler version 5.15.2
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide2.QtCore import *
from PySide2.QtGui import *
from PySide2.QtWidgets import *


class Ui_cpu_2(object):
    def setupUi(self, cpu_2):
        if not cpu_2.objectName():
            cpu_2.setObjectName(u"cpu_2")
        cpu_2.resize(259, 485)
        self.verticalLayout = QVBoxLayout(cpu_2)
        self.verticalLayout.setSpacing(0)
        self.verticalLayout.setObjectName(u"verticalLayout")
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.root_box = QGroupBox(cpu_2)
        self.root_box.setObjectName(u"root_box")
        self.verticalLayout_2 = QVBoxLayout(self.root_box)
        self.verticalLayout_2.setSpacing(0)
        self.verticalLayout_2.setObjectName(u"verticalLayout_2")
        self.file_box = QGroupBox(self.root_box)
        self.file_box.setObjectName(u"file_box")
        self.formLayout = QFormLayout(self.file_box)
        self.formLayout.setObjectName(u"formLayout")
        self.formLayout.setHorizontalSpacing(6)
        self.fw_file_l = QLabel(self.file_box)
        self.fw_file_l.setObjectName(u"fw_file_l")

        self.formLayout.setWidget(0, QFormLayout.LabelRole, self.fw_file_l)

        self.fw_file_path = QLineEdit(self.file_box)
        self.fw_file_path.setObjectName(u"fw_file_path")

        self.formLayout.setWidget(0, QFormLayout.FieldRole, self.fw_file_path)

        self.select_fw_file = QPushButton(self.file_box)
        self.select_fw_file.setObjectName(u"select_fw_file")

        self.formLayout.setWidget(1, QFormLayout.SpanningRole, self.select_fw_file)

        self.fw_file_size_l = QLabel(self.file_box)
        self.fw_file_size_l.setObjectName(u"fw_file_size_l")

        self.formLayout.setWidget(2, QFormLayout.LabelRole, self.fw_file_size_l)

        self.fw_file_size = QSpinBox(self.file_box)
        self.fw_file_size.setObjectName(u"fw_file_size")
        self.fw_file_size.setMaximum(2147483647)

        self.formLayout.setWidget(2, QFormLayout.FieldRole, self.fw_file_size)

        self.fw_file_checksum_l = QLabel(self.file_box)
        self.fw_file_checksum_l.setObjectName(u"fw_file_checksum_l")

        self.formLayout.setWidget(3, QFormLayout.LabelRole, self.fw_file_checksum_l)

        self.fw_file_checksum = QLineEdit(self.file_box)
        self.fw_file_checksum.setObjectName(u"fw_file_checksum")

        self.formLayout.setWidget(3, QFormLayout.FieldRole, self.fw_file_checksum)

        self.reload_fw_file = QPushButton(self.file_box)
        self.reload_fw_file.setObjectName(u"reload_fw_file")

        self.formLayout.setWidget(4, QFormLayout.SpanningRole, self.reload_fw_file)


        self.verticalLayout_2.addWidget(self.file_box)

        self.interface_box = QGroupBox(self.root_box)
        self.interface_box.setObjectName(u"interface_box")
        self.formLayout_2 = QFormLayout(self.interface_box)
        self.formLayout_2.setObjectName(u"formLayout_2")
        self.interfaces = QComboBox(self.interface_box)
        self.interfaces.setObjectName(u"interfaces")

        self.formLayout_2.setWidget(0, QFormLayout.SpanningRole, self.interfaces)

        self.update_interfaces = QPushButton(self.interface_box)
        self.update_interfaces.setObjectName(u"update_interfaces")

        self.formLayout_2.setWidget(1, QFormLayout.SpanningRole, self.update_interfaces)


        self.verticalLayout_2.addWidget(self.interface_box)

        self.bootloader_frame = QGroupBox(self.root_box)
        self.bootloader_frame.setObjectName(u"bootloader_frame")
        self.formLayout_3 = QFormLayout(self.bootloader_frame)
        self.formLayout_3.setObjectName(u"formLayout_3")
        self.btl_version_l = QLabel(self.bootloader_frame)
        self.btl_version_l.setObjectName(u"btl_version_l")

        self.formLayout_3.setWidget(0, QFormLayout.LabelRole, self.btl_version_l)

        self.btl_version = QSpinBox(self.bootloader_frame)
        self.btl_version.setObjectName(u"btl_version")
        self.btl_version.setMaximum(255)

        self.formLayout_3.setWidget(0, QFormLayout.FieldRole, self.btl_version)

        self.btl_fw_size_l = QLabel(self.bootloader_frame)
        self.btl_fw_size_l.setObjectName(u"btl_fw_size_l")

        self.formLayout_3.setWidget(1, QFormLayout.LabelRole, self.btl_fw_size_l)

        self.btl_fw_size = QSpinBox(self.bootloader_frame)
        self.btl_fw_size.setObjectName(u"btl_fw_size")
        self.btl_fw_size.setMaximum(2147483647)

        self.formLayout_3.setWidget(1, QFormLayout.FieldRole, self.btl_fw_size)

        self.btl_fw_checksum_l = QLabel(self.bootloader_frame)
        self.btl_fw_checksum_l.setObjectName(u"btl_fw_checksum_l")

        self.formLayout_3.setWidget(2, QFormLayout.LabelRole, self.btl_fw_checksum_l)

        self.btl_fw_checksum = QLineEdit(self.bootloader_frame)
        self.btl_fw_checksum.setObjectName(u"btl_fw_checksum")

        self.formLayout_3.setWidget(2, QFormLayout.FieldRole, self.btl_fw_checksum)


        self.verticalLayout_2.addWidget(self.bootloader_frame)

        self.process_frame = QGroupBox(self.root_box)
        self.process_frame.setObjectName(u"process_frame")
        self.formLayout_4 = QFormLayout(self.process_frame)
        self.formLayout_4.setObjectName(u"formLayout_4")
        self.state_l = QLabel(self.process_frame)
        self.state_l.setObjectName(u"state_l")
        self.state_l.setEnabled(False)

        self.formLayout_4.setWidget(0, QFormLayout.LabelRole, self.state_l)

        self.state = QLabel(self.process_frame)
        self.state.setObjectName(u"state")
        self.state.setEnabled(False)

        self.formLayout_4.setWidget(0, QFormLayout.FieldRole, self.state)

        self.progress_l = QLabel(self.process_frame)
        self.progress_l.setObjectName(u"progress_l")

        self.formLayout_4.setWidget(1, QFormLayout.LabelRole, self.progress_l)

        self.progress = QProgressBar(self.process_frame)
        self.progress.setObjectName(u"progress")
        self.progress.setValue(0)

        self.formLayout_4.setWidget(1, QFormLayout.FieldRole, self.progress)

        self.stop = QPushButton(self.process_frame)
        self.stop.setObjectName(u"stop")
        self.stop.setEnabled(False)

        self.formLayout_4.setWidget(2, QFormLayout.SpanningRole, self.stop)


        self.verticalLayout_2.addWidget(self.process_frame)


        self.verticalLayout.addWidget(self.root_box)


        self.retranslateUi(cpu_2)

        QMetaObject.connectSlotsByName(cpu_2)
    # setupUi

    def retranslateUi(self, cpu_2):
        cpu_2.setWindowTitle(QCoreApplication.translate("cpu_2", u"Form", None))
        self.root_box.setTitle(QCoreApplication.translate("cpu_2", u"\u041f\u0440\u043e\u0446\u0435\u0441\u0441\u043e\u0440", None))
        self.file_box.setTitle(QCoreApplication.translate("cpu_2", u"\u0424\u0430\u0439\u043b \u043f\u0440\u043e\u0448\u0438\u0432\u043a\u0438", None))
        self.fw_file_l.setText(QCoreApplication.translate("cpu_2", u"\u041f\u0443\u0442\u044c:", None))
        self.fw_file_path.setText("")
        self.select_fw_file.setText(QCoreApplication.translate("cpu_2", u"\u0412\u044b\u0431\u0440\u0430\u0442\u044c \u0444\u0430\u0439\u043b...", None))
        self.fw_file_size_l.setText(QCoreApplication.translate("cpu_2", u"\u0420\u0430\u0437\u043c\u0435\u0440:", None))
        self.fw_file_checksum_l.setText(QCoreApplication.translate("cpu_2", u"\u041a\u043e\u043d\u0442\u0440\u043e\u043b\u044c\u043d\u0430\u044f \u0441\u0443\u043c\u043c\u0430:", None))
        self.fw_file_checksum.setText(QCoreApplication.translate("cpu_2", u"0x12345678", None))
        self.reload_fw_file.setText(QCoreApplication.translate("cpu_2", u"\u041f\u0435\u0440\u0435\u0437\u0430\u0433\u0440\u0443\u0437\u0438\u0442\u044c \u0444\u0430\u0439\u043b", None))
        self.interface_box.setTitle(QCoreApplication.translate("cpu_2", u"\u0418\u043d\u0442\u0435\u0440\u0444\u0435\u0439\u0441", None))
        self.update_interfaces.setText(QCoreApplication.translate("cpu_2", u"\u041e\u0431\u043d\u043e\u0432\u0438\u0442\u044c \u0441\u043f\u0438\u0441\u043e\u043a", None))
        self.bootloader_frame.setTitle(QCoreApplication.translate("cpu_2", u"\u0411\u0443\u0442\u043b\u043e\u0430\u0434\u0435\u0440", None))
        self.btl_version_l.setText(QCoreApplication.translate("cpu_2", u"\u0412\u0435\u0440\u0441\u0438\u044f \u0431\u0443\u0442\u043b\u043e\u0434\u0435\u0440\u0430:", None))
        self.btl_fw_size_l.setText(QCoreApplication.translate("cpu_2", u"\u0420\u0430\u0437\u043c\u0435\u0440:", None))
        self.btl_fw_checksum_l.setText(QCoreApplication.translate("cpu_2", u"\u041a\u043e\u043d\u0442\u0440\u043e\u043b\u044c\u043d\u0430\u044f \u0441\u0443\u043c\u043c\u0430:", None))
        self.btl_fw_checksum.setText(QCoreApplication.translate("cpu_2", u"0x12345678", None))
        self.process_frame.setTitle(QCoreApplication.translate("cpu_2", u"\u041f\u0440\u043e\u0446\u0435\u0441\u0441", None))
        self.state_l.setText(QCoreApplication.translate("cpu_2", u"\u0421\u043e\u0441\u0442\u043e\u044f\u043d\u0438\u0435:", None))
        self.state.setText(QCoreApplication.translate("cpu_2", u"\u041e\u0436\u0438\u0434\u0430\u043d\u0438\u0435", None))
        self.progress_l.setText(QCoreApplication.translate("cpu_2", u"\u041f\u0440\u043e\u0433\u0440\u0435\u0441\u0441:", None))
        self.stop.setText(QCoreApplication.translate("cpu_2", u"\u041f\u0440\u0438\u043d\u0443\u0434\u0438\u0442\u0435\u043b\u044c\u043d\u0430\u044f \u043e\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0430", None))
    # retranslateUi

