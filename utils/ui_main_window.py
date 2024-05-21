# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'main_windowuuaYph.ui'
##
## Created by: Qt User Interface Compiler version 5.15.2
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide2.QtCore import *
from PySide2.QtGui import *
from PySide2.QtWidgets import *


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        if not MainWindow.objectName():
            MainWindow.setObjectName(u"MainWindow")
        MainWindow.resize(802, 564)
        self.centralwidget = QWidget(MainWindow)
        self.centralwidget.setObjectName(u"centralwidget")
        self.verticalLayout_2 = QVBoxLayout(self.centralwidget)
        self.verticalLayout_2.setSpacing(0)
        self.verticalLayout_2.setObjectName(u"verticalLayout_2")
        self.verticalLayout_2.setContentsMargins(0, 0, 0, 0)
        self.frame = QFrame(self.centralwidget)
        self.frame.setObjectName(u"frame")
        self.frame.setFrameShape(QFrame.StyledPanel)
        self.frame.setFrameShadow(QFrame.Raised)
        self.verticalLayout = QVBoxLayout(self.frame)
        self.verticalLayout.setSpacing(0)
        self.verticalLayout.setObjectName(u"verticalLayout")
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.frame_3 = QFrame(self.frame)
        self.frame_3.setObjectName(u"frame_3")
        self.frame_3.setFrameShape(QFrame.StyledPanel)
        self.frame_3.setFrameShadow(QFrame.Raised)
        self.formLayout = QFormLayout(self.frame_3)
        self.formLayout.setObjectName(u"formLayout")
        self.module_type_l = QLabel(self.frame_3)
        self.module_type_l.setObjectName(u"module_type_l")

        self.formLayout.setWidget(0, QFormLayout.LabelRole, self.module_type_l)

        self.module_type = QComboBox(self.frame_3)
        self.module_type.setObjectName(u"module_type")

        self.formLayout.setWidget(0, QFormLayout.FieldRole, self.module_type)

        self.bootlaoder_version_l = QLabel(self.frame_3)
        self.bootlaoder_version_l.setObjectName(u"bootlaoder_version_l")

        self.formLayout.setWidget(1, QFormLayout.LabelRole, self.bootlaoder_version_l)

        self.bootloader_version = QComboBox(self.frame_3)
        self.bootloader_version.setObjectName(u"bootloader_version")

        self.formLayout.setWidget(1, QFormLayout.FieldRole, self.bootloader_version)

        self.same_firmware = QCheckBox(self.frame_3)
        self.same_firmware.setObjectName(u"same_firmware")

        self.formLayout.setWidget(2, QFormLayout.SpanningRole, self.same_firmware)

        self.reverse_upload = QCheckBox(self.frame_3)
        self.reverse_upload.setObjectName(u"reverse_upload")
        self.reverse_upload.setEnabled(False)

        self.formLayout.setWidget(3, QFormLayout.SpanningRole, self.reverse_upload)

        self.upload_fw = QPushButton(self.frame_3)
        self.upload_fw.setObjectName(u"upload_fw")

        self.formLayout.setWidget(4, QFormLayout.SpanningRole, self.upload_fw)

        self.force_run_fw = QPushButton(self.frame_3)
        self.force_run_fw.setObjectName(u"force_run_fw")

        self.formLayout.setWidget(5, QFormLayout.SpanningRole, self.force_run_fw)

        self.cpu_frame = QFrame(self.frame_3)
        self.cpu_frame.setObjectName(u"cpu_frame")
        self.cpu_frame.setMinimumSize(QSize(0, 0))
        self.cpu_frame.setFrameShape(QFrame.StyledPanel)
        self.cpu_frame.setFrameShadow(QFrame.Raised)
        self.horizontalLayout = QHBoxLayout(self.cpu_frame)
        self.horizontalLayout.setObjectName(u"horizontalLayout")
        self.horizontalLayout.setContentsMargins(0, 0, 0, 0)

        self.formLayout.setWidget(6, QFormLayout.SpanningRole, self.cpu_frame)

        self.log = QPlainTextEdit(self.frame_3)
        self.log.setObjectName(u"log")

        self.formLayout.setWidget(7, QFormLayout.SpanningRole, self.log)

        self.frame_2 = QFrame(self.frame_3)
        self.frame_2.setObjectName(u"frame_2")
        self.frame_2.setFrameShape(QFrame.StyledPanel)
        self.frame_2.setFrameShadow(QFrame.Raised)
        self.horizontalLayout_2 = QHBoxLayout(self.frame_2)
        self.horizontalLayout_2.setObjectName(u"horizontalLayout_2")
        self.horizontalLayout_2.setContentsMargins(0, 0, 0, 0)
        self.save = QPushButton(self.frame_2)
        self.save.setObjectName(u"save")
        self.save.setEnabled(False)

        self.horizontalLayout_2.addWidget(self.save)

        self.clear = QPushButton(self.frame_2)
        self.clear.setObjectName(u"clear")

        self.horizontalLayout_2.addWidget(self.clear)


        self.formLayout.setWidget(8, QFormLayout.SpanningRole, self.frame_2)


        self.verticalLayout.addWidget(self.frame_3)


        self.verticalLayout_2.addWidget(self.frame)

        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QMenuBar(MainWindow)
        self.menubar.setObjectName(u"menubar")
        self.menubar.setGeometry(QRect(0, 0, 802, 21))
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QStatusBar(MainWindow)
        self.statusbar.setObjectName(u"statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)

        QMetaObject.connectSlotsByName(MainWindow)
    # setupUi

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(QCoreApplication.translate("MainWindow", u"MainWindow", None))
        self.module_type_l.setText(QCoreApplication.translate("MainWindow", u"\u0422\u0438\u043f \u043c\u043e\u0434\u0443\u043b\u044f", None))
        self.bootlaoder_version_l.setText(QCoreApplication.translate("MainWindow", u"\u0412\u0435\u0440\u0441\u0438\u044f \u0431\u0443\u0442\u043b\u043e\u0434\u0435\u0440\u0430", None))
        self.same_firmware.setText(QCoreApplication.translate("MainWindow", u"\u0415\u0434\u0438\u043d\u0430\u044f \u043f\u0440\u043e\u0448\u0438\u0432\u043a\u0430 (\u043f\u0440\u043e\u0446\u0435\u0441\u0441\u043e\u0440 \u0410)", None))
        self.reverse_upload.setText(QCoreApplication.translate("MainWindow", u"\u0420\u0435\u0436\u0438\u043c \u043e\u0431\u0440\u0430\u0442\u043d\u043e\u0439 \u0437\u0430\u0433\u0440\u0443\u0437\u043a\u0438 (\u0432\u044b\u0433\u0440\u0443\u0437\u043a\u0430 \u043f\u0440\u043e\u0448\u0438\u0432\u043a\u0438 \u0438\u0437 \u043c\u043e\u0434\u0443\u043b\u044f \u0432 \u0444\u0430\u0439\u043b)", None))
        self.upload_fw.setText(QCoreApplication.translate("MainWindow", u"\u041e\u0431\u043d\u043e\u0432\u043b\u0435\u043d\u0438\u0435 \u043f\u0440\u043e\u0448\u0438\u0432\u043a\u0438", None))
        self.force_run_fw.setText(QCoreApplication.translate("MainWindow", u"\u0417\u0430\u043f\u0443\u0441\u043a \u043f\u0440\u043e\u0448\u0438\u0432\u043a\u0438", None))
        self.save.setText(QCoreApplication.translate("MainWindow", u"\u0421\u043e\u0445\u0440\u0430\u043d\u0438\u0442\u044c", None))
        self.clear.setText(QCoreApplication.translate("MainWindow", u"\u041e\u0447\u0438\u0441\u0442\u0438\u0442\u044c", None))
    # retranslateUi

