import sys
import res_rc
import base64
import subprocess
from PIL import Image
from io import BytesIO
from random import randint
from base64 import b64encode
from PyQt5.uic import loadUi
from Crypto.Cipher import AES
from PyQt5 import QtCore, QtWidgets
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from PyQt5.QtWidgets import QApplication, QMainWindow, QStackedWidget, QDialog



class TransparentMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowFlags(QtCore.Qt.FramelessWindowHint)
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground)
        # Load the UI file for the home page
        home_page = HomePage(self)
        home_page.goToEncrypt.connect(self.showEncryptPage)
        home_page.goToDecrypt.connect(self.showDecryptPage)
        # Create the stacked widget and add the pages
        self.widget = QStackedWidget(self)
        self.widget.setObjectName("stackedWidget")
        self.widget.addWidget(home_page)
        # Adjust the size of the window to fit the content
        self.widget.setCurrentIndex(0)  # Show the home page
        self.resize(self.widget.currentWidget().size())
        # Set the TransparentMainWindow as the main window
        self.setCentralWidget(self.widget)
        # Show the window
        self.show()

    def showEncryptPage(self):
        encrypt_dialog = EncryptDialog(self)
        encrypt_dialog.goToHome.connect(self.goToHomePage)
        encrypt_dialog.goToDecrypt.connect(self.showDecryptPage)
        self.widget.addWidget(encrypt_dialog)
        self.widget.setCurrentWidget(encrypt_dialog)

    def showDecryptPage(self):
        decrypt_dialog = DecryptDialog(self)
        decrypt_dialog.goToHome.connect(self.goToHomePage)
        decrypt_dialog.goToEncrypt.connect(self.showEncryptPage)
        self.widget.addWidget(decrypt_dialog)
        self.widget.setCurrentWidget(decrypt_dialog)

    def goToHomePage(self):
        self.show()  # Show the main window
        self.widget.setCurrentWidget(self.widget.widget(0))

class HomePage(QDialog):
    goToEncrypt = QtCore.pyqtSignal()  # Signal to go to the encryption page
    goToDecrypt = QtCore.pyqtSignal()  # Signal to go to the decryption page

    def __init__(self, parent=None):
        super().__init__(parent)
        loadUi('home.ui', self)
        # Connect button signals
        self.pushButton1.clicked.connect(self.goToEncryptPage)
        self.pushButton2.clicked.connect(self.goToDecryptPage)
        self.closeButton.clicked.connect(self.closeEvent)
        #shadow effect
        self.label_1.setGraphicsEffect(QtWidgets.QGraphicsDropShadowEffect(blurRadius=25, xOffset=0, yOffset=0))
        self.label_2.setGraphicsEffect(QtWidgets.QGraphicsDropShadowEffect(blurRadius=25, xOffset=0, yOffset=0))
        self.label_7.setGraphicsEffect(QtWidgets.QGraphicsDropShadowEffect(blurRadius=25, xOffset=0, yOffset=0))
        self.label_5.setGraphicsEffect(QtWidgets.QGraphicsDropShadowEffect(blurRadius=25, xOffset=0, yOffset=0))
        self.pushButton1.setGraphicsEffect(QtWidgets.QGraphicsDropShadowEffect(blurRadius=25, xOffset=3, yOffset=3))
        self.pushButton2.setGraphicsEffect(QtWidgets.QGraphicsDropShadowEffect(blurRadius=25, xOffset=3, yOffset=3))

    def goToEncryptPage(self):
        self.goToEncrypt.emit()

    def goToDecryptPage(self):
        self.goToDecrypt.emit()

    def closeEvent(self, event): 
        sys.exit()


class EncryptDialog(QDialog):
    goToHome = QtCore.pyqtSignal()  # Signal to go to the home page
    goToDecrypt = QtCore.pyqtSignal()  # Signal to go to the decryption dialog

    def __init__(self, parent=None):
        super().__init__(parent)
        loadUi('encrypt.ui', self)
        # Connect button signals
        self.pushButton3_2.clicked.connect(self.closeEvent)
        self.pushButton2.clicked.connect(self.goToHome.emit)
        self.pushButton3.clicked.connect(self.goToDecrypt.emit)
        self.pushButton1.clicked.connect(self.encrypt)

        #shadow effect
        self.label_1.setGraphicsEffect(QtWidgets.QGraphicsDropShadowEffect(blurRadius=25, xOffset=0, yOffset=0))
        self.label_2.setGraphicsEffect(QtWidgets.QGraphicsDropShadowEffect(blurRadius=25, xOffset=0, yOffset=0))
        self.label_5.setGraphicsEffect(QtWidgets.QGraphicsDropShadowEffect(blurRadius=25, xOffset=0, yOffset=0))
        self.pushButton1.setGraphicsEffect(QtWidgets.QGraphicsDropShadowEffect(blurRadius=25, xOffset=3, yOffset=3))

    def closeEvent(self, event):
        sys.exit()
        

    @staticmethod
    def rgbScrambler(pt, x, y, i):
        scrambleType = {
            0: (pt, x, y),
            1: (y, pt, x),
            2: (x, y, pt)
        }
        return scrambleType.get(i % 3)

    def encrypt(self):
        lineEdit = self.lineEdit.toPlainText()
        key = self.lineEdit_2.text()
        if not lineEdit:
            QtWidgets.QMessageBox.warning(self, "Error", "Message field is empty!")
            return
        if not key:
            QtWidgets.QMessageBox.warning(self, "Error", "Key is empty!")
            return

        print(key)
        msg_file = BytesIO()
        msg_file.write(lineEdit.encode('utf-8'))
        msg_file.seek(0)

        key = key.encode('UTF-8')
        key = pad(key, AES.block_size)

        img = Image.new('RGB', (256, 256), color=(0, 0, 0))
        pixels = img.load()

        pt = bytearray(msg_file.read())

        xPts = [0]
        yPts = [0]
        for i in range(0, len(pt)):
            x = randint(0, 254)
            y = randint(0, 254)
            while (x in xPts) and (y in yPts):
                x = randint(0, 254)
                y = randint(0, 254)
            xPts.append(x)
            yPts.append(y)
            pixels[xPts[i], yPts[i]] = self.rgbScrambler(pt[i], x, y, i)

        img.save('encryptedImage.png')
        with open('encryptedImage.png', 'rb') as entry:
            data = entry.read()
            data = pad(data, AES.block_size)
            cipher = AES.new(key, AES.MODE_CFB)
            ciphertext = cipher.encrypt(data)
            iv = b64encode(cipher.iv).decode('UTF-8')
            ciphertext = b64encode(ciphertext).decode('UTF-8')
            to_write = iv + ciphertext
        entry.close()
        save_path, _ = QtWidgets.QFileDialog.getSaveFileName(None, "Save File", "", "Encrypted Files (*.enc)")
        if save_path:
            with open(save_path, 'w') as data:
                data.write(to_write)
                QtWidgets.QMessageBox.information(None, "Encryption", "Encryption completed successfully!")
        if not save_path:
            QtWidgets.QMessageBox.warning(None, "Error", "File save operation canceled!")



class DecryptDialog(QDialog):
    goToHome = QtCore.pyqtSignal()  # Signal to go to the home page
    goToEncrypt = QtCore.pyqtSignal()  # Signal to go to the encryption dialog

    def __init__(self, parent=None):
        super().__init__(parent)
        loadUi('decrypt.ui', self)
        # Connect button signals
        self.pushButton3_2.clicked.connect(self.closeEvent)
        self.pushButton2.clicked.connect(self.goToHome.emit)
        self.pushButton3.clicked.connect(self.goToEncrypt.emit)
        self.pushButton1.clicked.connect(self.decrypt)
        self.browse.clicked.connect(self.browsefile)
        self.clear2.clicked.connect(self.clearfield)
        #shadow effects
        self.label_1.setGraphicsEffect(QtWidgets.QGraphicsDropShadowEffect(blurRadius=25, xOffset=0, yOffset=0))
        self.label_2.setGraphicsEffect(QtWidgets.QGraphicsDropShadowEffect(blurRadius=25, xOffset=0, yOffset=0))
        self.label_5.setGraphicsEffect(QtWidgets.QGraphicsDropShadowEffect(blurRadius=25, xOffset=0, yOffset=0))
        self.pushButton1.setGraphicsEffect(QtWidgets.QGraphicsDropShadowEffect(blurRadius=25, xOffset=3, yOffset=3))
        self.filename=""



    def closeEvent(self, event):
        sys.exit()

    def browsefile(self):
        filename, _ = QtWidgets.QFileDialog.getOpenFileName(None, "Select File", "", "(*.enc)")
        if filename:
            if not filename.endswith('.enc'):
                QtWidgets.QMessageBox.warning(self, "Error", "Invalid file format. Please select an encrypted file (.enc).")
                return
            self.filename = filename
            self.lineEdit_3.setText(self.filename)

    def clearfield(self):
        self.lineEdit_2.clear()
        self.lineEdit_3.clear()
        self.lineEdit.clear()
            
    def decrypt(self):
        try:
            key = self.lineEdit_2.text()
            self.filename = self.lineEdit_3.text()
            if not hasattr(self, 'filename') or not self.filename:
                QtWidgets.QMessageBox.warning(self, "Error", "No file selected!")
                return

            if not key:
                QtWidgets.QMessageBox.warning(self, "Error", "Key not entered!")
                return

            key = key.encode('UTF-8')
            key = pad(key, AES.block_size)

            with open(self.filename, 'r') as entry:
                data = entry.read()
                iv = data[:24]
                iv = base64.b64decode(iv)
                ciphertext = data[24:]
                ciphertext = base64.b64decode(ciphertext)
                cipher = AES.new(key, AES.MODE_CFB, iv=iv)
                decrypted = cipher.decrypt(ciphertext)
                decrypted = unpad(decrypted, AES.block_size)

                with open('decrypted_image.png', 'wb') as data:
                    data.write(decrypted)

                EncryptedImage = Image.open('decrypted_image.png')
                encRGB = EncryptedImage.convert("RGB")
                decryptedPixel = [[0 for i in range(256)] for i in range(256)]

                for i in range(0, 256):
                    for j in range(0, 256):
                        encR, encG, encB = encRGB.getpixel((i, j))
                        msgR = int(encR)
                        msgG = int(encG)
                        msgB = int(encB)

                        if msgR < 0:
                            msgR = msgR + 255
                        if msgG < 0:
                            msgG = msgG + 255
                        if msgB < 0:
                            msgB = msgB + 255

                        decryptedPixel[i][j] = int(msgR), int(msgG), int(msgB)

                msgCount = 0
                Xa = 0
                Ya = 0

                decrypted_message = open("decryptedMessage.txt", "w+")

                while True:
                    message = decryptedPixel[Xa][Ya][msgCount % 3]
                    newXa = decryptedPixel[Xa][Ya][(msgCount + 1) % 3]
                    Ya = decryptedPixel[Xa][Ya][(msgCount + 2) % 3]
                    Xa = newXa

                    msgCount = msgCount + 1

                    if Xa == 0 and Ya == 0:
                        break

                    print("%c" % (message), end="")
                    decrypted_message.write("%c" % (message))

                decrypted_message.close()
            # Show a message box indicating successful encryption
            QtWidgets.QMessageBox.information(self, "Decryption", "Decryption completed successfully!")

            
            with open("decryptedMessage.txt", "r") as file:
                decrypted_contents = file.read()

                 # Set the decrypted contents as the text of the lineEdit widget
            self.lineEdit.setText(decrypted_contents)

        except(ValueError, KeyError):
            QtWidgets.QMessageBox.information(self, "Decryption", "Wrong Key")
            print('Wrong key')
            
        

if __name__ == "__main__":

    app = QApplication([])
    window = TransparentMainWindow()
    app.exec_()
    sys.exit(app.exec_())