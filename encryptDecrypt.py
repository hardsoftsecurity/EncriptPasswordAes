import base64
from Crypto import Random
from Crypto.Cipher import AES

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-s[-1]]

class AESCipher:

    def __init__( self, key ):
        self.key = key

    def encrypt( self, raw ):
        raw = pad(raw)
        iv = Random.new().read( AES.block_size )
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return base64.b64encode( iv + cipher.encrypt( raw ) )

    def decrypt( self, enc ):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return unpad(cipher.decrypt( enc[16:] ))


while True:
    select = int(input("1. Encriptar password. \n2. Desencriptar password. \n3. Salir del script. \n"))

    if select == 1:
        password = str(input("Introducir la password de cifrado maestra de 16 bytes: "))
        general = AESCipher(password)
        passcifrar = str(input("Introducir la password a cifrar: "))
        encriptar = general.encrypt(passcifrar)
        print("La contraseña encryptada es: %s" % encriptar )
        exit()
    elif select == 2:
        password = str(input("Introducir la password de descifrado maestra de 16 bytes: "))
        general = AESCipher(password)
        passdescifrar = str(input("Introducir la password a descifrar: "))
        descifrar = general.decrypt(passdescifrar)
        print("La contraseña descifrada es: %s" % descifrar)
        exit()
    elif select == 3:
        exit()
