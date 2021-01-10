import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from getpass import getpass
import sys
import random
import string


class CipherText(object):
    '''
        This class handles encryption and decryption requests
        encrypt -> Encrypts data, takes  plain text as arguement
        decrypt-> Decrypts data, takes encrypted text as argument
    '''

    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def __pad(self, plain_text):
        total_bytes = self.bs - len(plain_text) % self.bs
        a_string = chr(total_bytes)
        padding = total_bytes * a_string
        plain_text_with_padding = plain_text + padding
        return plain_text_with_padding

    @staticmethod
    def __unpad(plain_text):
        last_char = plain_text[len(plain_text) - 1:]
        extra_bytes = ord(last_char)
        return plain_text[:-extra_bytes]

    def encrypt(self, plain_text):
        plain_text = self.__pad(plain_text)
        iv = Random.new().read(self.bs)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text.encode())
        return b64encode(iv + encrypted_text).decode("utf-8")

    def decrypt(self, encrypted_text):
        encrypted_text = b64decode(encrypted_text)
        initialisation_vector = encrypted_text[:self.bs]
        cipher = AES.new(self.key, AES.MODE_CBC, initialisation_vector)
        plain_text = cipher.decrypt(encrypted_text[self.bs:]).decode("utf-8")
        return self.__unpad(plain_text)


def authorize(user, pawd, key, Admin, users):
    '''
        authorize function handles the authentication part
        takes 3 input arguements, user to store the username
        pawd to store the password and users dictionary for
        storing username/password entries

    '''
    newObj = CipherText(key)
    chances = 2
    secPin = '1234'
    isInitialLogin = True

    try:
        if user == 'Admin':
            while chances > 0:
                if pawd == Admin['Admin'] and chances > 0:
                    if isInitialLogin is True:
                        print('Access granted')
                        isInitialLogin = False
                    adminFunc(user, Admin, users)


                else:
                    pawd = getpass('Password:')
                    chances -= 1
                    pin = getpass('Enter Secret pin to print the admin password')
                    if pin == secPin:
                        print('The password for admin is', Admin['Admin'])
                        break



        else:
            while chances > 0:
                if pawd == users[user] and chances > 0:
                    if isInitialLogin is True:
                        print('Access granted')
                        isInitialLogin = False
                    userFunc(user, pawd, users, key, newObj)

                else:
                    pawd = getpass('Password:')
                    chances -= 1
                    if chances <= 0:
                        print('you have entered wrong password 3 times, please contact Admin for password reset')
                        break
    except Exception as e:
        print(e)
        sys.exit(0)


def adminFunc(user, Admin, users=None):
    '''
        adminFunc functions handles the admin user functionality
        user can choose between options d-> delete user
        u-> change user password, a-> add new user, c-> change admin password,
        l -> logout user
    '''
    ch = input(
        'D -> to delete a user, U-> to change the password of user, A -> to add another user, C-> change admin '
        'password, l -> logout, i -> print users').lower()
    print('     ')
    if ch == 'd':
        print(list(users.keys()))
        user = input('Please enter the username -->')
        if user in users.keys():
            users.pop(user)
            print(f'{user} deleted')
        else:
            print(f'{user} not available')

    elif ch == 'u':
        user = input('Please enter the username -->')
        if user in users:
            print('Please enter the new password --> ')
            pawd = getpass('Password:')
            users[user] = pawd
            print((f'{user} password updated'))
        else:
            print(f'{user} not available')

    elif ch == 'a':
        user = input('Please enter the username -->')
        if user in users:
            print(f'{user} already a member')
        else:
            print('Please enter the new password --> ')
            pawd = getpass('Password:')
            users[user] = pawd
            print((f'{user} added'))
    elif ch == 'l':
        print((f'Admin logged out'))
        user = input('Enter Username --> ')
        pawd = input('Enter your password -->')
        authorize(user, pawd,key ,  Admin, users)
    elif ch == 'c':
        opawd = getpass('Enter Old password:')
        if opawd == Admin['Admin']:
            npawd = getpass('Enter new password:')
            if npawd == '':
                print('Invalid password')
            else:
                Admin['Admin'] = npawd
    elif ch == 'i':
        print('list of users')
        if users:
            print(list(users.keys()))
    else:
        print('invalid entry')


def getKey(length=10):
    '''
        getKey funtion generates key for AES encryption/decryption
    '''
    print('Secret key generated')
    letters = string.ascii_lowercase
    key = ''.join(random.choice(letters) for i in range(length))
    return key


def userFunc(user, pawd, users, key, newObj):
    '''
        userFunc function handles regular users functionality,
        user can choose between these options, U -> to update the password,
        E -> to encrypt the data, D -> to decrypt the data, l -> logout
    '''
    print('U -> to update the password, E -> to encrypt the data, D -> to decrypt the data, l -> logout')
    ch = input("Enter your choice").lower()
    if ch == 'u':
        opawd = getpass('Enter Old password:')
        if opawd == pawd:
            npawd = getpass('Enter new password:')
            if npawd == '':
                print('Invalid password')
            else:
                users[user] = npawd
                print('Password Updated')
    elif ch == 'e':
        PlnTxt = input('Enter the plain text')
        encrStr = newObj.encrypt(PlnTxt)
        print('The encrypted text is', encrStr)
    elif ch == 'd':
        encrStr = input('Please enter the encrypted text')
        plnTxt = newObj.decrypt(encrStr)
        print('The plain text is', plnTxt)
    elif ch == 'l':
        print((f'{user} logged out'))
        user = input('Enter Username')
        pawd = getpass('Enter your password')
        authorize(user, pawd, key,  Admin, users)
    else:
        print('Invalid Entry, choose another option ')


if __name__ == "__main__":
    print('Welcome to the secure systems, Unauthorized access monitored')
    print('************ Please leave if not authorized ****************')
    key = getKey(10)
    users = {'default': 'default'}
    Admin = {'Admin': 'admin'}
    user = input('Please enter your username')
    pawd = getpass('Password:')
    authorize(user, pawd, key, Admin, users)