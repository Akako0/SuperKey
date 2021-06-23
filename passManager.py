import base64
import os
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

#TODO ---------------------------------------------------------------------------- #
#TODO                                  Color part                                  #
#TODO ---------------------------------------------------------------------------- #


class bcolors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    UNDERLINE_BLUE = '\033[0m\033[4m\033[96m'
    UNDERLINE_GREEN = '\033[4m\033[92m'
    UNDERLINE_FAIL = '\033[4m\033[91m'

#TODO ---------------------------------------------------------------------------- #
#TODO                                Function part                                 #
#TODO ---------------------------------------------------------------------------- #


#~---------------------------------------------------------------------- #
#~                             cryptography                              #
#~---------------------------------------------------------------------- #

#^ ------------------- key function ------------------ #
def get_key (passwordP):
    password_provised = passwordP
    password = password_provised.encode()
    salt = b'\x1c!\x96\xf4]v\xa3Nte\x91V(\x15\x94\xcb'
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt,
        iterations = 100000,
        backend = default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))

    return key

#^ ------------------ encode function ----------------- #
def encode_message (key, message):
    encoded = message.encode()
    f = Fernet(key)
    encoded_message = f.encrypt(encoded)
    return encoded_message

#^ ------------------ decode function ----------------- #
def decode_message (key, encoded_message):
    f = Fernet(key)
    decoded_message = f.decrypt(encoded_message)
    return decoded_message
   
#^ --------------------- test key --------------------- #
def test_key (key):
    try:
        f = Fernet(key)
        decoded_message = f.decrypt(open("pass.txt","rb").readline())
    except:
        print("|    |"+bcolors.FAIL+bcolors.UNDERLINE+"Invalid password - Unsuccessfully decrypted"+bcolors.ENDC)
        quit()


# ----------------------------------------------------------------------#
#                              Command Prompt                           #
# ----------------------------------------------------------------------#

def CommandPrompt(key):
    C = input("|    |\n|    |"+bcolors.UNDERLINE_BLUE+"Enter action:"+bcolors.ENDC+"\n|    |    |")
                        
# ---------------------- exit ------------------------ #

    if C == "exit" or C == "Exit" or C == "e" or C == "E" or C == "quit" or C == "Quit" or C == "q" or C == "Q":
        os.system('clear')
        print("|    |    |"+bcolors.UNDERLINE_BLUE+"Ok, quit.")
        quit()

# ----------------------- add ------------------------ #
    elif C == "add" or C == "Add" or C == "append" or C == "Append" or C == "a" or C == "A":
        file = open("pass.txt", "rb")
        n = len(file.read())
        file.close()
        name = input("|    |    |\n|    |    |"+bcolors.UNDERLINE_BLUE+"Enter new password name:\n"+bcolors.ENDC+"|    |    |")
        name_encode = encode_message(key, name)
        password = input("|    |    |\n|    |    |"+bcolors.UNDERLINE_BLUE+"Enter password:\n"+bcolors.ENDC+"|    |    |")
        password_encode = encode_message(key, password)
        C = input("|    |    |"+bcolors.UNDERLINE_BLUE+"are you sure you want to add '"+bcolors.BOLD+bcolors.GREEN+ name +bcolors.UNDERLINE_BLUE+"'for the password '"+bcolors.BOLD+bcolors.WARNING+password+bcolors.UNDERLINE_BLUE+"' ?"+bcolors.ENDC+"\n|    |    |")
        if C == "yes" or C == "Yes" or C == "y" or C == "Y":
            file = open("pass.txt","ab")
            if n > 10:
                file.write(b'\n')
            file.write(name_encode)
            file.write(b'\n')
            file.write(password_encode)
            file.close()
            print("|    |    |\n|    |    |"+bcolors.UNDERLINE_BLUE+"Okay writing."+bcolors.ENDC)
            CommandPrompt(key)
        else:
            print("|    |    |\n|    |    |"+bcolors.UNDERLINE_BLUE+"Okay canceled."+bcolors.ENDC)
            CommandPrompt(key)

#^ ---------------------- read ------------------------ #
    elif C == "read" or C == "Read" or C == "r" or C == "R":
        table = {}
        i = 1
        name = "None"
        file = open("pass.txt", "rb")

        for encoded_message in file: 
            
            if (i % 2) == 0:
                decoded_message = str(decode_message(key, encoded_message))
                decoded_message = decoded_message.replace("'","")
                table[name[1:]] = decoded_message[1:]
                i += 1
            else:
                name = str(decode_message(key,encoded_message))
                name = name.replace("'","")
                i += 1
        file.close()
        print("|    |    |"+bcolors.UNDERLINE_BLUE+"READ: this is your password:"+bcolors.ENDC)
        for name in table:
            print("|----|----|---------------------------------#")
            print("|    |    |",bcolors.UNDERLINE_GREEN+ name ," :"+bcolors.ENDC)
            print("|    |    |",bcolors.WARNING+ table[name] +bcolors.ENDC)
        print("|----|----|---------------------------------#")

        CommandPrompt(key)

#^ -------------------- clear chat -------------------- #
    elif C == "clear chat" or C == "Clear chat" or C == "Clear Chat" or C == "c c" or C == "C c" or C =="C C":
        os.system("clear")
        print("|    |"+bcolors.UNDERLINE_BLUE+"Chat clear."+bcolors.ENDC)
        CommandPrompt(key)

#^ ---------------------- help ------------------------ #
    elif C == "?" or C == "help":
        print("|    |welcome to passManager:\n|    |for set a password try '\033[4madd\033[0m' or '\033[4mappend\033[0m',\n|    |for read your password(s) try '\033[4mread\033[0m'.\n|    |For clear the chat try '\033[4mclear chat\033[0m' or '\033[4mc c\033[0m'(short)")
        CommandPrompt(key)

#^ --------------------- unknow ----------------------- #
    else:
        print("|    |\n|    |"+bcolors.UNDERLINE_BLUE+"sorry, '"+C+"' dosen't exist, retry\n"+bcolors.ENDC)
        CommandPrompt(key)




#TODO ---------------------------------------------------------------------------- #
#TODO                                     Main                                     #
#TODO ---------------------------------------------------------------------------- #
def __init__ ():
    os.system('clear')
    if len(open("pass.txt","rb").read()) < 30:
        print("|"+bcolors.UNDERLINE_BLUE+ "Welcome to passManager,"+bcolors.ENDC)
        time.sleep(0.5)
        Q = input("|"+bcolors.UNDERLINE_BLUE+"First, set your password and tape 'ENTER' :"+bcolors.ENDC+"\n|    |")
        if len(Q) < 2:
            print("|    |"+bcolors.UNDERLINE_BLUE+"please set a valid password."+bcolors.ENDC)
            __init__()
        else:
            time.sleep(0.5)
            key = get_key(passwordP = Q)
            print("|    |\n|    |"+bcolors.UNDERLINE_BLUE+"Your password is set to '"+Q+"'"+bcolors.ENDC)
            CommandPrompt(key)
    else:
        Q = input("|"+bcolors.UNDERLINE_BLUE+"Please enter your password:\n"+bcolors.ENDC+"|    |")
        key = get_key(passwordP = Q)
        test_key(key)
        CommandPrompt(key)
__init__()
#! --------------------------------- END FILE --------------------------------- #