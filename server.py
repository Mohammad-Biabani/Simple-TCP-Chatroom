from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from cipher import *
import threading
import socket
import os
import lzma
import time
from decoration import Decoration

host = '127.0.0.1'
port = 15000

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen()

class User:
    def __init__(self, username, password, is_online=False, is_banned=False, client='', addresss='', salt = b'', key = b''):
        self.client = client
        self.address = addresss
        self.username = username
        self.password = password
        self.is_online = is_online
        self.is_banned = is_banned
        self.salt = salt
        self.key = key
        
    def __str__(self):
        return f'client = {self.client},\naddress = {self.address},\nusername = {self.username},\npassword = {self.password},\nis_online = {self.is_online}'
        

admin = User(username='admin', password='adminpass')
mmd = User(username='mmd', password='1234')
ali = User(username='ali', password='4321')

users = [admin, mmd, ali]
  

def handle_if_user_is_online(user, key):
    if user.is_online is True:
        post('New attempt to login. this connection is going to close.',client=user.client, key=user.key)
        user.client.close()
        time.sleep(0.5)

def register(username, password):
    usernames_list = get_username_list(users)
    if username in usernames_list:
        return False
    else:
        user = User(username=username, password=password)
        users.append(user)
        return True

def get_username_list(users=[]):
    username_list = []
    for user in users:
        username_list.append(user.username)
    return username_list

def find_password(username):
    password = ''
    for user in users:
        if username == user.username:
            password = user.password
            break
    return password

def find_user(username):
    for user in users:
        if username == user.username:
            return user
    return False

def make_user_online(username, client, address, salt, key):
    for user in users:
        if username == user.username:
            user.client = client
            user.address = address
            user.is_online = True
            user.salt = salt
            user.key = key
 
def make_user_offline(username):
    for user in users:
        if username == user.username:
            user.client = ''
            user.address = ''
            user.is_online = False   
            user.salt = b''
            user.key = b''
    
def broadcast(message):
    for user in users:
        if user.is_online is True:
            post(message=message, client=user.client, key=user.key)

def public_broadcast(username, message):
    data = message.split('\r\n')
    msg_len = data[0][23:-1]
    msg_body = ''
    for i in range(len(data)):
        if i == 0:
            continue
        elif i == 1:
            msg_body += data[i]
        else:
            msg_body += ('\r\n' + data[i])
    for user in users:
        if user.is_online is True:
            post(f'Public message from {username}, length={msg_len}:\r\n{msg_body}', client=user.client, key=user.key)
    print(Decoration.Bold + '[' + Decoration.Reset + Decoration.Cyan + Decoration.Bold + f'RESPONSE to {username}' + Decoration.Reset + Decoration.Bold + '] ' + Decoration.Reset + Decoration.Cyan + f'Public message from {username}, length={msg_len}:\r\n{msg_body}' + Decoration.Reset)

def private_broadcast(username, message, client, key):
    data = message.split(' ')
    msg_len = data[2][7:]
    target_users_list_in_strig = message.split('\r\n')[0].split(' ')[4][:-1]
    target_users_list = target_users_list_in_strig.split(',')
    is_qualified = qualify_target_user_list(target_users_list)
    if is_qualified is False:
        print(Decoration.Bold + '[' + Decoration.Reset + Decoration.Cyan + Decoration.Bold + f'RESPONSE to {username}' + Decoration.Reset + Decoration.Bold + '] ' + Decoration.Reset + Decoration.Cyan + 'Operation failed because of inappropriate target users list. One or some of your target users are not exist or are not online.' + Decoration.Reset)
        return post('Operation failed because of inappropriate target users list. One or some of your target users are not exist or are not online.', client=client, key=key)
    new_data = message.split('\r\n')
    msg_body = ''
    for i in range(len(new_data)):
        if i == 0:
            continue
        elif i == 1:
            msg_body += new_data[i]
        else:
            msg_body += ('\r\n' + new_data[i])
            
    for name in target_users_list:
        user = find_user(username=name)
        post(f'Private message, length={msg_len} from {username} to {target_users_list_in_strig}:\r\n{msg_body}', client=user.client, key=user.key)
    print(Decoration.Bold + '[' + Decoration.Reset + Decoration.Cyan + Decoration.Bold + f'RESPONSE to {username}' + Decoration.Reset + Decoration.Bold + '] ' + Decoration.Reset + Decoration.Cyan + f'Private message, length={msg_len} from {username} to {target_users_list_in_strig}:\r\n{msg_body}' + Decoration.Reset)

def exit_user(username, client):
    client.close()
    make_user_offline(username)
    broadcast(f'{username} left the chat room.')
    print(Decoration.Bold + '[' + Decoration.Reset + Decoration.Yellow + Decoration.Bold + 'NOTIFICATION' + Decoration.Reset + Decoration.Bold + Decoration.Bold + '] ' + Decoration.Reset + Decoration.Reset + Decoration.Yellow + f'{username} left the chat room.' + Decoration.Reset)
    
def qualify_target_user_list(target_users_list):
    for username in target_users_list:
        user = find_user(username=username)
        if user is False:
            return False
        else:
            if user.is_online is False:
                return False
    return True


def send_attendees(username, client, key):
    attendees_list = []
    for user in users:
        if user.is_online is True:
            attendees_list.append(user.username)
    attendees_list_in_string = ''
    for username in attendees_list:
        attendees_list_in_string += (username + ',')
    attendees_list_in_string = attendees_list_in_string[:-1]
    post(f'Here is the list of attendees:\r\n{attendees_list_in_string}', client=client, key=key)
    print(Decoration.Bold + '[' + Decoration.Reset + Decoration.Cyan + Decoration.Bold + f'RESPONSE to {username}' + Decoration.Reset + Decoration.Bold + '] ' + Decoration.Reset + Decoration.Cyan + f'Here is the list of attendees:\r\n{attendees_list_in_string}' + Decoration.Reset)

def kick_user(username):
    user = find_user(username=username)
    post('You are going to kicked out by the admin...', client=user.client, key=user.key)
    user.client.close()
    make_user_offline(username)
    broadcast(f'admin kicked out {username}.')
    print(Decoration.Bold + '[' + Decoration.Reset + Decoration.Cyan + Decoration.Bold + f'RESPONSE to admin' + Decoration.Reset + Decoration.Bold + '] ' + Decoration.Reset + Decoration.Cyan + f'admin kicked out {username}.' + Decoration.Reset)

def ban_user(username):
    user = find_user(username=username)
    post('You are banned. This connection going to close...', client=user.client, key=user.key)
    user.client.close()
    make_user_offline(username)
    for user in users:
        if username == user.username:
            user.is_banned = True
    broadcast(f'{username} banned by the admin.')
    print(Decoration.Bold + '[' + Decoration.Reset + Decoration.Cyan + Decoration.Bold + f'RESPONSE to admin' + Decoration.Reset + Decoration.Bold + '] ' + Decoration.Reset + Decoration.Cyan + f'{username} banned by the admin.' + Decoration.Reset)

def unban_user(username):
    for user in users:
        if username == user.username:
            user.is_banned = False
    broadcast(f'{username} has been unbanned')
    print(Decoration.Bold + '[' + Decoration.Reset + Decoration.Cyan + Decoration.Bold + f'RESPONSE to admin' + Decoration.Reset + Decoration.Bold + '] ' + Decoration.Reset + Decoration.Cyan + f'{username} has been unbanned' + Decoration.Reset)

def receive_file(data, username, client):
    user = find_user(username=username)
    post('Upload process', client=client, key=user.key)
    data_list = data.split(' ')
    original_file_name = data_list[3].removeprefix('original_file_name=').removesuffix(',')
    new_file_name = data_list[4].removeprefix('new_file_name=')
    post(original_file_name, client=client, key=user.key)
    post(new_file_name, client=client, key=user.key)
    file_name = client.recv(1024).decode()
    file = open(file_name, 'wb')
    compressed_data_len = client.recv(1024).decode()
    compressed_file_bytes = b''
    done = False

    while not done:
        if str(len(compressed_file_bytes)) != compressed_data_len:
            data = client.recv(1024)
            compressed_file_bytes += data
        else:
            done = True
    
    file_bytes = lzma.decompress(compressed_file_bytes)
    file.write(file_bytes)
    file.close()
    print(Decoration.Bold + '[' + Decoration.Reset + Decoration.Cyan + Decoration.Bold + f'RESPONSE to {username}' + Decoration.Reset + Decoration.Bold + '] ' + Decoration.Reset + Decoration.Cyan + f'{file_name} succesfully received from {username}' + Decoration.Reset)
    broadcast(f'{file_name} uploaded by {username}')

def send_file(data, username, client):
    user = find_user(username=username)
    post('Download process', client=client, key=user.key)
    data_list = data.split(' ')
    original_file_name = data_list[3].removeprefix('original_file_name=').removesuffix(',')
    new_file_name = data_list[4].removeprefix('new_file_name=')
    file = open(original_file_name, 'rb')
    client.send(new_file_name.encode())
    data = file.read()
    compressed_data = lzma.compress(data)
    client.send(str(len(compressed_data)).encode())
    client.sendall(compressed_data)
    file.close()
    print(Decoration.Bold + '[' + Decoration.Reset + Decoration.Cyan + Decoration.Bold + f'RESPONSE to {username}' + Decoration.Reset + Decoration.Bold + '] ' + Decoration.Reset + Decoration.Cyan + f'{new_file_name} succesfully sended to {username}.' + Decoration.Reset)
    broadcast(f'{new_file_name} downloaded by {username}')

def is_socket_closed(sock):
    try:
        sock.send(b'')
        return False  # Socket is not closed
    except (socket.timeout, socket.error):
        return True  # Socket is closed or there's an error

def handle(client, username):
    while True:
        try:
            if is_socket_closed(client):
                continue
            user = find_user(username=username)
            message = get(client=client, key=user.key)
            print(Decoration.Bold + '[' + Decoration.Reset + Decoration.Magenta + Decoration.Bold + f'REQUEST from {username}' + Decoration.Reset + Decoration.Bold + '] ' + Decoration.Reset + Decoration.Magenta + message + Decoration.Reset)
            if message.startswith('/'):
                if username == 'admin':
                    if message.startswith('/Kick'):
                        data = message.split(' ')
                        name_to_kick = data[1]
                        kick_user(username=name_to_kick)
                    elif message.startswith('/Ban'):
                        data = message.split(' ')
                        name_to_ban = data[1]
                        ban_user(username=name_to_ban)
                    elif message.startswith('/Unban'):
                        data = message.split(' ')
                        name_to_unban = data[1]
                        unban_user(username=name_to_unban)
                    elif message.startswith('/Shut'):
                        broadcast('server gonna shut down by the admin command...')
                        print(Decoration.Bold + '[' + Decoration.Reset + Decoration.Cyan + Decoration.Bold + f'RESPONSE to {username}' + Decoration.Reset + Decoration.Bold + '] ' + Decoration.Reset + Decoration.Cyan + 'server gonna shut down by the admin command...' + Decoration.Reset)
                        server.close()
                        os._exit(0)
                else:
                    post('Commands can only be executed by the admin!', client=client, key=user.key)
            elif message.startswith('Upload'):
                receive_file(data=message, username=username, client=client)
            elif message.startswith('Download'):
                send_file(data=message, username=username, client=client)
            elif message.startswith('Please'):
                send_attendees(username=username, client=client, key=user.key)
            elif message.startswith('Private'):
                private_broadcast(username=username,message=message, client=client, key=user.key)
            elif message.startswith('Public'):
                public_broadcast(username=username,message=message)
            elif message.startswith('Bye'):
                exit_user(username=username, client=client)
        except:
            client.close()
            make_user_offline(username)
            broadcast(f'{username} left the chat room.')
            print(Decoration.Bold + '[' + Decoration.Reset + Decoration.Yellow + Decoration.Bold + 'NOTIFICATION' + Decoration.Reset + Decoration.Bold + '] ' + Decoration.Reset + Decoration.Yellow + f'{username} left the chat room.' + Decoration.Reset)
            break
        
def receive():
    while True:
        client, address = server.accept()
        print(Decoration.Bold + '[' + Decoration.Reset + Decoration.Yellow + Decoration.Bold + 'NOTIFICATION' + Decoration.Reset + Decoration.Bold + '] ' + Decoration.Reset + Decoration.Yellow + f'Connected with {str(address)}' + Decoration.Reset)
        
        time.sleep(2)
        client.send('Welcome'.encode('ascii'))
        init_operatoin = client.recv(1024).decode('ascii')
        
        if init_operatoin.startswith('Registration'):
            data = init_operatoin.split(' ')
            is_registered = register(username=data[1], password=data[2])
            if is_registered is True:
                client.send('Accept'.encode('ascii'))
                continue
            else:
                client.send('Refuse'.encode('ascii'))
                continue
        else:
            data = init_operatoin.split(' ')
            user = find_user(data[1])
            
            if user is False:
                client.send('Refuse'.encode('ascii'))
                client.close()
                continue
            elif user.is_banned is True:
                client.send('Banned'.encode('ascii'))
                client.close()
                continue
            else:
                client.send('Accept'.encode('ascii'))
                
            salt = get_random_bytes(32)
            key = PBKDF2(password=user.password, salt=salt, dkLen=32)
            client.send(b'Key ' + salt )
            try:
                if get(client=client, key=key) == f'Hello {data[1]}':
                    post(message=f'Hi {data[1]}, welcome to the chat room.', client=client, key=key)
                else:
                    post('Refuse', client=client, key=key)
                    client.close()
                    continue
            except:
                post('Refuse', client=client, key=key)
                client.close()
                continue
            
            handle_if_user_is_online(user=user, key=key)
            make_user_online(username=user.username,client=client,address=address, salt=salt, key=key)

        print(Decoration.Bold + '[' + Decoration.Reset + Decoration.Yellow + Decoration.Bold + 'NOTIFICATION' + Decoration.Reset + Decoration.Bold + Decoration.Bold + '] ' + Decoration.Reset + Decoration.Reset + Decoration.Yellow + f'{data[1]} joined the Chat room.' + Decoration.Reset)
        broadcast(f'{data[1]} joined the chat room.')
        


        thread = threading.Thread(target=handle, args=(client, data[1],))
        thread.start()      

print(Decoration.Bold + 'server is listening...' + Decoration.Reset)
receive()

        
        
    