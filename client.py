from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from cipher import *
import socket
import threading
import tkinter
import tkinter.scrolledtext
from tkinter import simpledialog
from tkinter import messagebox
import os
import ast
import lzma
import time
from decoration import Decoration

host = 'localhost'
port = 15000

class Client:
    def __init__(self, host, port):
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))

        msg = tkinter.Tk()
        msg.withdraw()

        self.item = simpledialog.askstring('Item', 'Please choose an item: 1-login 2-sign up', parent=msg)
        self.username = simpledialog.askstring('Username', 'Username:', parent=msg)
        self.password = simpledialog.askstring('Password', 'Password:', parent=msg)

        self.stop_thread = False
        self.key = ''

        self.gui_done = False
        self.running = True
        
        gui_thread = threading.Thread(target=self.gui_loop)
        receive_thread = threading.Thread(target=self.receive)

        gui_thread.start()
        receive_thread.start()


    def gui_loop(self):
        self.win = tkinter.Tk()
        self.win.title(self.username)
        self.win.configure(bg='#0e1621')

        self.chat_label = tkinter.Label(self.win, text='Chat:', bg='#0e1621', fg='white') #lightgray
        self.chat_label.config(font=('Comfortaa', 12))
        self.chat_label.pack(padx=20, pady=5)

        self.text_area = tkinter.scrolledtext.ScrolledText(self.win, background='#2b5378', foreground='white', font=('Comfortaa', 12))
        self.text_area.pack(padx=20, pady=5)
        self.text_area.config(state='disabled')
        
        self.msg_label = tkinter.Label(self.win, text='Message:', bg='#0e1621', fg='white')
        self.msg_label.config(font=('Comfortaa', 12))
        self.msg_label.pack(padx=20, pady=5)
        
        self.input_area = tkinter.Text(self.win, height=3, background='#2b5378', foreground='white', font=('Comfortaa', 12))
        self.input_area.bind("<KeyPress>", self.shortcut)
        self.input_area.pack(padx=20, pady=5)
        
        self.send_button = tkinter.Button(self.win, text='Send', command=self.write)
        self.send_button.config(font=('Comfortaa', 12))
        self.send_button.pack(padx=20, pady=5)
        
        self.gui_done = True

        self.win.protocol('WM_DELETE_WINDOW', self.stop)
    
        self.win.mainloop()
    
    
    def stop(self):
        self.running = False
        self.win.destroy()
        self.sock.close()
        exit(0)
        os._exit(0)
        
    def shortcut(self, event):
        if event.state == 4 and event.keysym == 'Return':
            self.write()
        
    def gprint(self, message):
        self.text_area.config(state='normal')
        self.text_area.insert('end', message)
        self.text_area.yview('end')
        self.text_area.config(state='disabled')  
    
    def receive(self):
        while self.running:
            if self.stop_thread is True:
                break
            if self.gui_done is False:
                continue
            try:
                message = self.sock.recv(1024).decode('ascii')
                if message == 'Welcome':
                    if self.item == '1':
                        self.sock.send(f'Login {self.username}'.encode('ascii'))
                        next_message = self.sock.recv(1024).decode('ascii')
                        if next_message == 'Refuse':
                            self.gprint('Wrong usernname. please try again.')
                            print(Decoration.Bold + '[' + Decoration.Reset + Decoration.Bold + Decoration.Red + 'ERROR' + Decoration.Reset + Decoration.Bold + '] ' + Decoration.Reset + Decoration.Red + 'Wrong usernname. please try again.' + Decoration.Reset)
                            time.sleep(3)
                            self.stop_thread = True
                            self.sock.close()
                            os._exit(0) 
                        elif next_message == 'Banned':
                            self.gprint(message='Could not connect. You are banned.')
                            print(Decoration.Bold + '[' + Decoration.Reset + Decoration.Bold + Decoration.Red + 'ERROR' + Decoration.Reset + Decoration.Bold + '] ' + Decoration.Reset + Decoration.Red + 'Could not connect. You are banned.' + Decoration.Reset)
                            time.sleep(3)
                            self.stop_thread = True
                            self.sock.close()
                            os._exit(0)
                        else:
                            data = self.sock.recv(1024)
                            salt = data.removeprefix(b'Key ')
                            self.key = PBKDF2(password=self.password, salt=salt, dkLen=32)
                            post(message=f'Hello {self.username}', client=self.sock, key=self.key)
                            next_next_message = get(client=self.sock, key=self.key)
                            if next_next_message == f'Hi {self.username}, welcome to the chat room.':
                                self.gprint(next_next_message + '\n')
                                print(Decoration.Bold + '[' + Decoration.Reset + Decoration.Yellow + Decoration.Bold + 'NOTIFICATION' + Decoration.Reset + Decoration.Bold + '] ' + Decoration.Reset + Decoration.Yellow + f'{next_next_message}' + Decoration.Reset)
                            else:
                                self.gprint(message='Wrong password. please try again.')
                                print(Decoration.Bold + '[' + Decoration.Reset + Decoration.Bold + Decoration.Red + 'ERROR' + Decoration.Reset + Decoration.Bold + '] ' + Decoration.Reset + Decoration.Red + 'Wrong password. please try again.' + Decoration.Reset)
                                time.sleep(3)
                                self.stop_thread = True
                                self.sock.close()
                                os._exit(0) 
                    else:
                        self.sock.send(f'Registration {self.username} {self.password}'.encode('ascii'))
                        next_message = self.sock.recv(1024).decode('ascii')
                        if next_message == 'Refuse':
                            self.gprint('Sign up failed. Your choosen username has already taken. Please try again')
                            print(Decoration.Bold + '[' + Decoration.Reset + Decoration.Bold + Decoration.Red + 'ERROR' + Decoration.Reset + Decoration.Bold + '] ' + Decoration.Reset + Decoration.Red + 'Sign up failed. Your choosen username has already taken. Please try again' + Decoration.Reset)
                            time.sleep(3)
                            self.stop_thread = True
                            self.sock.close()
                            os._exit(0)
                        else:
                            self.gprint('Successfully Signed up. See you again.')
                            print(Decoration.Bold + '[' + Decoration.Reset + Decoration.Yellow + Decoration.Bold + 'NOTIFICATION' + Decoration.Reset + Decoration.Bold + '] ' + Decoration.Reset + Decoration.Yellow + f'Successfully Signed up. See you again.' + Decoration.Reset)
                            time.sleep(3)
                            self.stop_thread = True
                            self.sock.close()
                            os._exit(0)
                elif aes_decrypt(message, self.key).startswith('New attempt'):
                    message = aes_decrypt(message, self.key)
                    self.gprint(message + '\n')
                    print(Decoration.Bold + '[' + Decoration.Reset + Decoration.Bold + Decoration.Red + 'ERROR' + Decoration.Reset + Decoration.Bold + '] ' + Decoration.Reset + Decoration.Red + message + Decoration.Reset)
                    self.sock.close()
                    time.sleep(3)
                    os._exit(0)
                    break
                elif aes_decrypt(message,self.key) == 'Upload process':
                    original_file_name = get(client=self.sock, key=self.key)
                    new_file_name = get(client=self.sock, key=self.key)
                    file = open(original_file_name, 'rb')
                    self.sock.send(new_file_name.encode())
                    data = file.read()
                    compressed_data = lzma.compress(data)
                    self.sock.send(str(len(compressed_data)).encode())
                    self.sock.sendall(compressed_data)
                    file.close()
                    self.gprint(f'{new_file_name} succesfully sended to server.\n')
                    print(Decoration.Bold + '[' + Decoration.Reset + Decoration.Yellow + Decoration.Bold + 'NOTIFICATION' + Decoration.Reset + Decoration.Bold + '] ' + Decoration.Reset + Decoration.Yellow + f'{new_file_name} succesfully sended to server.' + Decoration.Reset)
                elif aes_decrypt(message,self.key) == 'Download process':
                    file_name = self.sock.recv(1024).decode()
                    file = open(file_name, 'wb')
                    compressed_data_len = self.sock.recv(1024).decode()
                    compressed_file_bytes = b''
                    done = False
                    while not done:
                        if str(len(compressed_file_bytes)) != compressed_data_len:
                            data = self.sock.recv(1024)
                            compressed_file_bytes += data
                        else:
                            done = True
                    file_bytes = lzma.decompress(compressed_file_bytes)
                    file.write(file_bytes)
                    file.close()
                    self.gprint(f'{file_name} succesfully received from server.\n')
                    print(Decoration.Bold + '[' + Decoration.Reset + Decoration.Yellow + Decoration.Bold + 'NOTIFICATION' + Decoration.Reset + Decoration.Bold + '] ' + Decoration.Reset + Decoration.Yellow + f'{file_name} succesfully received from server.' + Decoration.Reset)
                else:
                    message = aes_decrypt(message,self.key)
                    self.gprint(message + '\n')
                    print(Decoration.Bold + '[' + Decoration.Reset + Decoration.Green + Decoration.Bold + 'MESSAGE' + Decoration.Reset + Decoration.Bold + '] ' + Decoration.Reset + Decoration.Green + message + Decoration.Reset)
            except Exception as e:
                if f'{e}' == 'Padding is incorrect.':
                    self.gprint('Wrong password. please try again.')
                    print(Decoration.Bold + '[' + Decoration.Reset + Decoration.Bold + Decoration.Red + 'ERROR' + Decoration.Reset + Decoration.Bold + '] ' + Decoration.Reset + Decoration.Red + 'Wrong password. please try again.' + Decoration.Reset)
                else:
                    self.gprint('An error ocurred!')
                    print(Decoration.Bold + '[' + Decoration.Reset + Decoration.Bold + Decoration.Red + 'ERROR' + Decoration.Reset + Decoration.Bold + '] ' + Decoration.Reset + Decoration.Red + 'An error ocurred!' + Decoration.Reset)
                    self.gprint(f'\n{e}')
                    print(Decoration.Bold + '[' + Decoration.Reset + Decoration.Bold + Decoration.Red + 'ERROR' + Decoration.Reset + Decoration.Bold + '] ' + Decoration.Reset + Decoration.Red + f'{e}' + Decoration.Reset)
                time.sleep(3)
                self.sock.close()
                os._exit(0)
                break
        
        
    def write(self):

        message = self.input_area.get('1.0', 'end')
        message = message[:-1]
        print(Decoration.Bold + '[' + Decoration.Reset + Decoration.Magenta + Decoration.Bold + 'INPUT' + Decoration.Reset + Decoration.Bold + '] ' + Decoration.Reset + Decoration.Magenta + message + Decoration.Reset)
            
        if message.startswith('/'):
            if self.username == "admin":
                if message.startswith('/kick'): #expected request format: /kick {username}
                    data = message.split(' ')
                    name_to_kick = data[1]
                    post(message=f'/Kick {name_to_kick}',client=self.sock,key=self.key)
                elif message.startswith('/ban'):   #expected request format: /ban {username}
                    data = message.split(' ')
                    name_to_ban = data[1]
                    post(message=f'/Ban {name_to_ban}',client=self.sock,key=self.key)
                elif message.startswith('/unban'):  #expected request format:   /unban {username}
                    data = message.split(' ')
                    name_to_unban = data[1]
                    post(message=f'/Unban {name_to_unban}',client=self.sock,key=self.key)
                elif message.startswith('/shut down'):  #expected request format:   /shut down
                    post(message='/Shut down the server', client=self.sock, key=self.key)
            else:
                self.gprint('Commands can only be executed by the admin!')
                print(Decoration.Bold + '[' + Decoration.Reset + Decoration.Bold + Decoration.Red + 'ERROR' + Decoration.Reset + Decoration.Bold + '] ' + Decoration.Reset + Decoration.Red + 'Commands can only be executed by the admin!' + Decoration.Reset)
        elif message.startswith('upd'):      #expected request format: upd {original_file_name} {new_file_name} --> example: upd 1.txt 11.txt
            data = message.split(' ')
            original_file_name = data[1]
            new_file_name = data[2]
            post(f'Upload file request, original_file_name={original_file_name}, new_file_name={new_file_name} from {self.username}', client=self.sock, key=self.key)
        elif message.startswith('dnd'):      #expected request format: dnd {original_file_name} {new_file_name} --> example: dnd 2.jpg 22.jpg
            data = message.split(' ')
            original_file_name = data[1]
            new_file_name = data[2]
            post(f'Download file request, original_file_name={original_file_name}, new_file_name={new_file_name} from {self.username}', client=self.sock, key=self.key)
        elif message.startswith('attendees'):   #expected request format: attendees
            post('Please send the list of attendees.', client=self.sock, key=self.key)
        elif message == 'bye':
            post('Bye.', client=self.sock, key=self.key)
            self.gprint('gonna closed...')
            print(Decoration.Bold + '[' + Decoration.Reset + Decoration.Yellow + Decoration.Bold + 'NOTIFICATION' + Decoration.Reset + Decoration.Bold + '] ' + Decoration.Reset + Decoration.Yellow + f'gonna closed...' + Decoration.Reset)
            self.stop_thread = True
            os._exit(0)
        elif message.startswith('pvm'): #expected request format: pvm {message_body} {target_list} --> example: pvm Good afternoon admin,mmd
            data_list = message.split(' ')
            message_body = ''
            for i in range(len(data_list)):
                if i == 0 or i == len(data_list) - 1:
                    continue
                message_body += data_list[i] + ' '
            message_body = message_body[:-1]
            target_users = data_list[-1]
            post(f'Private message, length={len(message_body)} to {target_users}:\r\n{message_body}', client=self.sock, key=self.key)
        else:
            post(f'Public message, length={len(message)}:\r\n{message}', client=self.sock, key=self.key)
        self.input_area.delete('1.0', 'end')


        
client = Client(host=host, port=port)


