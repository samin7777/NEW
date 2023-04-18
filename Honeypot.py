#!/usr/bin/env python
import argparse
import threading
import socket
import os
import traceback
import json
import logging
import paramiko
import subprocess
from datetime import datetime
from binascii import hexlify
from paramiko.py3compat import b, u, decodebytes
import time
import sys
import concurrent.futures


# check if user input is 'q' and exit the program


HOST_KEY = paramiko.RSAKey(filename='server.key')
SSH_BANNER = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1"

UP_KEY = '\x1b[A'.encode()
DOWN_KEY = '\x1b[B'.encode()
RIGHT_KEY = '\x1b[C'.encode()
LEFT_KEY = '\x1b[D'.encode()
BACK_KEY = '\x7f'.encode()

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    filename='ssh_honeypot.log')

# root_path = r"D:\Honeypot with ML\latest\New FYP\ascii"
root_path = r"D:\ROOT\Sys file"
hacked_path = os.path.join(root_path, 'ROOT_FOLDER')
path = root_path
Hacked = ['bin', 'dev', 'etc', 'home', 'lib', 'root', 'tmp', 'usr', 'var']

def create_hacked_folders(hacked_path):
    #Hacked = ['bin', 'dev', 'etc', 'home', 'lib', 'root', 'tmp', 'usr', 'var']

    for folder in Hacked:
        folder_path = os.path.join(hacked_path, folder)
        os.makedirs(folder_path, exist_ok=True)

    # Add sample files to the /etc folder
    etc_path = os.path.join(hacked_path, 'etc')

    # Create passwd file with sample data
    passwd_data = '''\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
'''
    with open(os.path.join(etc_path, 'passwd'), 'w') as f:
        f.write(passwd_data)

    # Create hosts file with sample data
    hosts_data = '''\
127.0.0.1   localhost
127.0.1.1   ubuntu.localdomain   ubuntu
'''
    with open(os.path.join(etc_path, 'hosts'), 'w') as f:
        f.write(hosts_data)

    # Create a sample /etc/fstab file
    fstab_data = '''\
# /etc/fstab: static file system information.
#
# <file system> <mount point>   <type>  <options>       <dump>  <pass>
proc            /proc           proc    defaults        0       0
'''
    with open(os.path.join(etc_path, 'fstab'), 'w') as f:
        f.write(fstab_data)

    # Add sample files to the /home folder
    home_path = os.path.join(hacked_path, 'home')

    # Create a sample user folder and a file within it
    user_folder = os.path.join(home_path, 'user1')
    os.makedirs(user_folder, exist_ok=True)

    sample_file_data = 'This is a sample file in the user1 home directory.'
    with open(os.path.join(user_folder, 'sample_file.txt'), 'w') as f:
        f.write(sample_file_data)

# Call the create_hacked_folders function after defining the hacked_path variable
hacked_path = os.path.join(root_path, 'ROOT_FOLDER')
create_hacked_folders(hacked_path)

def handle_cmd(cmd, chan, ip):
    global path  # Make path a global variable
    response = ""

    
  
    if cmd.startswith("ls"):
        #path = r"D:\Honeypot with ML\latest\New FYP\ascii"
        files = os.listdir(path)
        if path == root_path:  # Check if the current path is the root directory
            files = [file for file in files if file != 'ROOT_FOLDER' and file not in Hacked]  # Exclude the Hacked folders
            files.append('ROOT_FOLDER')
        elif path == hacked_path:  # Check if the current path is the ROOT_FOLDER directory
            files = Hacked
        #files = os.listdir()
      # sort the list alphabetically and print the result
        #file_list = files.sort()
        #file_list = '\n'.join([f"{file}\n" for file in files])
        #file_list = file_list.split('\n')
        # Set the path to the root of the folder containing the files
        
        response = str(files)
        #response = file_list
        
    elif cmd.startswith("pwd"):
        cwd = os.getcwd()
        response = cwd
    elif cmd.startswith("cd"):
        try:
            dir_name = cmd.split()[1]
            new_path = os.path.join(path, dir_name)
            new_abs_path = os.path.abspath(new_path)
            root_abs_path = os.path.abspath(root_path)

            # Prevent going back further than the root directory
            if new_abs_path.startswith(root_abs_path) or new_abs_path == root_abs_path:
                if os.path.isdir(new_path):
                    path = new_path  # Update the path variable
                    os.chdir(path)
                    response = "Changed current directory to {}".format(path)
                else:
                    response = "Error: '{}' is not a valid directory".format(dir_name)
            else:
                response = "Cannot go back further than the root directory"

        except Exception as e:
            response = "Error: {}".format(e)

    elif cmd.startswith("mkdir"):
        try:
            dir_name = cmd.split()[1]
            os.mkdir(dir_name)
            response = "Created directory {}".format(dir_name)
        except Exception as e:
            response = "Error: {}".format(e)
    elif cmd.startswith("rmdir"):
        try:
            dir_name = cmd.split()[1]
            os.rmdir(dir_name)
            response = "Deleted directory {}".format(dir_name)
        except Exception as e:
            response = "Error: {}".format(e)
    elif cmd.startswith("cat"):
        try:
            file_name = cmd.split()[1]
            #if os.path.exists(file_name):
            if os.path.exists(os.path.join(path, file_name)):
                with open(os.path.join(path, file_name)) as f:
               #with open(file_name) as f:
                    contents = f.read()
                    response = contents
            else:
                response = "Error: file does not exist"
        except Exception as e:
            response = "Error: {}".format(e)
    elif cmd.startswith("touch"):
        try:
            file_name = cmd.split()[1]
            open(os.path.join(path, file_name), 'w').close()
            #open(file_name, 'w').close()
            response = "Created file {}".format(file_name)
        except Exception as e:
            response = "Error: {}".format(e)
    elif cmd.startswith("chmod"):
        try:
            mode = cmd.split()[1]
            file_name = cmd.split()[2]
            os.chmod(file_name, mode)
            response = "Changed permissions of {} to {}".format(file_name, mode)
        except Exception as e:
            response = "Error: {}".format(e)
    elif cmd.startswith("rm"):
        try:
            file_name = cmd.split()[1]
            os.unlink(file_name)
            response = "Deleted file {}".format(file_name)
        except Exception as e:
            response = "Error: {}".format(e)
    elif cmd.startswith("version"):
        response = "Super Amazing Awesome (tm) Shell v1.1"
    elif ".exe" in cmd:
        response = "Hmm, trying to access .exe files from an ssh terminal..... Your methods are unconventional"
    elif cmd.startswith("cmd"):
        response = "Command Prompt? We only use respectable shells on this machine.... Sorry"

    elif cmd.startswith("sudo"):
        response = "Permission Denied"
    elif cmd.startswith("nmap"):
        try:
            target = cmd.split()[1]
            result = subprocess.run(["nmap", "-sS", target], capture_output=True)
            response = result.stdout.decode('utf-8')
        except Exception as e:
            response = "Error: {}".format(e)
    elif cmd.startswith("wget"):
        response = "Error: file not found or permission denied"
    elif cmd.startswith("curl"):
        response = "Error: resource not found or permission denied"
    elif cmd.startswith("telnet"):
        response = "Connection refused"
    elif cmd.startswith("ssh"):
        response = "Connection refused or already connected via SSH"
    elif cmd.startswith("ftp"):
        response = "Connection refused"
    elif cmd.startswith("tcpdump"):
        response = "Error: permission denied"
    elif cmd.startswith("netcat"):
        response = "Connection refused or permission denied"
    elif cmd.startswith("ncat"):
        response = "Connection refused or permission denied"
    elif cmd.startswith("msfconsole"):
        response = "Requires sudo permission to access msfconsole"
    elif cmd.startswith("nessus"):
        response = "Error: this command is not reconized or user does not have permission to us it"
    elif cmd.startswith("sqlmap"):
        response = "Connection refused or permission denied"
    elif cmd.startswith("aircrack-ng"):
        response = "Error: aircrack-ng is not installed on this system. Please try another command."
    elif cmd.startswith("hydra"):
        response = "permission denied."
    
    else:
        response = "Sorry, I don't recognize that command."
    
    if response != '':
        logging.info('Response from honeypot ({}): '.format(ip, response))
        response = response + "\r\n"
    chan.send(response)


'''
def send_ascii(filename, chan):
    """Print ascii from a file and send it to the channel"""
    with open('ascii/{}'.format(filename)) as text:
        chan.send("\r")
        for line in enumerate(text):   
            chan.send(line[1] + "\r")
'''


class BasicSshHoneypot(paramiko.ServerInterface):
    client_ip = None

    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        logging.info('client called check_channel_request ({}): {}'.format(
            self.client_ip, kind))
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED

    def get_allowed_auths(self, username):
        logging.info('client called get_allowed_auths ({}) with username {}'.format(
            self.client_ip, username))
        return "publickey,password"

    def check_auth_publickey(self, username, key):
        fingerprint = u(hexlify(key.get_fingerprint()))
        logging.info(
            'client public key ({}): username: {}, key name: {}, md5 fingerprint: {}, base64: {}, bits: {}'.format(
                self.client_ip, username, key.get_name(), fingerprint, key.get_base64(), key.get_bits()))
        return paramiko.AUTH_PARTIALLY_SUCCESSFUL

    def check_auth_password(self, username, password):
        # Accept all passwords as valid by default
        logging.info('new client credentials ({}): username: {}, password: {}'.format(
            self.client_ip, username, password))
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command, username):
        command_text = str(command.decode("utf-8"))

        logging.info('client sent command via check_channel_exec_request ({}): {}'.format(
            self.client_ip, username, command))
        return True


def handle_connection(client, addr, settings=None):
    client_ip = addr[0]
    logging.info('New connection from: {}'.format(client_ip))
    print('New connection is here from: {}'.format(client_ip))

    try:
        transport = paramiko.Transport(client)
        transport.add_server_key(HOST_KEY)
        transport.local_version = SSH_BANNER  # Change banner to appear more convincing
        server = BasicSshHoneypot(client_ip)
        try:
            transport.start_server(server=server)

        except paramiko.SSHException:
            print('*** SSH negotiation failed.')
            raise Exception("SSH negotiation failed")

        # wait for auth
        chan = transport.accept(10)
        if chan is None:
            print('*** No channel (from ' + client_ip + ').')
            raise Exception("No channel")

        chan.settimeout(10)

        if transport.remote_mac != '':
            logging.info('Client mac ({}): {}'.format(client_ip, transport.remote_mac))

        if transport.remote_compression != '':
            logging.info('Client compression ({}): {}'.format(client_ip, transport.remote_compression))

        if transport.remote_version != '':
            logging.info('Client SSH version ({}): {}'.format(client_ip, transport.remote_version))
        '''    
        if transport.remote_cipher != '':
            logging.info('Client SSH cipher ({}): {}'.format(client_ip, transport.remote_cipher))
        '''
        server.event.wait(10)
        if not server.event.is_set():
            logging.info('** Client ({}): never asked for a shell'.format(client_ip))
            raise Exception("No shell request")

        try:
            chan.send("Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-128-generic x86_64)\r\n\r\n")
            run = True
            while run:
                chan.send("$ ")
                command = ""
                while not command.endswith("\r"):
                    transport = chan.recv(1024)
                    print(client_ip + "- received:", transport)
                    # Echo input to psuedo-simulate a basic terminal
                    if (
                            transport != UP_KEY
                            and transport != DOWN_KEY
                            and transport != LEFT_KEY
                            and transport != RIGHT_KEY
                            and transport != BACK_KEY
                    ):
                        chan.send(transport)
                        command += transport.decode("utf-8")

                chan.send("\r\n")
                command = command.rstrip()
                logging.info('Command received ({}): {}'.format(client_ip, command))

                if command == "exit":
                    settings.addLogEntry("Connection closed (via exit command): " + client_ip + "\n")
                    run = False

                else:
                    handle_cmd(command, chan, client_ip)

        except Exception as err:
            print('!!! Exception: {}: {}'.format(err.__class__, err))
            try:
                transport.close()
            except Exception:
                pass

        chan.close()

    except Exception as err:
        print('!!! Exception: {}: {}'.format(err.__class__, err))
        try:
            transport.close()
        except Exception:
            pass


def start_server(port, bind):
    """Init and run the ssh server"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((bind, port))
    except Exception as err:
        print('*** Bind failed: {}'.format(err))
        traceback.print_exc()
        sys.exit(1)

    threads = []
    while True:
        try:
            sock.listen(100)
            print('Listening for connection on port {} ...'.format(port))
            client, addr = sock.accept()

        except Exception as err:
            print('*** Listen/accept failed: {}'.format(err))
            traceback.print_exc()
        new_thread = threading.Thread(target=handle_connection, args=(client, addr))
        new_thread.start()
        threads.append(new_thread)

    for thread in threads:
        thread.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run an SSH honeypot server')
    parser.add_argument("--port", "-p", help="The port to bind the ssh server to (default 22)", default=22, type=int,
                        action="store")
    parser.add_argument("--bind", "-b", help="The address to bind the ssh server to", default="", type=str,
                        action="store")
    args = parser.parse_args()
    '''with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        executor.submit(start_server, args.port, args.bind)
        executor.submit(exit_program())'''
    start_server(args.port, args.bind)
