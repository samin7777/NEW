import sys
import socket
import threading 
import time

def scanner():
    print('[+] Optimized Port Scanner')
    print('-'*80)
    try:
        tar = input('Enter IP address: ')
        if not tar.replace('.', '').isdigit():
            raise ValueError('Invalid IP address entered!')
        target = socket.gethostbyname(tar)  # host name given will resolve to corresponding ip address from dns
    except socket.gaierror:
        print('Name resolution error')
        sys.exit()
    except ValueError as e:
        print(e)
        sys.exit()
    try:
        start_port = int(input('Enter start port: '))
        end_port = int(input('Enter end port: '))
        if end_port > 65535:
            raise ValueError('End port number out of range!')
    except ValueError as e:
        print(e)
        sys.exit()
    startTime = time.time()
    print(f'Scanning {target}...')
    def scan(port):
        p = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # tcp
        p.settimeout(5)
        connection = p.connect_ex((target, port))
        if not connection:
            service_name = socket.getservbyport(port, 'tcp')
            print(f"{port}|tcp   OPEN        {service_name}")
        p.close()
    print('PORT \t  STATUS      SERVICE')
    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan, args=(port,))
        thread.start()
    thread.join()
    print('Scanning complete!')
    print('Time taken:', str(time.time() - startTime)[:4], 'sec')

if __name__ == '__main__':
    scanner()
