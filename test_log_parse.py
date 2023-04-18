import pandas as pd
import re

# read the log file into a DataFrame
with open('C:/Users/Samin Basnet/Downloads/latest/New FYP/ssh_honeypot.log') as f:
    log = f.read()

log_list = log.split('\n')

data = []

for i in range(len(log_list)):
    if 'New connection from' in log_list[i]:
        timestamp = log_list[i][:19]
        ip_address = log_list[i].split()[-1]
        not_local = True if ip_address != '127.0.0.1' else False
    elif 'Command' in log_list[i]:
        command = re.search(r': (.*)', log_list[i]).group(1)
        not_local = True if ip_address != '127.0.0.1' else False
        offtime = True if int(timestamp[11:13]) not in range(9, 18) else False
        has_malicious_command = any(
            x in command for x in ['curl', 'wget', 'sudo', 'chmod', 'useradd', 'ssh-keygen', 'netstat'])
        data.append((timestamp, ip_address, command, not_local, offtime, has_malicious_command))

        # save the DataFrame to a CSV file after every new connection
        df = pd.DataFrame(data, columns=['timestamp', 'ip_address', 'command', 'not_local', 'offtime',
                                         'has_malicious_command'])
        df.to_csv('Dataset.csv', index=False)


