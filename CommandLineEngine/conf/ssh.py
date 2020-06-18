"""
Copyright 2019 Pacific Gas and Electric Company

ALL RIGHTS RESERVED
"""
import paramiko

class SSH:
    def __init__(self, host, port, username, password):
        self.host = host
        self.port = port
        self.username = username
        self.password = password

        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(self.host, port=self.port, username=self.username, password=self.password)

    def exec(self, command):
        try:
            stdin, stdout, stderr = self.client.exec_command(command)
        except paramiko.ssh_exception.SSHException:
            self.client.close()
            self.client.connect(self.host, port=self.port, username=self.username, password=self.password)
            stdin, stdout, stderr = self.client.exec_command(command)

        output = stdout.read().decode()
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            raise Exception('Non-zero exit code on command: {command}'.format(command=command))
        return output

    def get_history(host, port, username, password):
        if 'bash' in shell:
            stdin, stdout, stderr = client.exec_command('cat ~/.bash_history')
            return set(stdout.read().decode().splitlines())
        else:
            print('The shell is not bash')

    def get_stream(self, command):
        stdin, stdout, stderr = self.client.exec_command(command)
        self.stream = stdout

    def get_stream_data(self, size=1024):
        return self.stream.read(size)
