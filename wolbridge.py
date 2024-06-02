#!/bin/python3
import sys
import csv
import socket
import syslog
import binascii
import subprocess


def run_command(mac, commands):
    if mac in commands.keys():
        for cmd in commands[mac]:
            syslog.syslog(syslog.LOG_INFO, f"{mac}: run {cmd.split()}")
            subprocess.Popen(cmd.split())
    else:
        syslog.syslog(syslog.LOG_INFO, f"{mac}: no commands to run")


def load_commands(filename):
    with open(filename, "r") as csv_file:
        commands = {}
        reader = csv.reader(csv_file)
        for row in reader:
            # ignore malformed or empty lines
            if len(row) < 2:
                continue
            mac = row[0]
            cmd = row[1]
            if mac in commands.keys():
                commands[mac].append(cmd)
            else:
                commands[mac] = []
                commands[mac].append(cmd)
        return commands


def parse_wol(pkt):
    # convert to lowercase hex stream
    raw = str(binascii.hexlify(pkt).decode()).lower()
    # return immediately if packet is big
    if len(raw) < 300:
        # WOL packet starts with broadcast 'ffffffffffff'
        if raw.startswith(6 * "ff"):
            # ends with the broadcast and 16 times the mac addr
            mac = raw[-12:]
            if raw.endswith(6 * "ff" + 16 * mac):
                return mac
    return None


def run(iface, filepath):
    s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    s.bind((iface, 0))
    commands = load_commands(filepath)
    while True:
        pkt, addr = s.recvfrom(1000)
        mac = parse_wol(pkt)
        # run any registered command for this mac addr
        if mac:
            run_command(mac, commands)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"usage {sys.argv[0]} <iface name> <path/to/file.csv>")
        exit(1)
    iface = sys.argv[1]
    filepath = sys.argv[2]
    exit(run(iface, filepath))
