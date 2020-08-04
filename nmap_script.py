#!/usr/bin/python

import nmap
import pyfiglet 
ascii_banner = pyfiglet.figlet_format("SCANNER")
print(ascii_banner)
scanner = nmap.PortScanner()
print("Welcome to NMAP automation tool")
print("<--------------------------------------------------->")
ip_addr = input("Please enter the IP addr you want to scan: ")
print("The IP you've entered is: ",ip_addr)
type(ip_addr)


def scan():
    resp = input("""\nPlease Enter the Type of Scan
                (1)SYN ACK Scan
                (2)UDP SCAN
                (3)Comprehensive Scan\n""")
    print("You've selected option: ",resp)
    print("Please be patient while scanning unless you're using NASA's internet")
    
    if resp == '1':
        #print("Nmap Version: ",scanner.nmap version())
        scanner.scan(ip_addr,'1-1023','-v -sS')
        print(scanner.scaninfo())
        print("Ip Status: ",scanner[ip_addr].state())
        print(scanner[ip_addr].all_protocols())
        print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
        

    elif resp=='2':
        scanner.scan(ip_addr,'1-1023','-v -sU')
        print(scanner.scaninfo())
        print("Ip Status: ",scanner[ip_addr].state())
        print(scanner[ip_addr].all_protocols())
        print("Open Ports: ", scanner[ip_addr]['udp'].keys())

    elif resp=='3':
        scanner.scan(ip_addr,'1-1024','-v -sS -sV -sC -A -O')
        print(scanner.scaninfo())
        print("Ip Status: ",scanner[ip_addr].state())
        print(scanner[ip_addr].all_protocols())
        print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
        print("Host name: ",scanner[ip_addr].hostnames())
        #print("OS: ",scanner[ip_addr]['osclass'])
        if 'osclass' in scanner[ip_addr]:
            for osclass in scanner[ip_addr]['osclass']:
                print('OsClass.type : {0}'.format(osclass['type']))
                print('OsClass.vendor : {0}'.format(osclass['vendor']))
                print('OsClass.osfamily : {0}'.format(osclass['osfamily']))
                print('OsClass.osgen : {0}'.format(osclass['osgen']))
                print('OsClass.accuracy : {0}'.format(osclass['accuracy']))
                print('')
        
        if 'osmatch' in scanner[ip_addr]:
            print("OS match: ",scanner[ip_addr]['osmatch'])
            #for osmatch in scanner[ip_addr]['osmatch']:
             #   print('OsMatch.name : {0}'.format(osclass['name']))
             #   print('OsMatch.accuracy : {0}'.format(osclass['accuracy']))
             #   print('OsMatch.line : {0}'.format(osclass['line']))
             #  print('')

        if 'fingerprint' in scanner[ip_addr]:
            print('\nFingerprint : {0}'.format(scanner[ip_addr]['fingerprint']))
        
        for h in scanner.all_hosts():
            if 'mac' in scanner[h]['addresses']:
                print(scanner[h]['addresses'], scanner[h]['vendor'])
    
    else:
        print("\nPlease enter a valid option")
        scan()
scan()
