# Cass' attempt at a quick smb server scanner
#import nmap into the script
import nmap
#import the SMBConnection module into the script
from smb.SMBConnection import SMBConnection

def list_Shares(server, username, password):
    conn = SMBConnection(username, password, 'my_computer', server, use_ntlm_v2 = True)
    try:
        conn.connect(server, 139)
        shares = conn.listShares()
        for share in shares:
            if share.name == 'IPC$':
                continue
            print(f'Name: {share.name}, Type: {share.type}')
            for file in conn.listPath(share.name, '/'):
                print(f'\tFile: {file.filename}')
    except Exception as e:
        print(f'Error: {e}')
    finally:
        conn.close()

userDefinedIp = input("What Address(es) would you like to scan\n")
server_name = userDefinedIp
username = "anonymous"
password = ""
conn = SMBConnection(username, password, "", server_name, use_ntlm_v2 = True)

nmScan = nmap.PortScanner()
nmScan.scan(userDefinedIp)

for hostip in nmScan.all_hosts():
    print('Host : %s (%s)' % (hostip, nmScan[hostip].hostname()))
    print('State : %s' % nmScan[hostip].state())
    for proto in nmScan[hostip].all_protocols():
        print('----------')
        print('Protocol : %s' % proto)
        listports = nmScan[hostip][proto].keys()
        sorted(listports)
        for port in listports:
            print('Port : %s\tState : %s\tService : %s' % (proto, nmScan[hostip][proto][port]['state'], nmScan[hostip][proto][port]['name']))
        print('----------')
        print('\n')

for hostip in nmScan.all_hosts():
    if nmScan[hostip].has_tcp(445) and nmScan[hostip].has_tcp(139):
        print("Server running SMB Server found")
        print("----------")
        print("Attempting to connect to SMB Server")
        try:
            conn.connect(server_name, 139)
            list_Shares(server_name, username, password)
        except Exception as e:
            print("Annonymous access is not allowed. Error : ", e)
