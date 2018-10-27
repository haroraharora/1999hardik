
# Entire code is written by Hardik Arora Comp CSS Batch1 CSS roll no: 12


# This displays the port scan for tcp protocol
# If the line 15 is commented and the indetation of next few lines is corrected relating to it then it will display for all protocols


import nmap


def myscan(host_range ='127.0.0.1', port_range ='1-100'):
    nm = nmap.PortScanner()
    nm.scan(host_range, port_range)
    for host in nm.all_hosts():
        print("Host: " + host + "  |  State: " + nm[host].state())
        for protocol in nm[host].all_protocols():
            if protocol == 'tcp':
                for port in nm[host][protocol].keys():
                    print("Port: " + str(port) + "  |  State: " + str(nm[host][protocol][port]['state']) + "  |  Service: " + str(nm[host][protocol][port]['name']))

# print (nm['192.168.43.92'].all_protocols())
# print (nm['192.168.43.92']['tcp'].keys())
# print (nm['192.168.43.92']['tcp'][80]['name'])
# print (nm['192.168.43.92']['tcp'][22]['name'])


if __name__ == "__main__":

    while True:
        host_range = raw_input("\nPress exit to Quit\nEnter host range sample(XX.XX.XX.0-10) or sample(XX.XX.XX.XX): ")
        if host_range == host_range.lower():
            break
        else:
            port_range = raw_input("Enter Port range sample(1-100 or 100): ")
            myscan(host_range, port_range)
