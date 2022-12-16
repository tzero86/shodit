import argparse
import threading
import shodan


# Define a function that will be run in a separate thread
def fingerprint_host(client, ip_address):
    try:
        # Lookup the IP on Shodan
        host = client.host(ip_address)

        # Print the results
        print(f'[-] Fingerprint for {ip_address}:')
        print(f'    OS: {host.get("os", "unknown")}')
        print(f'    Hostnames: {", ".join(host["hostnames"])}')
        print(f'    Ports: {", ".join(str(p) for p in host["ports"])}')
    except shodan.exception.APIError as e:
        print(f'[!] Error: {e} {ip_address}')


banner = '''
   ▄████████    ▄█    █▄     ▄██████▄  ████████▄   ▄█      ███     
  ███    ███   ███    ███   ███    ███ ███   ▀███ ███  ▀█████████▄ 
  ███    █▀    ███    ███   ███    ███ ███    ███ ███▌    ▀███▀▀██ 
  ███         ▄███▄▄▄▄███▄▄ ███    ███ ███    ███ ███▌     ███   ▀ 
▀███████████ ▀▀███▀▀▀▀███▀  ███    ███ ███    ███ ███▌     ███     
         ███   ███    ███   ███    ███ ███    ███ ███      ███     
   ▄█    ███   ███    ███   ███    ███ ███   ▄███ ███      ███     
 ▄████████▀    ███    █▀     ▀██████▀  ████████▀  █▀      ▄████▀                                                                
                            v.0.0.1 A multithreaded shodan fingerprinter by tzero86
'''
print(banner)
# Parse the command-line arguments
parser = argparse.ArgumentParser()
parser.add_argument('api_key', help='Your Shodan API key')
parser.add_argument('ip_addresses', nargs='+', help='The IP addresses to scan')
args = parser.parse_args()

# Create a Shodan client
client = shodan.Shodan(args.api_key)

# Create a thread for each IP address
threads = []
for ip in args.ip_addresses:
    t = threading.Thread(target=fingerprint_host, args=(client, ip))
    threads.append(t)
    t.start()

# Wait for all threads to complete
for t in threads:
    t.join()
print('[*] All done, shodit is exiting.')
