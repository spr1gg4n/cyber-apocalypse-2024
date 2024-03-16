#You can pass the IP address and port as command-line arguments when running the script:
#python3 solver.py --ip <host_address> --port <port>
#python3 solver.py --ip 127.0.0.1 --port 12345

from pwn import *
import argparse

# Function to convert a byte to a list of voltages on pins
def byte_to_volts(byte):
    return [((byte >> i) & 1) * 5 for i in range(10, -1, -1)]

# Function to convert a list of bits to a byte
def bits_to_byte(bits):
    return int(''.join(map(str, bits)), 2)

# Function to convert data to ASCII string
def to_ascii(data):
    return data.decode().strip()

# Function to read data from memory at a given address
def read_memory(r, address, secret=False):
    r.sendlineafter(b"> ", b"set_ce_pin(0)")
    r.sendlineafter(b"> ", b"set_oe_pin(0)")
    r.sendlineafter(b"> ", b"set_we_pin(5)")
    if secret:
        bits = byte_to_volts(address)
        bits[1] = 12
        address_pins = bytes(str(bits), "Latin")
    else:
        address_pins = bytes(str(byte_to_volts(address)), "Latin")
    r.sendlineafter(b"> ", b"set_address_pins(" + address_pins + b")")
    r.sendlineafter(b"> ", b"read_byte()")
    return to_ascii(r.recvline())

# Function to get the flag
def get_flag(r):
    flag = ""
    for address in range(0x7e0, 0x7ff + 1):
        data = read_memory(r, address, secret=True)
        byte = data[5:-17]
        flag += chr(eval(byte))
    return flag


#def pwn():
#    r.recvuntil(b"> help")
#    flag = get_flag()
#    print(flag)
#

#if __name__ == "__main__":
#    if args.REMOTE:
#        ip, port = args.HOST.split(":")
#        r = remote(ip, int(port))
#    else:
#        r = process("python3 ../challenge/server.py", shell=True)

#    pwn()

# Main exploit function
def pwn(ip, port):
    if ip and port:
        r = remote(ip, int(port)) # Connecting to a remote server
    else:
        r = process("python3 ../challenge/server.py", shell=True) # Launching a local server

    r.recvuntil(b"> help") # Waiting for prompt
    flag = get_flag(r) # Getting the flag
    print(flag) # Printing the flag

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Exploit script')
    parser.add_argument('--ip', help='IP address', required=True) # Argument for IP address
    parser.add_argument('--port', help='Port number', required=True) # Argument for port
    args = parser.parse_args() # Parsing command line arguments

    pwn(args.ip, args.port) # Calling the main function with specified IP and port

