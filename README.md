## Prerequisites

- python 13.11 or newer
- click==8.3.0 
- et_xmlfile==2.0.0 
- openpyxl==3.1.5 
- scapy==2.6.1

---

## How to

1. Run the server (only as root user, otherwise you will be greeted with `PermissionError`)
   ```bash
   python main.py server start
   ```
2. The server will bind on IP 0.0.0.0 (all IPs) and will listen on port 99
3. (optional) One can start the server on a dedicated IP and port with the following command
   ```bash
   python main.py server start -ip 192.168.1.1 --port 12345
   ```
4. (optional) Run a test towards the server by firing up the client.
Make sure you input correctly the `dst_ip` which is the server's up set at the previous step
    ```bash
    python main.py client --dst_ip 192.168.1.1 test
    ```
5. (optional) List app all the sub-commands and options of the `client` command
    ```bash
    python main.py client --help
    ```
6. Create payload from CLI.
The payload will be saved into an SQLite DB.
The keyword `exit` or `Ctrl+C` will close the input prompt.
    ```bash
    python main.py client --dst_ip 192.168.1.1 cli
    ```
7. Create payload from file.
The contents of the file should be in HEX format.
One line creates payload for one packet
    ```bash
    python main.py client --dst_ip 192.168.1.1 file --path /path/to/payload/file.txt
    ```
8. (Optional) Render the structure of the payload and save it into an xcel file.  
   - Create a file having as contents on each line a dictionary `key:value`.
   - The `key` represents the name of the field.  
   - The `value` represents the size of the field in bytes (each byte is one xcel cell). 
   - Each line will create one sheet in the xcel file.   
   - See the `data.sample` file
   ```bash
   python main.py render -f /path/to/input/file.txt -o /path/to/save/xcel/file.xls
   ``` 

