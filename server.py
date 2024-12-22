import rsa
import threading
import socket

# Generate RSA keys for the server
public_key, private_key = rsa.newkeys(1024)
clients = []  # List to keep track of connected clients
public_keys = {}  # Dictionary to store the public keys of clients

# Get IP address and port from the user
server_ip = input("Enter server IP address: ")  # Prompt for server IP address
server_port = int(input("Enter server port: "))  # Prompt for server port

# Create the server socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the server to the given IP address and port
server.bind((server_ip, server_port))
server.listen()  # Start listening for client connections
print(f"Server running on {server_ip}:{server_port}. Waiting for connections...")

# Function to handle each client's connection
def handle_client(client_socket, addr):
    global public_keys
    try:
        print(f"Client connected: {addr}")

        # Send the server's public key to the client
        client_socket.send(public_key.save_pkcs1("PEM"))

        # Receive the client's public key
        client_public_key = rsa.PublicKey.load_pkcs1(client_socket.recv(1024))
        public_keys[client_socket] = client_public_key  # Store the client's public key

        while True:
            # Receive the encrypted message from the client
            encrypted_message = client_socket.recv(1024)
            if not encrypted_message:
                break  # If no message, close the connection

            # Decrypt the message using the server's private key
            decrypted_message = rsa.decrypt(encrypted_message, private_key).decode()
            print(f"Message from {addr}: {decrypted_message}")

            # Forward the decrypted message to other clients
            for client in clients:
                if client != client_socket:  # Don't send the message back to the sender
                    encrypted_message = rsa.encrypt(decrypted_message.encode(), public_keys[client])
                    client.send(encrypted_message)
    except Exception as e:
        print(f"Client {addr} disconnected. Error: {e}")
    finally:
        # Remove the client from the list and close the connection
        clients.remove(client_socket)
        del public_keys[client_socket]
        client_socket.close()

# Main server loop to accept new clients and create new threads for each connection
while True:
    # Wait for new clients to connect
    client_socket, addr = server.accept()
    clients.append(client_socket)  # Add the client to the list
    # Create a new thread to handle the client
    threading.Thread(target=handle_client, args=(client_socket, addr)).start()