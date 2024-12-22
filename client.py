import rsa
import threading
import socket

# Generate RSA keys for the client
public_key, private_key = rsa.newkeys(1024)

# Connect the client to the server
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_ip = input("Enter server IP address: ")  # Prompt user for server's IP address
server_port = int(input("Enter server port: "))  # Prompt user for server's port
client.connect((server_ip, server_port))  # Establish the connection to the server
print("Connected to server!")

# Receive the server's public key
server_public_key = rsa.PublicKey.load_pkcs1(client.recv(1024))
# Send the client's public key to the server
client.send(public_key.save_pkcs1("PEM"))

# Function to send messages to the server
def sending_message():
    while True:
        try:
            # Get the message from the user
            message = input("")
            if message.lower() == "exit":
                print("Closing connection...")
                client.close()  # Close the connection when the user types "exit"
                break

            # Encrypt the message using the server's public key
            encrypted_message = rsa.encrypt(message.encode(), server_public_key)
            # Send the encrypted message to the server
            client.send(encrypted_message)
            print("You: " + message)
        except Exception as e:
            print(f"Error while sending message: {e}")
            break

# Function to receive messages from the server
def recv_message():
    while True:
        try:
            # Receive the encrypted message from the server
            encrypted_message = client.recv(1024)
            if not encrypted_message:
                break  # If no message, close the connection
            # Decrypt the message using the client's private key
            decrypted_message = rsa.decrypt(encrypted_message, private_key).decode()
            print("Partner: " + decrypted_message)
        except Exception as e:
            print(f"Error while receiving message: {e}")
            break

# Create threads for sending and receiving messages
threading.Thread(target=sending_message, daemon=True).start()
threading.Thread(target=recv_message, daemon=True).start()

# Main thread waits for the socket to close before ending the program
while client.fileno() != -1:  # Wait until the socket is closed
    pass