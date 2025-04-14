import socket

def test_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('localhost', 9000))  # Make sure this matches the client's port
        s.listen()
        print("Server listening on port 9000...")
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            data = conn.recv(1024)
            print(f"Received: {data.decode()}")
            conn.sendall(b"Message received!")

test_server()