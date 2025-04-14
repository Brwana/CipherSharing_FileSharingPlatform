import socket

def test_client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('localhost', 9000))
        s.send(b"Test message")
        response = s.recv(1024)
        print(f"Received: {response.decode()}")

test_client()
