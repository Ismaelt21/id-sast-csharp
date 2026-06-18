import socket
import ssl

host = "ac-5i1askr-shard-00-00.yyqxspe.mongodb.net"

ctx = ssl.create_default_context()

sock = socket.create_connection((host, 27017))

with ctx.wrap_socket(sock, server_hostname=host) as s:
    print("TLS OK")
    print(s.version())
    print(s.getpeercert())