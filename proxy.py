# Computer Networks - Project 2 (Proxy server)
# Student Name: Daeyeol Ryu

import urlparse, socket, threading, sys, datetime

# HTTP packet class
# Manage packet data and provide related functions
class HTTPPacket:
    # Constructer   
    def __init__(self, line, header, body):
        self.line = line        # Packet first line(String)
        self.header = header    # Headers(Dict.{Field:Value})
        self.body = body        # Body(Bytes)
    
    # Make encoded packet data
    def pack(self):
        # Concat first line
        ret = self.line + '\r\n'
        # Concat headers
        for field in self.header:
            ret += field + ': ' + self.header[field] + '\r\n'
        ret += '\r\n'
        # String -> Bytes
        ret = ret.encode()
        # Concat body
        ret += self.body
        return ret
    
    # Get HTTP header value
    def getHeader(self, field):
        # Return header value by field.
        # If not exist, return empty string as default value
        return self.header.get(field, '')
    
    # Set HTTP header value
    def setHeader(self, field, value):
        if not value:
            # If value is empty string, remove field
            try:
                del self.header[field]
            except KeyError:
                pass
        else:
            # Add or update value of field
            self.header[field] = value
    
    # Get URL from request packet line
    def getURL(self):
        # HTTP Header's first line format => 'METHOD' SP 'URL' SP 'VERSION'
        return self.line.split(' ')[1]

    def isChunked(self):
        return 'chunked' in self.getHeader('Transfer-Encoding')

# Receive HTTP packet with socket
def recvHttpData(conn):
    # Set time out for error or persistent connection end
    conn.settimeout(TIMEOUT)

    # Get HTTP header from the socket (some piece of HTTP body can be received together)
    data = conn.recv(BUFSIZE)
    if not data:
        raise Exception('Disconnected')
    while b'\r\n\r\n' not in data:
        data += conn.recv(BUFSIZE)
    packet = parseHTTP(data)
    body = packet.body

    # Get HTTP body from the socket
    # Chunked-Encoding
    if packet.isChunked():
        readed = 0
        # Read and merge chunked HTTP body
        while True:
            while b'\r\n' not in body[readed:len(body)]:
                d = conn.recv(BUFSIZE)
                body += d
            size_str = body[readed:len(body)].split(b'\r\n')[0]
            size = int(size_str, 16)
            readed += len(size_str) + 2
            while len(body) - readed < size + 2:
                d = conn.recv(BUFSIZE)
                body += d
            readed += size + 2
            if size == 0: break

        # Normalize chunked body to non-chunked body to use 'Content-Length' instead of 'Transfer-Encoding: chunked'
        # Only odd index carries real message (even index include 0 indicates the bytes count)
        bodyChunks = body.split(b'\r\n')[1::2]
        # Remove last chunk because it is empty string
        del bodyChunks[-1]
        # Join all chunks
        body = b''.join(bodyChunks)

        packet.setHeader('Transfer-Encoding', '')
        packet.setHeader('Content-Length', str(len(body)))
    # Content-Length
    elif packet.getHeader('Content-Length'):
        # Read HTTP body
        received = 0
        expected = packet.getHeader('Content-Length')
        if not expected:
            expected = '0'
        expected = int(expected)
        received += len(body)
        while received < expected:
            d = conn.recv(BUFSIZE)
            received += len(d)
            body += d
    
    # Finally HTTP body normalized to normal HTTP body not chunked
    packet.body = body
    return packet

# Dissect HTTP header into line(first line), header(second line to end), body
def parseHTTP(data):
    # Get the first line
    endIndex = data.find(b'\r\n', 0)
    firstLine = data[:endIndex].decode()

    # Get the header lines
    startIndex = endIndex + len(b'\r\n')
    endIndex = data.find(b'\r\n\r\n', startIndex)
    headerLines = data[startIndex:endIndex].decode()
    # Convert header lines to header dictionary
    header = dict()
    for line in headerLines.split('\r\n'):
        # Get header and make it to dictionary
        arr = list(map(lambda x: x.strip(), line.split(':')))
        header[arr[0]] = arr[1]

    # Get the body lines
    startIndex = endIndex + len(b'\r\n\r\n')
    body = data[startIndex:]

    return HTTPPacket(firstLine, header, body)

# Proxy handler function
def handleProxy(clientSock, clientAddr):
    # CONNECTION_NUM is global variable which can be modified in this function
    global CONNECTION_NUM

    serverSock = None
    prevHostname = ''

    while IS_PROXY_RUNNING:
        try:
            # Client -> Proxy (Intercept HTTP request from client)
            # Receive data from the client
            req = recvHttpData(clientSock)
            # Parse URL
            url = urlparse.urlparse(req.getURL())

            # Handle only http. So other schemes are ignored
            if url.scheme != 'http':
                # Get connection number
                clientNum = CONNECTION_NUM
                CONNECTION_NUM += 1
                # Print logs
                print('[' + str(clientNum) + '] ' + datetime.datetime.now().strftime('%d/%b/%Y %H:%M:%S.%f') + '\n'
                + '[' + str(clientNum) + '] > Connection from ' + clientAddr[0] + ':' + str(clientAddr[1]) + '\n'
                + '[' + str(clientNum) + '] > ' + req.line + '\n'
                )
                raise NotImplementedError('Wrong scheme. Only HTTP is supported.')

            # Remove proxy infomation (Elite anonymity level proxy)
            req.setHeader('Proxy-Connection', '')
            if OPT_PC:
                # Use keep-alive for persistent connection
                req.setHeader('Connection', 'keep-alive')
            else:
                # Use close for non-persistent connection
                req.setHeader('Connection', 'close')

            # Proxy -> Server
            # If Persistent connection is enabled, server socket is connected and prev host name is same as current one,
            # then use same server socket as prev
            if not OPT_PC or serverSock == None or prevHostname != url.hostname:
                # Close previous server socket
                if serverSock != None:
                    try:
                        serverSock.shutdown(socket.SHUT_RDWR)
                        serverSock.close()
                    except:
                        pass

                # Establish new server socket connection
                serverSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                serverSock.connect((url.hostname, 80))
                prevHostname = url.hostname

            # Send HTTP request to server
            serverSock.sendall(req.pack())

            # Receive data from the server
            res = recvHttpData(serverSock)

            if OPT_PC:
                # Use keep-alive for persistent connection
                res.setHeader('Connection', 'keep-alive')
            else:
                # Use close for non-persistent connection
                res.setHeader('Connection', 'close')

                # Close the server socket
                try:
                    serverSock.shutdown(socket.SHUT_RDWR)
                    serverSock.close()
                except:
                    pass

            # Proxy -> Client (Send back HTTP response from the server to client)
            clientSock.sendall(res.pack())

            # Get connection number
            clientNum = CONNECTION_NUM
            CONNECTION_NUM += 1
            # Print logs
            print('[' + str(clientNum) + '] ' + datetime.datetime.now().strftime('%d/%b/%Y %H:%M:%S.%f') + '\n'
             + '[' + str(clientNum) + '] > Connection from ' + clientAddr[0] + ':' + str(clientAddr[1]) + '\n'
             + '[' + str(clientNum) + '] > ' + req.line + '\n'
             + '[' + str(clientNum) + '] > ' + res.line + '\n'
             + '[' + str(clientNum) + '] < ' + res.getHeader('Content-Type') + ' ' + res.getHeader('Content-Length') + 'bytes' + '\n'
             )

            if not OPT_PC:
                raise Exception('Non-persistent')
        except Exception as e:
            # print('Proxy handling error: ' + str(e))
            break
    
    # Close server socket
    if serverSock != None:
        try:
            serverSock.shutdown(socket.SHUT_RDWR)
            serverSock.close()
        except:
            pass

    # Close client socket
    try:
        clientSock.shutdown(socket.SHUT_RDWR)
        clientSock.close()
        CLIENT_SOCKS.remove(clientSock)
    except:
        pass

# Constants
PROXY_HOST = '0.0.0.0'
BUFSIZE = 2048
TIMEOUT = 5

# Flags for thread to safely finished
IS_PROXY_RUNNING = True

# Optional arguments
OPT_MT = False
OPT_PC = False

# Connection number
CONNECTION_NUM = 1

# Client sockets
CLIENT_SOCKS = []

def main():
    # Get proxy port
    proxyPort = int(sys.argv[1])

    # OPT_MT, OPT_PC, and IS_PROXY_RUNNING are global variable which can be modified in main function
    global OPT_MT
    global OPT_PC
    global IS_PROXY_RUNNING

    # Get either MT or PC option if exists
    if len(sys.argv) > 2:
        if sys.argv[2] == '-mt':
            OPT_MT = True
        elif sys.argv[2] == '-pc':
            OPT_PC = True

        if len(sys.argv) > 3:
            if sys.argv[3] == '-mt':
                OPT_MT = True
            elif sys.argv[3] == '-pc':
                OPT_PC = True

    # Make TCP socket for proxy and bind it
    proxySock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxySock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxySock.bind((PROXY_HOST, proxyPort))

    # Listen for connections
    proxySock.listen(20)

    # Print logs
    print('Proxy Server started on port ' + str(proxyPort) + ' at ' + datetime.datetime.now().strftime('%d/%b/%Y %H:%M:%S.%f'))
    if OPT_MT:
        print('* Multithreading - [ON]')
    else:
        print('* Multithreading - [OFF]')
    if OPT_PC:
        print('* Persistent Connection - [ON]')
    else:
        print('* Persistent Connection - [OFF]')
    print('')

    try:
        while True:
            # New client connection established
            clientSock, clientAddr = proxySock.accept()
            CLIENT_SOCKS.append(clientSock)

            if OPT_MT:
                # Use multi-thread if multithreading is enabled
                proxyThread = threading.Thread(target=handleProxy, args=(clientSock, clientAddr))
                proxyThread.start()
            else:
                # Use main thread if multithreading is disabled
                handleProxy(clientSock, clientAddr)
    except KeyboardInterrupt:
        print('KeyboardInterrupt')

        # Set proxy running flag as false
        IS_PROXY_RUNNING = False

        # Wait until background threads are exited safely
        mainThread = threading.currentThread()
        for thread in threading.enumerate():
            if thread is not mainThread:
                try:
                    thread.join()
                except:
                    pass

        # Close client sockets remained
        for clientSock in CLIENT_SOCKS:
            try:
                clientSock.shutdown(socket.SHUT_RDWR)
                clientSock.close()
            except:
                pass

        # Close proxy sockets
        try:
            proxySock.shutdown(socket.SHUT_RDWR)
            proxySock.close()
        except:
            pass

        # Exit program
        sys.exit()

# Start main function
if __name__ == '__main__':
    main()
