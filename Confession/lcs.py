import socketserver

FLAG = "flag{test_flag_here}"

def lcs(a, b):
    dp = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]

    for i in range(len(a)):
        for j in range(len(b)): 
            if a[i] == b[j]:
                dp[i+1][j+1] = dp[i][j] + 1
            else:
                dp[i+1][j+1] = max(dp[i][j+1], dp[i+1][j])
                
    return dp[-1][-1]   

class OracleHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.sendall(
                b"\n[#] You're on trial. \n"
                b"[=] Speak nothing but the truth. \n\n"
                b"[=] You must confess:  "
            )
            while True:
                guess = self.request.recv(1024)
                if not guess:
                    break
                guess = guess.strip().decode(errors='ignore')
                score = lcs(guess, FLAG)
                try:
                    self.request.sendall(f"Truth: {score}\n".encode())
                    self.request.sendall(b"[=] You must confess:  ")
                except BrokenPipeError:
                    # Client disconnected early; stop handling
                    break
        except Exception as e:
            pass  # Optionally log or ignore unexpected issues


if __name__ ==  "__main__":
    HOST, PORT = "0.0.0.0", 8008

    with socketserver.ThreadingTCPServer((HOST, PORT), OracleHandler) as server:
        print(f"[+] Listening on port {PORT}...")
        server.serve_forever()