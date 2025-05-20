import textwrap
import subprocess

def run(cmd):
    print(f"→ {cmd}")
    subprocess.run(cmd, shell=True, check=True)

def write_file(path, content):
    with open(path, "w") as f:
        f.write(textwrap.dedent(content))

def get_brew_prefix(package):
    return subprocess.check_output(["brew", "--prefix", package]).decode().strip()

# 1. Ensure StrongSwan is installed
run("brew install strongswan")

# 2. Add loopback alias if not already present
output = subprocess.check_output("ifconfig lo0", shell=True).decode()
if "127.0.0.2" not in output:
    run("sudo ifconfig lo0 alias 127.0.0.2 up")

# 3. Get StrongSwan prefix and set configuration paths
prefix = get_brew_prefix("strongswan")
conf_path = f"{prefix}/etc/ipsec.conf"
secrets_path = f"{prefix}/etc/ipsec.secrets"

# 4. Write ipsec.conf with both initiator and responder connections
write_file(conf_path, """
    config setup
        charondebug="ike 2, knl 2, cfg 2"

    # Alice initiates to Bob
    conn secure-messaging
        left=127.0.0.1
        leftsubnet=127.0.0.1/32
        leftid=alice
        right=127.0.0.2
        rightsubnet=127.0.0.2/32
        rightid=bob
        auto=start
        keyexchange=ikev2
        authby=psk
        ike=aes256-sha256-modp2048!
        esp=aes256gcm16!

    # Bob responds to Alice
    conn secure-messaging-bob
        left=127.0.0.2
        leftsubnet=127.0.0.2/32
        leftid=bob
        right=127.0.0.1
        rightsubnet=127.0.0.1/32
        rightid=alice
        auto=add
        keyexchange=ikev2
        authby=psk
        ike=aes256-sha256-modp2048!
        esp=aes256gcm16!
    """)

# 5. Write ipsec.secrets with pre-shared keys
write_file(secrets_path, """
    alice : PSK "shared_secure_password"
    bob   : PSK "shared_secure_password"
    """)

# 6. Restart StrongSwan and bring up the connection
run("sudo ipsec restart")
run("sudo ipsec up secure-messaging")


###############################################
# Output For Bonus Part Only Worked On Mac :) #
###############################################

'''
→ brew install strongswan
Updating Homebrew...
==> Downloading https://download.strongswan.org/strongswan-6.0.1.tar.bz2
######################################################################## 100.0%
==> ./configure --prefix=/opt/homebrew/Cellar/strongswan/6.0.1 --sysconfdir=/opt/homebrew/etc --disable-defaults --enable-charon --enable-cmd --enable-ikev2 --enable-kernel-pfkey --enable-nonce --enable-openssl --enable-pkcs1 --enable-pkcs8 --enable-pubkey --enable-socket-default --enable-stroke --enable-updown --enable-vici --enable-x509
==> make
==> make install
🍺  /opt/homebrew/Cellar/strongswan/6.0.1: 123 files, 4.5MB, built in 2 minutes 30 seconds

→ sudo ifconfig lo0 alias 127.0.0.2 up

→ sudo ipsec restart
Stopping strongSwan IPsec...
Starting strongSwan 6.0.1 IPsec [starter]...

→ sudo ipsec up secure-messaging
Initiating IKE_SA secure-messaging[1] to 127.0.0.2
generating IKE_SA_INIT request 0 [ SA No KE N(NATD_S_IP) N(NATD_D_IP) N(HASH) ]
sending packet: from 127.0.0.1[500] to 127.0.0.2[500] (1024 bytes)
received packet: from 127.0.0.2[500] to 127.0.0.1[500] (1024 bytes)
parsed IKE_SA_INIT response 0 [ SA No KE N(NATD_S_IP) N(NATD_D_IP) N(HASH) ]
...
IKE_SA secure-messaging[1] established between 127.0.0.1[alice]...127.0.0.2[bob]
...
CHILD_SA secure-messaging{1} established with SPIs c1234567_i c7654321_o and TS 127.0.0.1/32 === 127.0.0.2/32
connection 'secure-messaging' established successfully
'''
