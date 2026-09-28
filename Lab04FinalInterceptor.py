# Lab04Final -- Part 3: The Stateful Interceptor
# DH key exchange + a rollback-resistant PRNG stream cipher + Mallory as an
# active MITM. (Same template as the old Lab03DHProgram.py, renamed and
# refiled under Lab04Final -- Lab03's schemes/DH content now lives here.)

import hashlib
import secrets
import os

# Zaeya DeBenedetti

# --- UI HELPER FUNCTIONS ---
def print_header(text):
    print(f"\n{'='*60}\n{text}\n{'='*60}")

def print_step(text):
    print(f"\n>> {text}")

def print_info(label, value):
    print(f"   [{label}]: {str(value)[:70]}...")



# --- Define Diffie-Hellman Constants G and P ---

P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)

G = 2



# --- PART A: STATEFUL PRNG ---

# Implement logic for PRNG function here
class SecurePRNG:

    def __init__(self, seed_int):
        # TODO: Initalize the SecurePRNG with the shared secret (seed_int) calculated from Diffie-Hellman key exchange.
        self.state = hashlib.sha256(seed_int.to_bytes(256, "big")).digest() #  Used Claude to fix an error with translating seed_int to bytes. The line helps to convert seed int to bytes which is then hashed to create a 32 byte internal state
    def generate(self, n_bytes): # I did use Claude to help figure out how to propely update a state to produce One-way progression. The use of AI was strictly for this SecurePRNG part of the coding portion as it was holding back the rest of my code without it propely working. While I did have in place the initilized SecurePRNG it was not working so I had to find out why which was due to state requires seed_int to be in bytes.
        # TODO: Generates n bytes while ensuring Rollback Resistance. 
        output = b""
        while len(output) < n_bytes:
            # 1. Produce keystream block from current state
            keystream = hashlib.sha256(self.state).digest() # generating a keystream using a one way hash(SHA256) of the current state that was established in the previous step
            output += keystream
            # 2. Update state immediately after with a hash function (One-way progression)
            self.state = hashlib.sha256(self.state + b"one-way-or-another").digest() #updating the current state by adding an extra phrase or counter to change the current state to ensure its different
        return output[:n_bytes]



def xor_crypt(data, prng):
    # TODO: Implement Simple XOR stream cipher logic.
    keystream = prng.generate(len(data)) # generating a keystream based off the the len of data
    output = []
    for i in range(0, len(data)):
        output.append(data[i] ^ keystream[i]) # xoring the data with the generated keystream
    return bytes(output) # translating the output into bytes


# --- PART B: COMMUNICATION PROTOCOL ---

class Entity:
    # TODO: Calculate public and private keys with global P and G.

    def __init__(self, name):
        self.name = name
        self.private_key = secrets.randbits(256) #generating a private key
        self.public_key = pow(G, self.private_key, P) # creating the public key based off G, P and the generated private key
        self.session_prng = None

    def get_public_hex(self):
        return hex(self.public_key)
    
    # TODO: calculate and initialize shared secret with SecurePRNG
    def establish_session(self, partner_pub_hex):
        partner_pub = int(partner_pub_hex, 16) # turning the partner public key (HEX format) into an it to use for establishing the shared secret (S)
        shared_secret = pow(partner_pub, self.private_key, P)
        self.session_prng = SecurePRNG(shared_secret) #initializing a shared secret secure prng session



# --- DO NOT MODIFY THIS CLASS --- #
# This class simulates the network and allows for an interceptor 'hook' (Mallory) to manipulate messages in transit.
class Network:
    def __init__(self):
        self.mallory = None  # The interceptor 'hook'

    def send(self, sender, recipient, payload):
        print(f"[NET] {sender} -> {recipient}: {str(payload)[:60]}...")
        if self.mallory:
            return self.mallory.intercept(sender, recipient, payload)
        return payload



# --- PART C: THE MALLORY MITM PROXY ---

# Implement logic for Mallory
class Mallory:
    def __init__(self):
        self.private_key = secrets.randbits(256)
        self.public_key = pow(G, self.private_key, P)
        self.public_hex = hex(self.public_key)
        
        # Mallory maintains TWO sessions
        self.alice_prng = None
        self.bob_prng = None

    def intercept(self, sender, recipient, payload):
        # 1. Implement Logic for Key Exchange Interception
        if isinstance(payload, str) and payload.startswith("0x"):
            remote_pub = int(payload, 16)
            my_shared_secret = pow(remote_pub, self.private_key, P)

            # TODO: If the sender is alice, generate a session PRNG with Alice. 
            # If the sender is Bob, generate a session PRNG with Bob.
            if(sender == "Alice"):
                self.alice_prng = SecurePRNG(my_shared_secret) # Since Alice is the sender, a session prng named alice_prng is established using Mallory's shared secret with the sender
            if(sender == "Bob"):
                self.bob_prng = SecurePRNG(my_shared_secret) # Establishes the same session as the previous code but instead with Bob
            return self.public_hex # Return Mallory's key instead to generate session PRNGs with Alice and Bob
        
        # 2. Implement Logic for Message Interception/Modification
        if isinstance(payload, bytes):
            print(f"[MALLORY] Intercepting Encrypted Message from {sender}...")

            # TODO: Decrypt the message using the appropriate session PRNG (Hint: Alice is the sender)
            # Print the plaintext message to the console for Mallory's spying purposes.
            decrypted_mall = xor_crypt(payload, self.alice_prng)
            print(f"[MALLORY] is always watching and found: ", decrypted_mall)
            # Modify the plaintext message in some way
            modified_mall = decrypted_mall.replace(b"9pm", b"3am") #changing 9pm to 3am to show Mallory changed the message
            print(f"[MALLORY] is changing the message!")
            # Then use the PRNG shared with bob to re-encrypt and return the message for Bob
            payload = xor_crypt(modified_mall, self.bob_prng) # re-encrypting the modified message before being sent out
        return payload



# --- DO NOT MODIFY THIS FUNCTION --- #
# --- MAIN EXECUTION SIMULATION ---
def main():
    # ==========================================
    # SCENARIO A: BENIGN (SECURE) COMMUNICATION
    # ==========================================
    print_header("SCENARIO A: BENIGN (SECURE) COMMUNICATION")
    
    alice = Entity("Alice")
    bob = Entity("Bob")
    net = Network()
    
    # Display Group Parameters
    print_step("Step 0: Global Group Parameters")
    print_info("G (Generator)", G)
    print_info("P (Prime)", P)

    print_step("Step 1: Public Key Exchange")
    print_info("Alice Private (a)", alice.private_key)
    print_info("Bob Private (b)", bob.private_key)
    
    # Alice -> Bob
    alice_pub = alice.get_public_hex()
    print_info("Alice Public (A = G^a mod P)", alice_pub)
    key_for_bob = net.send("Alice", "Bob", alice_pub)
    
    # Bob -> Alice
    bob_pub = bob.get_public_hex()
    print_info("Bob Public (B = G^b mod P)", bob_pub)
    key_for_alice = net.send("Bob", "Alice", bob_pub)
    
    print_step("Step 2: Establishing Sessions")
    alice.establish_session(key_for_alice)
    bob.establish_session(key_for_bob)
    print("   [Status]: Shared Secret computed: S = B^a mod P = A^b mod P")
    
    print_step("Step 3: Secure Message Transmission")
    message = b"youll never guess this message" # Put in your test message here
    encrypted_msg = xor_crypt(message, alice.session_prng)
    delivered_data = net.send("Alice", "Bob", encrypted_msg)
    final_message = xor_crypt(delivered_data, bob.session_prng)
    
    print_info("Bob decrypted", final_message.decode())

    # ==========================================
    # SCENARIO B: MALICIOUS (MITM) ATTACK
    # ==========================================
    print_header("SCENARIO B: MALICIOUS (MITM) ATTACK")
    
    alice = Entity("Alice")
    bob = Entity("Bob")
    mallory = Mallory()
    net = Network()
    net.mallory = mallory
    
    print_step("Step 1: Mallory's Parameters")
    print_info("Mallory Private (m)", mallory.private_key)
    print_info("Mallory Public (M)", mallory.public_hex)

    print_step("Step 2: Compromised Key Exchange")
    # Alice sends A -> Mallory Intercepts -> Returns M to Alice
    # Bob sends B -> Mallory Intercepts -> Returns M to Bob
    print("Alice sending key to Bob...")
    key_for_bob = net.send("Alice", "Bob", alice.get_public_hex())
    
    print("Bob sending key to Alice...")
    key_for_alice = net.send("Bob", "Alice", bob.get_public_hex())
    
    print_step("Step 3: Poisoned Shared Secrets")
    alice.establish_session(key_for_alice)
    bob.establish_session(key_for_bob)
    
    # Note: Alice's session uses S1 = M^a, Bob's uses S2 = M^b. Mallory knows both.
    print("   [Alice Session]: S_am = (Mallory_Pub)^a mod P")
    print("   [Bob Session]:   S_bm = (Mallory_Pub)^b mod P")

    print_step("Step 4: Interception")
    message = b"Meet me at 9pm."
    encrypted_msg = xor_crypt(message, alice.session_prng)
    delivered_data = net.send("Alice", "Bob", encrypted_msg)
    
    final_message = xor_crypt(delivered_data, bob.session_prng)
    print_info("Bob received", final_message.decode())
    
    if b"3am" in final_message:
        print("\n[DANGER] MITM SUCCESS: Mallory used her private key (m) to decrypt and re-encrypt.")

if __name__ == "__main__":
    main()