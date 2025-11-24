import random
import math  # Used for gcd() and random number generation

def power(a, b, m):
    """Computes (a^b) % m using modular exponentiation"""
    res = 1
    a %= m
    while b > 0:
        if b % 2 == 1:
            res = (res * a) % m
        a = (a * a) % m
        b //= 2
    return res

def miller_rabin_is_prime(n, k=5):
    """Miller-Rabin primality test with k rounds"""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^s * d
    s = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        s += 1

    # Witness loop
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = power(a, d, n)
        if x == 1 or x == n - 1:
            continue
        
        composite = True
        for _ in range(s - 1):
            x = power(x, 2, n)
            if x == n - 1:
                composite = False
                break
        if composite:
            return False # n is composite

    return True # n is probably prime

def generate_random_prime(min_val):
    """Generates a random prime number greater than min_val"""
    # Calculate required bit length with 10-bit margin
    required_bit_length = min_val.bit_length() + 10

    # Minimum 128 bits for security
    if required_bit_length < 128:
        required_bit_length = 128

    lower_bound_for_q = max(min_val + 1, 2**(required_bit_length - 1))
    upper_bound_for_q = 2**required_bit_length - 1

    if lower_bound_for_q % 2 == 0:
        lower_bound_for_q += 1

    max_attempts = 2000
    for _ in range(max_attempts):
        if lower_bound_for_q > upper_bound_for_q:
            raise ValueError(f"Lower bound exceeds upper bound for prime generation")

        num = random.randint(lower_bound_for_q, upper_bound_for_q)
        if num % 2 == 0:
            num += 1
        
        if num > upper_bound_for_q:
            num = upper_bound_for_q - 2 if upper_bound_for_q % 2 == 0 else upper_bound_for_q - 1
            if num < lower_bound_for_q:
                num = lower_bound_for_q
                if num % 2 == 0: num += 1

        if miller_rabin_is_prime(num):
            return num
        
    raise ValueError(f"Could not find suitable prime after {max_attempts} attempts")

def mod_inverse(a, m):
    """Computes modular inverse using Extended Euclidean Algorithm"""
    m0 = m
    y = 0
    x = 1

    if m == 1:
        return 0

    while a > 1:
        q = a // m  # Quotient
        t = m
        m = a % m
        a = t
        t = y
        y = x - q * y
        x = t

    if x < 0:
        x = x + m0

    return x

def generate_key_pair(n):
    """Generates public/private key pair for n-bit blocks"""
    # Generate superincreasing sequence e
    e = []
    sum_e = 0
    for i in range(n):
        if i == 0:
            e_i = random.randint(2, 50)
        else:
            e_i = sum_e + random.randint(1, 100)
        e.append(e_i)
        sum_e += e_i

    # Generate prime q > 2*e_n
    q = generate_random_prime(2 * e[-1])

    # Generate w coprime to q
    while True:
        w = random.randint(2, q - 1)
        if math.gcd(w, q) == 1:
            break

    # Compute public key h where h_i = (w * e_i) mod q
    h = [(w * e_val) % q for e_val in e]

    private_key = (e, q, w)
    public_key = h
    return public_key, private_key

def encrypt(message_bits, public_key):
    """Encrypts message bits using public key h"""
    if len(message_bits) != len(public_key):
        raise ValueError("Message bits length must match public key length")

    ciphertext = sum(public_key[i] * message_bits[i] for i in range(len(message_bits)))
    return ciphertext

def decrypt(ciphertext, private_key):
    """Decrypts ciphertext using private key (e, q, w)"""
    e, q, w = private_key
    n = len(e)

    w_inv = mod_inverse(w, q)
    c_prime = (ciphertext * w_inv) % q

    decrypted_message_bits = [0] * n

    # Recover bits using superincreasing property
    for i in range(n - 1, -1, -1):
        if c_prime >= e[i]:
            decrypted_message_bits[i] = 1
            c_prime -= e[i]
    
    return decrypted_message_bits

def text_to_bits(text):
    """Converts text to 8-bit ASCII binary representation"""
    bits = []
    for char in text:
        ascii_val = ord(char)
        binary_str = bin(ascii_val)[2:].zfill(8)
        bits.extend([int(bit) for bit in binary_str])
    return bits

def bits_to_text(bits):
    """Converts bits back to text using 8-bit ASCII chunks"""
    text = []
    for i in range(0, len(bits), 8):
        byte_bits = bits[i:i+8]
        if len(byte_bits) == 8:
            byte_str = "".join(str(b) for b in byte_bits)
            ascii_val = int(byte_str, 2)
            text.append(chr(ascii_val))
    return "".join(text)

def main():
    MIN_MESSAGE_LENGTH_CHARS = 500
    N_BITS = 128

    print(f"--- Merkle-Hellman Knapsack Cryptosystem (Block Size N = {N_BITS} bits) ---")

    my_name = "Tang Yang"

    # reference: Chapter 1, https://ia601800.us.archive.org/5/items/blackbeautyautob00sewe/blackbeautyautob00sewe.pdf
    black_beauty = "The first place that I can well remember, was a large pleasant meadow with a pond of clear water in it. Some trees overshadowed the pond, and rushes and water-lilies grew at the deep end. Over the hedge on one side we looked into a ploughed field ; and on the other, we looked over a gate at our master's house which stood by the roadside. At the top of the meadow was a plantation of fir-trees ; and at the bottom, a running brook overhung by a steep bank. Whilst I was young I lived upon my mother's milk, as I could not eat grass. In the daytime I ran by her side, and at night I lay down close by her. When it was hot, we used to stand by the pond in the shade of the trees ; and when it was cold, we had a nice warm shed near the plantation. As soon as I was old enough to eat grass, my mother"
            
    base_plaintext = f"To {my_name}: {black_beauty} "
    
    while len(base_plaintext) < MIN_MESSAGE_LENGTH_CHARS:
        base_plaintext += black_beauty + " "        # repeatedly concatenate until minimum length is reached
    
    original_plaintext = base_plaintext[:MIN_MESSAGE_LENGTH_CHARS]

    print(f"\nOriginal Plaintext ({len(original_plaintext)} chars):\n{original_plaintext}")

    full_message_bits = text_to_bits(original_plaintext)
    
    padding_needed = N_BITS - (len(full_message_bits) % N_BITS)     # ensures length of message is a multiple of N_BITS
    if padding_needed != N_BITS:        
        full_message_bits.extend([0] * padding_needed)

    print(f"\nFull message in bits (total {len(full_message_bits)} bits, first 16 and last 16): {full_message_bits[:16]}...{full_message_bits[-16:]}")

    print("\n" + "="*30 + " Test Case 1 " + "="*30)
    print("\nGenerating Key Pair 1...")
    public_key1, private_key1 = generate_key_pair(N_BITS)
    e1, q1, w1 = private_key1
    
    print("\n--- Key Pair 1 Details ---")
    print(f"Public Key (h1, first 10 elements): {public_key1[:10]}...")
    print(f"Private Key (e1, first 10 elements): {e1[:10]}...")
    print(f"Private Key (q1): {q1}")
    print(f"Private Key (w1): {w1}")
    print("-------------------------------------------------")

    print("\nEncrypting with Key Pair 1...")
    encrypted_ciphertexts1 = []
    for i in range(0, len(full_message_bits), N_BITS):
        block_bits = full_message_bits[i : i + N_BITS]
        try:
            ciphertext_block = encrypt(block_bits, public_key1)
            encrypted_ciphertexts1.append(ciphertext_block)
        except ValueError as e:
            print(f"Error during encryption (Key Pair 1, block {i//N_BITS}): {e}")
            return

    print(f"Ciphertext 1 (first 3 blocks): {encrypted_ciphertexts1[:3]}...")

    print("\nDecrypting with Key Pair 1...")
    decrypted_full_bits1 = []
    for ciphertext_block in encrypted_ciphertexts1:
        decrypted_block_bits = decrypt(ciphertext_block, private_key1)
        decrypted_full_bits1.extend(decrypted_block_bits)
    
    decrypted_text1 = bits_to_text(decrypted_full_bits1[:len(text_to_bits(original_plaintext))])

    print(f"Decrypted Plaintext 1 ({len(decrypted_text1)} chars):\n{decrypted_text1}")

    if decrypted_text1 == original_plaintext:
        print("\nVerification 1: Decryption successful! Original and decrypted plaintexts match.")
    else:
        print("\nVerification 1: Decryption FAILED! Original and decrypted plaintexts DO NOT match.")
        print(f"Original (first 50): {original_plaintext[:50]}")
        print(f"Decrypted (first 50): {decrypted_text1[:50]}")


    # --- Test Case 2 ---
    print("\n" + "="*30 + " Test Case 2 " + "="*30)
    print("\nGenerating Key Pair 2...")
    public_key2, private_key2 = generate_key_pair(N_BITS)
    e2, q2, w2 = private_key2

    print("\n--- Key Pair 2 Details ---")
    print(f"Public Key (h2, first 10 elements): {public_key2[:10]}...")
    print(f"Private Key (e2, first 10 elements): {e2[:10]}...")
    print(f"Private Key (q2): {q2}")
    print(f"Private Key (w2): {w2}")
    print("-------------------------------------------------")

    print("\nEncrypting with Key Pair 2 (same plaintext)...")
    encrypted_ciphertexts2 = []
    for i in range(0, len(full_message_bits), N_BITS):
        block_bits = full_message_bits[i : i + N_BITS]
        try:
            ciphertext_block = encrypt(block_bits, public_key2)
            encrypted_ciphertexts2.append(ciphertext_block)
        except ValueError as e:
            print(f"Error during encryption (Key Pair 2, block {i//N_BITS}): {e}")
            return

    print(f"Ciphertext 2 (first 3 blocks): {encrypted_ciphertexts2[:3]}...")

    print("\nDecrypting with Key Pair 2...")
    decrypted_full_bits2 = []
    for ciphertext_block in encrypted_ciphertexts2:
        decrypted_block_bits = decrypt(ciphertext_block, private_key2)
        decrypted_full_bits2.extend(decrypted_block_bits)
    
    decrypted_text2 = bits_to_text(decrypted_full_bits2[:len(text_to_bits(original_plaintext))])

    print(f"Decrypted Plaintext 2 ({len(decrypted_text2)} chars):\n{decrypted_text2}")

    if decrypted_text2 == original_plaintext:
        print("\nVerification 2: Decryption successful! Original and decrypted plaintexts match.")
    else:
        print("\nVerification 2: Decryption FAILED! Original and decrypted plaintexts DO NOT match.")
        print(f"Original (first 50): {original_plaintext[:50]}")
        print(f"Decrypted (first 50): {decrypted_text2[:50]}")

if __name__ == "__main__":
    main()