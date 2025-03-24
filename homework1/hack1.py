import requests
from Crypto.Util.number import bytes_to_long, long_to_bytes

base_url = "https://rsaenc.syssec.dk/"

response = requests.get(base_url + 'pk/')
print(response.text)
data = response.json()
N = data['N']
e = data['e']
block_size = (N.bit_length() + 7) // 8

print(block_size)

# obtain initial ciphertext
response = requests.get(base_url)
authtoken = response.cookies.get('authtoken')
print("Auth token:", authtoken)
c = bytes.fromhex(authtoken)
c_int = bytes_to_long(c)
print(c_int)

lower = 0
upper = N
iterations = N.bit_length()


def get_oracle_response(c_int, block_size):
    c_bytes = long_to_bytes(c_int, block_size)
    hex_token = c_bytes.hex()
    response = requests.get(
        base_url + 'quote/',
        cookies={'authtoken': hex_token},
        allow_redirects=False
    )
    if response.status_code == 200:
        if 'I do not like even numbers.' in response.text:
            return 'even'
        else:
            return 'odd'
    else:
        return 'error'

for _ in range(iterations):
    c_int = (c_int * pow(2, e, N)) % N
    response = get_oracle_response(c_int, block_size)

    mid = (lower + upper) // 2
    if response == 'even':
        upper = mid
    else:
        lower = mid

recovered_m = upper
print(recovered_m)

m_bytes = long_to_bytes(recovered_m, block_size)
print(m_bytes)

def pkcs1_unpad(padded, bs):
    if len(padded) != bs:
        return None
    if padded[0] != 0x00 or padded[1] != 0x02:
        return None
    sep = padded.find(b'\x00', 2)
    if sep == -1:
        return None
    return padded[sep+1:]

unpadded = pkcs1_unpad(m_bytes, block_size)
if unpadded:
    secret = unpadded.split(b'"')[1]
    print("Recovered secret:", secret.decode())
else:
    print("Unpadding failed.")

correct_plain = b'Not using proper OAEP is dangerous ...' + b' because of weird oracles!'

def pkcs1_pad(message, block_size):
    padding_length = block_size - len(message) - 3
    padding = b'\x01' * padding_length
    return b'\x00\x02' + padding + b'\x00' + message

padded_message = pkcs1_pad(correct_plain, block_size)

m = bytes_to_long(padded_message)
ciphertext = pow(m, e, N)
ciphertext_bytes = long_to_bytes(ciphertext, block_size)
hex_token = ciphertext_bytes.hex()

response = requests.get(
    base_url + 'quote/',
    cookies={'authtoken': hex_token},
    allow_redirects=False
)

print("Response status:", response.status_code)
print("Response text:", response.text)

