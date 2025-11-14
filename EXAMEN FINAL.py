import hashlib
import heapq
import os
from collections import defaultdict
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# Función de Hashing FNV-1
def fnv1_hash(message):
    hash = 0x811c9dc5 
    for byte in message.encode('utf-8'):
        hash = (hash * 0x01000193) & 0xffffffff  
        hash ^= byte
    return hash

# Comprimir el mensaje
def rle_compress(message):
    compressed = []
    prev_char = ''
    count = 1
    for char in message:
        if char == prev_char:
            count += 1
        else:
            if prev_char:
                compressed.append((prev_char, count))
            prev_char = char
            count = 1
    compressed.append((prev_char, count))
    return compressed

# Comprimir usando Huffman
def huffman_compress(message):
    freq = defaultdict(int)
    for char in message:
        freq[char] += 1

    heap = [[weight, [char, ""]] for char, weight in freq.items()]
    heapq.heapify(heap)

    while len(heap) > 1:
        lo = heapq.heappop(heap)
        hi = heapq.heappop(heap)
        for pair in lo[1:]:
            pair[1] = '0' + pair[1]
        for pair in hi[1:]:
            pair[1] = '1' + pair[1]
        heapq.heappush(heap, [lo[0] + hi[0]] + lo[1:] + hi[1:])

    huff_dict = {}
    for pair in heap[0][1:]:
        huff_dict[pair[0]] = pair[1]

    compressed_message = ''.join(huff_dict[char] for char in message)
    return compressed_message, huff_dict

# Firma con RSA
def sign_message(private_key, message_hash):
    signer = pkcs1_15.new(private_key)
    h = SHA256.new(message_hash.encode('utf-8'))
    signature = signer.sign(h)
    return signature

# Verificar firma digital
def verify_signature(public_key, message_hash, signature):
    verifier = pkcs1_15.new(public_key)
    h = SHA256.new(message_hash.encode('utf-8'))
    try:
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
def main():
    print(" M       E       N       U")
    print("1. Ingresar mensaje")
    print("2. Calcular hash FNV-1")
    print("3. Comprimir mensaje")
    print("4. Firmar el hash con RSA")
    print("5. Simular envIo")
    print("6. Descomprimir y verificar firma")
    print("7. Salir")
    
    message = ""
    hash_value = None
    compressed_message = None
    signature = None
    public_key = None
    private_key = None
    
    while True:
        option = input("\nSeleccione una opcion: ")
        
        if option == '1':
            message = input("Ingrese el mensaje: ")
        
        elif option == '2':
            hash_value = fnv1_hash(message)
            print(f"Hash FNV-1: {hash_value}")
        
        elif option == '3':
            compression_option = input("Seleccione el mwtodo de compresión (1: RLE, 2: Huffman): ")
            if compression_option == '1':
                compressed_message = rle_compress(message)
                print(f"Mensaje comprimido (RLE): {compressed_message}")
            elif compression_option == '2':
                compressed_message, _ = huffman_compress(message)
                print(f"Mensaje comprimido (Huffman): {compressed_message}")
        
        elif option == '4':
            if not private_key:
                private_key = RSA.generate(2048)
                public_key = private_key.publickey()
                print("Generando par de claves RSA...")

            if hash_value:
                signature = sign_message(private_key, str(hash_value))
                print(f"Firma digital: {signature.hex()}")
                print(f"Clave pública: {public_key.export_key().decode()}")
            else:
                print("Por favor, calcule el hash FNV-1 primero.")
        
        elif option == '5':
            if compressed_message and signature and public_key:
                print("Enviando mensaje comprimido junto con la firma digital y clave publica...")
            else:
                print("Complete las etapas previas antes de simular el envío.")
        
        elif option == '6':
            if compressed_message and signature and public_key:
                decompressed_message = ''.join([char * count for char, count in compressed_message]) if isinstance(compressed_message, list) else compressed_message
                print(f"Mensaje descomprimido: {decompressed_message}")
                
                new_hash_value = fnv1_hash(decompressed_message)
                print(f"Nuevo hash FNV-1: {new_hash_value}")
                
                if verify_signature(public_key, str(new_hash_value), signature):
                    print("Mensaje autentico")
                else:
                    print("Mensaje alterado")
            else:
                print("No se ha recibido un mensaje valido para verificar.")
        
        elif option == '7':
            print("Saliendo del programa.")
            break

if __name__ == '__main__':
    main()
