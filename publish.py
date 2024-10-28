import pika
import json
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

# Carregar a chave privada do Publicador A
with open("chave_privada.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(key_file.read(), password=None)

def sign_message(message):
    # Gerar uma assinatura para a mensagem
    message_hash = hashlib.sha256(message.encode()).digest()
    signature = private_key.sign(
        message_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def publish_message(message):
    # Conectar ao RabbitMQ
    connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost', port=5672))
    channel = connection.channel()

    # Declarar a exchange do tipo "topic"
    channel.exchange_declare(exchange='events', exchange_type='topic')

    # Assinar a mensagem
    signature = sign_message(message)

    # Publicar a mensagem e a assinatura
    channel.basic_publish(
        exchange='events',
        routing_key='venda.pedido_realizado',
        body=json.dumps({'message': message, 'signature': signature.hex()})
    )
    print("Mensagem publicada:", message)
    connection.close()

if __name__ == "__main__":
    publish_message("Pedido realizado com sucesso!")
