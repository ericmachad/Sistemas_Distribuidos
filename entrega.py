import pika
import json
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

with open("chave_publica_estoque.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(key_file.read())

def verify_signature(message, signature):
    message_hash = hashlib.sha256(message.encode()).digest()
    try:
        public_key.verify(
            bytes.fromhex(signature),
            message_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print("Erro na verificação da assinatura:", e)
        return False

def callback(ch, method, properties, body):
    data = json.loads(body)
    message = data['message']
    signature = data['signature']
    
    if verify_signature(message, signature):
        print("Produto a ser entregue:", message)
    else:
        print("Falha na verificação da mensagem!")

if __name__ == "__main__":
    connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost', port=5672))
    channel = connection.channel()

    channel.exchange_declare(exchange='events', exchange_type='topic')

    result = channel.queue_declare(queue='', exclusive=True)
    queue_name = result.method.queue
    channel.queue_bind(exchange='events', queue=queue_name, routing_key='entrega.produto')

    print('Esperando por mensagens...')
    channel.basic_consume(queue=queue_name, on_message_callback=callback, auto_ack=True)
    channel.start_consuming()