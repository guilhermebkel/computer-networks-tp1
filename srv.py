import sys
import random
import socket
import struct
from enum import IntEnum

PROTOCOL_MESSAGE_CHECKSUM_BYTE_INDEX = 1

class MessageType(IntEnum):
	HEL = 1
	TRY = 2
	RES = 3
	BYE = 4
	ERR = 5

def setup_random_password_if_needed (password):
	# Requisito do TP:
	# - Uma senha representada como uma sequência com entre 4 e 8 zeros indica que uma senha
	# daquele comprimento deve ser escolhida aleatoriamente pelo servidor no momento da execução.
	is_password_composed_only_by_zeros = all(character == '0' for character in password)

	if (is_password_composed_only_by_zeros):
		digits = list(range(10))
		random.shuffle(digits)
		password_size = len(password)
		random_password = ''.join(str(digit) for digit in digits[:password_size])

		return random_password
	else:
		return password
	
def parse_message (message):
	type = message[0]
	sequence_number = struct.unpack('!H', message[2:4])[0]
	payload = message[4:] if len(message) > 4 else b''

	return type, sequence_number, payload
	
def calculate_message_checksum (message):
	checksum = 0

	for index, byte in enumerate(message):
		is_not_protocol_message_checksum_byte = index != PROTOCOL_MESSAGE_CHECKSUM_BYTE_INDEX

		if is_not_protocol_message_checksum_byte:
			checksum ^= byte

	return checksum
	
def is_valid_message (message):
	has_minimum_protocol_message_size = len(message) >= 4

	if not has_minimum_protocol_message_size:
		return False
	else:
		calculated_message_checksum = calculate_message_checksum(message)
		protocol_message_checksum = message[PROTOCOL_MESSAGE_CHECKSUM_BYTE_INDEX]

		is_valid_checksum = calculated_message_checksum == protocol_message_checksum

		return is_valid_checksum
	
def setup_socket_server (port):
	socket_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	socket_server.bind(('0.0.0.0', port))

	return socket_server

def handle_socket_client_connections(socket_server, password, max_attempts):
	client_address_to_client_state = {}
	total_processed_clients = 0

	# Requisito do TP:
	# - O programa servidor não deve ler nada da entrada padrão, nem escrever nada na saída padrão,
	# deve terminar depois que atender dois clientes (depois que o segundo cliente executar seu BYE).
	max_processed_clients = 2

	while total_processed_clients < max_processed_clients:
		message, address = socket_server.recvfrom(2048)

		if not is_valid_message(message):
			continue

		type, sequence_number, payload = parse_message(message)
		client_state = client_address_to_client_state[address]

		match type:
			case MessageType.HEL:
				print("Hello")
			case MessageType.TRY:
				print("Try")
			case MessageType.BYE:
				print("Bye")
			case _:
				print("Received message with unknown type, ignoring...")

def main():
	port = int(sys.argv[1])
	password = str(sys.argv[2])
	max_attempts = int(sys.argv[3])

	password = setup_random_password_if_needed(password)

	socket_server = setup_socket_server(port)

	handle_socket_client_connections(socket_server, password, max_attempts)

	socket_server.close()

if __name__ == '__main__':
  main()