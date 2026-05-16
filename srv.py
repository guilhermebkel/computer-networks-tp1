import sys
import random
import socket
import struct
from enum import IntEnum, Enum

PROTOCOL_MESSAGE_CHECKSUM_BYTE_INDEX = 1

client_address_to_client_state = {}
total_processed_clients = 0

class MessageType(IntEnum):
	HEL = 1
	TRY = 2
	RES = 3
	BYE = 4
	ERR = 5

class ClientStatePhase(Enum):
	INIT = 'init'
	PLAYING = 'playing'
	DONE = 'done'

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

def build_message (type, sequence_number, payload=b''):
	sequence_number_in_bytes = struct.pack('!H', sequence_number & 0xFFFF)
	raw_message = bytes([type, 0]) + sequence_number_in_bytes + payload
	checksum = calculate_message_checksum(raw_message)

	response_message = bytes([type, checksum]) + sequence_number_in_bytes + payload

	return response_message
	
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

def evaluate_password_guess (password, client_guess_digits):
	evaluation = []

	for index, guess_digit in enumerate(client_guess_digits):
		is_valid_guess_digit = guess_digit == password[index]
		is_guess_contained_in_password = guess_digit in password

		if is_valid_guess_digit:
			evaluation.append('*')
		elif is_guess_contained_in_password:
			evaluation.append('+')
		else:
			evaluation.append('-')

	return ''.join(evaluation)

def process_hel_message (sequence_number, socket_server, client_address, password, max_attempts):
	client_state = client_address_to_client_state[client_address]

	has_invalid_sequence_number = sequence_number != 0

	if has_invalid_sequence_number:
		response_message = build_message(MessageType.ERR, sequence_number)
		socket_server.sendto(response_message, client_address)
		return
	
	is_client_already_initialized = client_state is not None and client_state['phase'] != ClientStatePhase.INIT

	if is_client_already_initialized:
		if client_state['last_sent']:
			socket_server.sendto(client_state['last_sent'], client_address)
		return
	
	password_guess_evaluation_in_bytes = bytes([ord('?')] * len(password) + [ord(' ')] * (8 - len(password)))
	response_message = build_message(MessageType.RES, max_attempts, password_guess_evaluation_in_bytes)

	client_address_to_client_state[client_address] = {
		'phase': ClientStatePhase.PLAYING,
		'expected_sequence_number': 1,
		'last_sent': response_message
	}

	socket_server.sendto(response_message, client_address)

def process_try_message (sequence_number, socket_server, client_address, password, client_message, payload, max_attempts):
	client_state = client_address_to_client_state[client_address]

	is_client_not_initialized_yet = client_state is None or client_state['phase'] != ClientStatePhase.PLAYING

	if is_client_not_initialized_yet:
		response_message = build_message(MessageType.ERR, 0)
		socket_server.sendto(response_message, client_address)
		return

	expected_sequence_number = client_state['expected_sequence_number']

	is_message_retransmission = sequence_number < expected_sequence_number

	if is_message_retransmission:
		if client_state['last_sent']:
			socket_server.sendto(client_state['last_sent'], client_address)
		return

	is_message_out_of_order_or_max_attempted = sequence_number > expected_sequence_number or sequence_number > max_attempts

	if is_message_out_of_order_or_max_attempted:
		response_message = build_message(MessageType.ERR, sequence_number)
		socket_server.sendto(response_message, client_address)
		return

	is_message_incomplete = len(client_message) < 12

	if is_message_incomplete:
		response_message = build_message(MessageType.ERR, sequence_number)
		client_state['last_sent'] = response_message
		client_state['expected_sequence_number'] = sequence_number + 1
		socket_server.sendto(response_message, client_address)
		return

	client_guess_digits = list(payload[:len(password)])

	is_valid_client_guess = True

	for guess_digit in client_guess_digits:
		is_guess_digit_outside_valid_range = guess_digit < 0 or guess_digit > 9

		if is_guess_digit_outside_valid_range:
			is_valid_client_guess = False
			break
	
	is_guess_with_repeated_digits = len(set(client_guess_digits)) != len(password)

	if is_guess_with_repeated_digits:
		is_valid_client_guess = False
	
	if not is_valid_client_guess:
		response_message = build_message(MessageType.ERR, sequence_number)
		client_state['last_sent'] = response_message
		client_state['expected_sequence_number'] = sequence_number + 1
		socket_server.sendto(response_message, client_address)
		return
	
	password_guess_evaluation = evaluate_password_guess(password, client_guess_digits)
	remaining_attempts = max_attempts - sequence_number
	password_guess_evaluation_in_bytes = bytes([ord(eval_item) for eval_item in password_guess_evaluation] + [ord(' ')] * (8 - len(password)))
	response_message = build_message(MessageType.RES, remaining_attempts, password_guess_evaluation_in_bytes)
	client_state['last_sent'] = response_message
	client_state['expected_sequence_number'] = sequence_number + 1
	socket_server.sendto(response_message, client_address)

def process_bye_message (sequence_number, socket_server, client_address, password):
	client_state = client_address_to_client_state[client_address]

	is_client_invalid_state = client_state is None

	if is_client_invalid_state:
		response_message = build_message(MessageType.ERR, 0)
		socket_server.sendto(response_message, client_address)
		return
	
	is_client_already_finished = client_state['phase'] == ClientStatePhase.DONE

	if is_client_already_finished:
		if client_state['last_sent']:
			socket_server.sendto(client_state['last_sent'], client_address)
		return
		
	is_client_not_initialized_yet = client_state['phase'] != ClientStatePhase.PLAYING

	if is_client_not_initialized_yet:
		response_message = build_message(MessageType.ERR, 0)
		socket_server.sendto(response_message, client_address)
		return

	expected_bye_sequence_number = client_state['expected_sequence_number'] - 1

	is_out_of_order_bye_message = sequence_number != expected_bye_sequence_number

	if is_out_of_order_bye_message:
		response_message = build_message(MessageType.ERR, sequence_number)
		socket_server.sendto(response_message, client_address)
		return

	password_in_bytes = bytes([ord(password_digit) for password_digit in password] + [ord(' ')] * (8 - len(password)))
	response_message = build_message(MessageType.RES, 0xFFFF, password_in_bytes)
	client_state['last_sent'] = response_message
	client_state['phase'] = ClientStatePhase.DONE
	socket_server.sendto(response_message, client_address)

	total_processed_clients += 1

def process_unknown_message (socket_server, client_address):
	response_message = build_message(MessageType.ERR, 0)
	socket_server.sendto(response_message, client_address)

def handle_socket_client_connections (socket_server, password, max_attempts):
	# Requisito do TP:
	# - O programa servidor não deve ler nada da entrada padrão, nem escrever nada na saída padrão,
	# deve terminar depois que atender dois clientes (depois que o segundo cliente executar seu BYE).
	max_processed_clients = 2

	while total_processed_clients < max_processed_clients:
		client_message, client_address = socket_server.recvfrom(2048)

		if not is_valid_message(client_message):
			continue

		type, sequence_number, payload = parse_message(client_message)

		match type:
			case MessageType.HEL:
				process_hel_message(sequence_number, socket_server, client_address, password, max_attempts)
			case MessageType.TRY:
				process_try_message(sequence_number, socket_server, client_address, password, client_message, payload, max_attempts)
			case MessageType.BYE:
				process_bye_message(sequence_number, socket_server, client_address, password)
			case _:
				process_unknown_message(socket_server, client_address)

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