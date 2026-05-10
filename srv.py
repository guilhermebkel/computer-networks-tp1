import sys
import random
import socket

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
	
def setup_socket_server (port):
	socket_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	socket_server.bind(('0.0.0.0', port))

	return socket_server

def handle_socket_client_connections(socket_server, password, max_attempts):
	clients = {}
	total_processed_clients = 0

	# Requisito do TP:
	# - O programa servidor não deve ler nada da entrada padrão, nem escrever nada na saída padrão,
	# deve terminar depois que atender dois clientes (depois que o segundo cliente executar seu BYE).
	max_processed_clients = 2

	while total_processed_clients < max_processed_clients:
		print("Waiting for client connection...")

def main():
	port = int(sys.argv[1])
	password = str(sys.argv[2])
	max_attempts = int(sys.argv[3])

	password = setup_random_password_if_needed(password)

	socket_server = setup_socket_server(port)

	handle_socket_client_connections(socket_server, password, max_attempts)

if __name__ == '__main__':
  main()