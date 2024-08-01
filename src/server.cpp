#include <cctype>
#include <cstdint>
#include <cstring>
#include <ios>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

// https://en.cppreference.com/w/cpp/language/bit_field
struct header_struct {
	uint16_t id : 16;
	unsigned int qr : 1;
	unsigned int opcode : 4;
	unsigned int aa : 1;
	unsigned int tc : 1;
	unsigned int rd : 1;
	unsigned int ra : 1;
	unsigned int z : 3;
	unsigned int rcode : 4;
	unsigned int qdcount : 16;
	unsigned int ancount : 16;
	unsigned int nscount : 16;
	unsigned int arcount : 16;
};

bool system_is_little_endian() {
	short int number = 0x0102;
	char *ptr = reinterpret_cast<char *>(&number);
	bool little_endian = *ptr == 0x02; // If the least significant byte is 0x02, it's little-endian
	if (little_endian) {
		std::cout << "System is little endian" << std::endl;
	} else {
		std::cout << "System is NOT little endian" << std::endl;
	}

	return little_endian;
}

uint16_t little_endian_to_big_endian(uint16_t value) {
	return (value >> 8) | (value << 8);
}

uint16_t big_endian_to_little_endian(uint16_t value) {
	return (value << 8) | (value >> 8);
}

void print_request(char *request, int bytesRead) {
	std::printf("message (hex):\n↓\n");
	for (int i = 0; i < bytesRead; i++) {
		std::printf("%02x ", static_cast<unsigned char>(request[i]));
	}
	std::printf("\n↑\n");

	std::printf("message (ASCII):\n↓\n");
	for (int i = 0; i < bytesRead; i++) {
		if (isprint(request[i])) {
			std::printf("%c", request[i]);
		} else {
			std::cout << ".";
		}
	}
	std::printf("\n↑\n");

	std::printf("message (hex, formatted):\n↓\n");
	int byte_count = 0;

	for (int i = 0; i < bytesRead; i++) {
		std::printf("%02x ", static_cast<unsigned char>(request[i]));

		byte_count++;
		if (byte_count % 16 == 0) {
			std::cout << std::endl;
		}
	}

	std::printf("\n↑\n");

	std::printf("message (ASCII, formatted):\n↓\n");

	byte_count = 0;
	for (int i = 0; i < bytesRead; i++) {
		if (std::isprint(request[i])) {
			printf("%2c ", request[i]);
		} else {
			printf("%2c ", '.');
		}
		byte_count++;
		if (byte_count % 16 == 0) {
			std::printf("\n");
		}
	}

	std::printf("\n↑\n");
}

int main() {
	// Flush after every std::cout / std::cerr
	std::cout << std::unitbuf;
	std::cerr << std::unitbuf;

	// Disable output buffering
	setbuf(stdout, nullptr);

	// You can use print statements as follows for debugging, they'll be visible when running tests.
	std::cout << "Logs from your program will appear here!" << std::endl;

	int udpSocket;
	struct sockaddr_in clientAddress;

	udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
	if (udpSocket == -1) {
		std::cerr << "Socket creation failed: " << strerror(errno) << "..." << std::endl;
		return 1;
	}

	// Since the tester restarts your program quite often, setting REUSE_PORT
	// ensures that we don't run into 'Address already in use' errors
	if (int reuse = 1; setsockopt(udpSocket, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
		std::cerr << "SO_REUSEPORT failed: " << strerror(errno) << std::endl;
		return 1;
	}

	sockaddr_in serv_addr = {
		.sin_family = AF_INET,
		.sin_port = htons(2053),
		.sin_addr = {htonl(INADDR_ANY)},
	};
	if (
		bind(udpSocket, reinterpret_cast<struct sockaddr *>(&serv_addr), sizeof(serv_addr)) != 0) {
		std::cerr << "Bind failed: " << strerror(errno) << std::endl;
		return 1;
	}

	std::cout << "Bound port: " << ntohs(serv_addr.sin_port) << std::endl;

	int bytesRead;
	char request[512];
	char response[512];
	socklen_t clientAddrLen = sizeof(clientAddress);

	header_struct h = {};
	while (true) {
		std::printf("↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓\n");

		// Receive data
		bytesRead = recvfrom(udpSocket, request, sizeof(request), 0, reinterpret_cast<struct sockaddr *>(&clientAddress), &clientAddrLen);
		if (bytesRead == -1) {
			perror("Error receiving data");
			break;
		}

		uint16_t source_port = ntohs(reinterpret_cast<struct sockaddr_in *>(&clientAddress)->sin_port);

		uint16_t destination_port = htons(2053);

		std::cout << "Source port: " << source_port << std::endl;
		std::cout << "Destination port: " << destination_port << std::endl;

		request[bytesRead] = '\0';
		std::cout << "Received UDP packet with " << bytesRead << " bytes" << std::endl;

		print_request(request, bytesRead);

		// Copy request to create response
		memcpy(response, request, bytesRead);
		memcpy(&h, request, sizeof(header_struct));

		uint16_t id_with_system_endianness;
		memcpy(&id_with_system_endianness, &request, 2);

		// found the solution using Wireshark
		if (system_is_little_endian()) {
			id_with_system_endianness = big_endian_to_little_endian(id_with_system_endianness);
		}

		std::cout << "id: " << id_with_system_endianness << std::endl;

		h.qr = 1;

		memcpy(response, &h, sizeof(header_struct));

		// Send response
		if (sendto(udpSocket, &h, sizeof(header_struct), 0, reinterpret_cast<struct sockaddr *>(&clientAddress), sizeof(clientAddress)) == -1) {
			perror("Failed to send response");
		}

		std::printf("↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑\n");
	}

	close(udpSocket);

	return 0;
}
