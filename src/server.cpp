#include <cctype>
#include <cstdint>
#include <cstring>
#include <ios>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

// https://en.cppreference.com/w/cpp/language/bit_field
struct __attribute__((packed)) header_struct {
	uint16_t id : 16;
	uint16_t qr : 1;
	uint16_t opcode : 4;
	uint16_t aa : 1;
	uint16_t tc : 1;
	uint16_t rd : 1;
	uint16_t ra : 1;
	uint16_t z : 3;
	uint16_t rcode : 4;
	uint16_t qdcount : 16;
	uint16_t ancount : 16;
	uint16_t nscount : 16;
	uint16_t arcount : 16;
};

void print_header_struct(const header_struct &hs) {
	// used Wiresark that ID uses a different byte order than my system
	std::cout << "id: " << ntohs(hs.id) << std::endl;
	std::cout << "qr: " << hs.qr << std::endl;
	std::cout << "opcode: " << hs.opcode << std::endl;
	std::cout << "aa: " << hs.aa << std::endl;
	std::cout << "tc: " << hs.tc << std::endl;
	std::cout << "rd: " << hs.rd << std::endl;
	std::cout << "ra: " << hs.ra << std::endl;
	std::cout << "z: " << hs.z << std::endl;
	std::cout << "rcode: " << hs.rcode << std::endl;
	std::cout << "qdcount: " << hs.qdcount << std::endl;
	std::cout << "ancount: " << hs.ancount << std::endl;
	std::cout << "nscount: " << hs.nscount << std::endl;
	std::cout << "arcount: " << hs.arcount << std::endl;
}

void print_hex(void *request, int bytesRead) {

	int byte_count = 0;

	for (int i = 0; i < bytesRead; i++) {
		std::printf("%02x ", static_cast<unsigned char>(((char *)request)[i]));

		byte_count++;
		if (byte_count % 16 == 0) {
			std::cout << std::endl;
		}
	}

	printf("\n");
}
void print_message(char *request, int bytesRead) {
	std::printf("message (hex):\n↓\n");
	print_hex(request, bytesRead);

	std::printf("↑\n");

	std::printf("message (ASCII):\n↓\n");

	int byte_count = 0;
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

		print_message(request, bytesRead);

		// Copy request to create response
		memcpy(response, request, bytesRead);
		memcpy(&h, request, sizeof(header_struct));

		print_header_struct(h);

		memcpy(response, &h, sizeof(header_struct));
		print_message(response, bytesRead);

		// Send response
		if (sendto(udpSocket, &h, sizeof(header_struct), 0, reinterpret_cast<struct sockaddr *>(&clientAddress), sizeof(clientAddress)) == -1) {
			perror("Failed to send response");
		}

		std::printf("↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑\n");
	}

	close(udpSocket);

	return 0;
}
