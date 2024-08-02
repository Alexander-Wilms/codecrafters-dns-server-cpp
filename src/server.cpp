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
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;

	bool isQuery() const {
		return (flags >> 15) & 0x1;
	}

	void setQuery(bool isQuery) {
		if (isQuery) {
			flags |= (0x1 << 15);
		} else {
			flags &= ~(0x1 << 15);
		}
	}

	bool isAuthoritative() const {
		return (flags >> 10) & 0x1;
	}

	void setAuthoritative(bool isAuthoritative) {
		if (isAuthoritative) {
			flags |= (0x1 << 10);
		} else {
			flags &= ~(0x1 << 10);
		}
	}

	bool isTruncated() const {
		return (flags >> 9) & 0x1;
	}

	void setTruncated(bool isTruncated) {
		if (isTruncated) {
			flags |= (0x1 << 9);
		} else {
			flags &= ~(0x1 << 9);
		}
	}

	bool isRecursionDesired() const {
		return (flags >> 8) & 0x1;
	}

	void setRecursionDesired(bool recursionDesired) {
		if (recursionDesired) {
			flags |= (0x1 << 8);
		} else {
			flags &= ~(0x1 << 8);
		}
	}

	bool isRecursionAvailable() const {
		return (flags >> 7) & 0x1;
	}

	void setRecursionAvailable(bool recursionAvailable) {
		if (recursionAvailable) {
			flags |= (0x1 << 7);
		} else {
			flags &= ~(0x1 << 7);
		}
	}

	uint8_t getReserved() const {
		return (flags >> 4) & 0x7;
	}

	void setReserved(uint8_t zField) {
		flags &= 0xFF8F;			  // Clear the 3 bits for Z field
		flags |= (zField & 0x7) << 4; // Set the 3 bits for Z field
	}
};

struct __attribute__((packed)) question_struct {
	char name[512];
	uint16_t type;
	uint16_t _class;
};

typedef uint16_t (*byte_order_conversion_func)(uint16_t);

header_struct convert_struct_byte_order(const header_struct &struct_with_network_byte_order, byte_order_conversion_func conversion_func) {
	header_struct struct_with_host_byte_order;
	struct_with_host_byte_order = struct_with_network_byte_order;
	struct_with_host_byte_order.id = conversion_func(struct_with_network_byte_order.id);
	struct_with_host_byte_order.flags = conversion_func(struct_with_network_byte_order.flags);
	struct_with_host_byte_order.qdcount = conversion_func(struct_with_network_byte_order.qdcount);
	struct_with_host_byte_order.ancount = conversion_func(struct_with_network_byte_order.ancount);
	struct_with_host_byte_order.nscount = conversion_func(struct_with_network_byte_order.nscount);
	struct_with_host_byte_order.arcount = conversion_func(struct_with_network_byte_order.arcount);

	return struct_with_host_byte_order;
}

void print_header_struct(const header_struct &hs) {
	// used Wiresark to determine that ID uses a different byte order than my system
	// this applies to all uint16_t fields
	std::cout << "id: " << ntohs(hs.id) << std::endl;
	std::cout << "qr: " << ((hs.flags >> 15) & 0x1) << std::endl;
	std::cout << "opcode: " << ((hs.flags >> 11) & 0xF) << std::endl;
	std::cout << "aa: " << ((hs.flags >> 10) & 0x1) << std::endl;
	std::cout << "tc: " << ((hs.flags >> 9) & 0x1) << std::endl;
	std::cout << "rd: " << ((hs.flags >> 8) & 0x1) << std::endl;
	std::cout << "ra: " << ((hs.flags >> 7) & 0x1) << std::endl;
	std::cout << "z: " << ((hs.flags >> 4) & 0x7) << std::endl;
	std::cout << "rcode: " << (hs.flags & 0xF) << std::endl;
	std::cout << "qdcount: " << ntohs(hs.qdcount) << std::endl;
	std::cout << "ancount: " << ntohs(hs.ancount) << std::endl;
	std::cout << "nscount: " << ntohs(hs.nscount) << std::endl;
	std::cout << "arcount: " << ntohs(hs.arcount) << std::endl;
}

void print_hex(void *request, int bytesRead) {

	int byte_count = 0;

	printf("→");

	for (int i = 0; i < bytesRead; i++) {
		std::printf("%02x ", static_cast<unsigned char>(((char *)request)[i]));

		byte_count++;
		if (byte_count % 16 == 0 && bytesRead > 16) {
			std::cout << std::endl;
		}
	}

	printf("←\n");
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

	header_struct h_n = {};
	header_struct h_h = {};
	while (true) {
		int responseSize = sizeof(header_struct);

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
		memcpy(&h_n, request, sizeof(header_struct));

		h_h = convert_struct_byte_order(h_n, ntohs);

		print_header_struct(h_h);
		h_h.setQuery(true);
		h_h.setRecursionDesired(false);
		h_h.setReserved(0);

#ifdef DEBUG
		h_h.qdcount = 44;
		h_h.ancount = 55;
		h_h.nscount = 66;
		h_h.arcount = 77;
#endif

		question_struct q = {};
		//
		// putting the hex code in the string without additional quotes results in this warning and results in the wrong value being stored:
		// warning: hex escape sequence out of range
		// Cf. https://www.unix.com/programming/149172-how-use-hex-escape-char-string-c.html
		strcpy(q.name, "\x0c"
					   "codecrafters"
					   "\x02"
					   "io");
		print_hex(q.name, strlen(q.name));
		q.type = htons((uint16_t)1);
		q._class = htons((uint16_t)1);

		print_hex(&q.type, 2);
		print_hex(&q._class, 2);

		bool add_question_section = true;
		if (add_question_section) {
			h_h.qdcount = 1;
			print_header_struct(h_h);

			memcpy(response + sizeof(header_struct), q.name, strlen(q.name) + 1);
			memcpy(response + sizeof(header_struct) + strlen(q.name) + 1, &q.type, sizeof(q.type));
			memcpy(response + sizeof(header_struct) + strlen(q.name) + 1 + 2, &q._class, sizeof(q._class));
			// add 1 for the null terminator to fix this error
			// ;; Warning: Message parser reports malformed message packet.
			// ;; Got answer:
			// ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 48552
			// ;; flags: qr; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0
			// ;; WARNING: Message has 3 extra bytes at end
			int questionLength = strlen(q.name) + 1 + sizeof(q.type) + sizeof(q._class);
			responseSize += questionLength;
			print_hex(response + sizeof(header_struct), questionLength);
		}

		h_n = convert_struct_byte_order(h_h, htons);
		memcpy(response, &h_n, sizeof(header_struct));
		print_message(response, responseSize);

		// Send response
		if (sendto(udpSocket, &response, responseSize, 0, reinterpret_cast<struct sockaddr *>(&clientAddress), sizeof(clientAddress)) == -1) {
			perror("Failed to send response");
		}

		std::printf("↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑\n");
	}

	close(udpSocket);

	return 0;
}
