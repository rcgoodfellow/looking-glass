header icmp_h {
    bit<8> type;
    bit<8> code;
    bit<16> checksum;
}

struct echo_request_t {
    icmp_h icmp;
    bit<16> identifier;
    bit<16> sequence_number;
}
