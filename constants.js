
var TLS = {
  'Versions': {
    '1.1': [ 0x03, 0x02 ],
    '1.2': [ 0x03, 0x03 ]
  },
  'ContentTypes': {
    'change_cipher_spec': 20,
    'alert': 21,
    'handshake': 22,
    'application_data': 23,
    'default': 255
  }
};

var Handshake = {
  Types: {
    hello_request: 0,
    client_hello: 1,
    server_hello: 2,
    certificate: 11,
    server_key_exchange: 12,
    certificate_request: 13,
    server_hello_done: 14,
    certificate_verify: 15,
    client_key_exchange: 16,
    finished: 20
  }
};

exports.TLS = TLS;
exports.Handshake = Handshake;