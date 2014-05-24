
var TLS = {
  'Versions': {
    '1.0': [ 0x03, 0x01 ],
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

TLS.ContentTypes[20] = 'change_cipher_spec';
TLS.ContentTypes[21] = 'alert';
TLS.ContentTypes[22] = 'handshake';
TLS.ContentTypes[23] = 'application_data';
TLS.ContentTypes[255] = 'default';

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

var alert = {
  level: [],
  description: []
}

// constants for parsing

alert.level[1] = 'warning';
alert.level[2] = 'fatal';

alert.description[0] = 'close_notify';
alert.description[10] = 'unexpected_message';
alert.description[20] = 'bad_record_mac';
alert.description[21] = 'decryption_failed_RESERVED';
alert.description[22] = 'record_overflow';
alert.description[30] = 'decompression_failure';
alert.description[40] = 'handshake_failure';
alert.description[41] = 'no_certificate_RESERVED';
alert.description[42] = 'bad_certificate';
alert.description[43] = 'unsupported_certificate';
alert.description[44] = 'certificate_revoked';
alert.description[45] = 'certificate_expired';
alert.description[46] = 'certificate_unknown';
alert.description[47] = 'illegal_parameter';
alert.description[48] = 'unknown_ca';
alert.description[49] = 'access_denied';
alert.description[50] = 'decode_error';
alert.description[51] = 'decrypt_error';
alert.description[60] = 'export_restriction_RESERVED';
alert.description[70] = 'protocol_version';
alert.description[71] = 'insufficient_security';
alert.description[80] = 'internal_error';
alert.description[90] = 'user_canceled';
alert.description[100] = 'no_renegotiation';
alert.description[110] = 'unsupported_extension';

exports.TLS = TLS;
exports.Handshake = Handshake;
exports.alert = alert;
