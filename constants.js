
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
  },
  types: { /* compatible */ },
  cipher_suites: {},
  keyExchange: {
    algorithms: [
      'dhe_dss',
      'dhe_rsa',
      'dh_anon',
      'rsa',
      'dh_dss',
      'dh_rsa'
    ]
  }
};

var handshake = Handshake;
handshake.types[0] = 'hello_request';
handshake.types[1] = 'client_hello';
handshake.types[2] = 'server_hello';
handshake.types[11] = 'certificate';
handshake.types[12] = 'server_key_exchange';
handshake.types[13] = 'certificate_request';
handshake.types[14] = 'server_hello_done';
handshake.types[15] = 'certificate_verify';
handshake.types[16] = 'client_key_exchange';
handshake.types[20] = 'finished';

handshake.cipher_suites[0x0000] = 'TLS_NULL_WITH_NULL_NULL';
handshake.cipher_suites[0x0001] = 'TLS_RSA_WITH_NULL_MD5';
handshake.cipher_suites[0x0002] = 'TLS_RSA_WITH_NULL_SHA';
handshake.cipher_suites[0x003b] = 'TLS_RSA_WITH_NULL_SHA256';
handshake.cipher_suites[0x0004] = 'TLS_RSA_WITH_RC4_128_MD5';
handshake.cipher_suites[0x0005] = 'TLS_RSA_WITH_RC4_128_SHA';
handshake.cipher_suites[0x000a] = 'TLS_RSA_WITH_3DES_EDE_CBC_SHA';
handshake.cipher_suites[0x002f] = 'TLS_RSA_WITH_AES_128_CBC_SHA';
handshake.cipher_suites[0x0035] = 'TLS_RSA_WITH_AES_256_CBC_SHA';
handshake.cipher_suites[0x003c] = 'TLS_RSA_WITH_AES_128_CBC_SHA256';
handshake.cipher_suites[0x003d] = 'TLS_RSA_WITH_AES_256_CBC_SHA256';

handshake.cipher_suites[0x000d] = 'TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA';
handshake.cipher_suites[0x0010] = 'TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA';
handshake.cipher_suites[0x0013] = 'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA';
handshake.cipher_suites[0x0016] = 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA';
handshake.cipher_suites[0x0030] = 'TLS_DH_DSS_WITH_AES_128_CBC_SHA';
handshake.cipher_suites[0x0031] = 'TLS_DH_RSA_WITH_AES_128_CBC_SHA';
handshake.cipher_suites[0x0032] = 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA';
handshake.cipher_suites[0x0033] = 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA';
handshake.cipher_suites[0x0036] = 'TLS_DH_DSS_WITH_AES_256_CBC_SHA';
handshake.cipher_suites[0x0037] = 'TLS_DH_RSA_WITH_AES_256_CBC_SHA';
handshake.cipher_suites[0x0038] = 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA';
handshake.cipher_suites[0x0039] = 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA';
handshake.cipher_suites[0x003e] = 'TLS_DH_DSS_WITH_AES_128_CBC_SHA256';
handshake.cipher_suites[0x003f] = 'TLS_DH_RSA_WITH_AES_128_CBC_SHA256';
handshake.cipher_suites[0x0040] = 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256';
handshake.cipher_suites[0x0067] = 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256';
handshake.cipher_suites[0x0068] = 'TLS_DH_DSS_WITH_AES_256_CBC_SHA256';
handshake.cipher_suites[0x0069] = 'TLS_DH_RSA_WITH_AES_256_CBC_SHA256';
handshake.cipher_suites[0x006a] = 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256';
handshake.cipher_suites[0x006b] = 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256';

handshake.cipher_suites[0x0018] = 'TLS_DH_anon_WITH_RC4_128_MD5';
handshake.cipher_suites[0x001b] = 'TLS_DH_anon_WITH_3DES_EDE_CBC_SHA';
handshake.cipher_suites[0x0034] = 'TLS_DH_anon_WITH_AES_128_CBC_SHA';
handshake.cipher_suites[0x003a] = 'TLS_DH_anon_WITH_AES_256_CBC_SHA';
handshake.cipher_suites[0x006c] = 'TLS_DH_anon_WITH_AES_128_CBC_SHA256';
handshake.cipher_suites[0x006d] = 'TLS_DH_anon_WITH_AES_256_CBC_SHA256';

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
exports.handshake = handshake;
exports.alert = alert;
