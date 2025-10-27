const PTK_HASHDATA = PTK_HASHDATA__;
const EAPOL_HASHDATA = EAPOL_HASHDATA__;
const AUTH_MIC = AUTH_MIC__;
const ESSID_HASHDATA = ESSID_HASHDATA__;
const EXPECTED_PMKID = EXPECTED_PMKID__;
const PMK_NAME_BUF = PMK_NAME_BUF__;

fn sha1_round(w: ptr<function, array<u32, 16>>, IV: array<u32, 5>) -> array<u32, 5> {
  var a = IV[0];
  var b = IV[1];
  var c = IV[2];
  var d = IV[3];
  var e = IV[4];
  var t = 0u;
  e = ((a << 5) | (a >> 27)) + ((b & c) | ((~b) & d)) + e + 1518500249 + w[0]; b = (b << 30) | (b >> 2);
  d = ((e << 5) | (e >> 27)) + ((a & b) | ((~a) & c)) + d + 1518500249 + w[1]; a = (a << 30) | (a >> 2);
  c = ((d << 5) | (d >> 27)) + ((e & a) | ((~e) & b)) + c + 1518500249 + w[2]; e = (e << 30) | (e >> 2);
  b = ((c << 5) | (c >> 27)) + ((d & e) | ((~d) & a)) + b + 1518500249 + w[3]; d = (d << 30) | (d >> 2);
  a = ((b << 5) | (b >> 27)) + ((c & d) | ((~c) & e)) + a + 1518500249 + w[4]; c = (c << 30) | (c >> 2);
  e = ((a << 5) | (a >> 27)) + ((b & c) | ((~b) & d)) + e + 1518500249 + w[5]; b = (b << 30) | (b >> 2);
  d = ((e << 5) | (e >> 27)) + ((a & b) | ((~a) & c)) + d + 1518500249 + w[6]; a = (a << 30) | (a >> 2);
  c = ((d << 5) | (d >> 27)) + ((e & a) | ((~e) & b)) + c + 1518500249 + w[7]; e = (e << 30) | (e >> 2);
  b = ((c << 5) | (c >> 27)) + ((d & e) | ((~d) & a)) + b + 1518500249 + w[8]; d = (d << 30) | (d >> 2);
  a = ((b << 5) | (b >> 27)) + ((c & d) | ((~c) & e)) + a + 1518500249 + w[9]; c = (c << 30) | (c >> 2);
  e = ((a << 5) | (a >> 27)) + ((b & c) | ((~b) & d)) + e + 1518500249 + w[10]; b = (b << 30) | (b >> 2);
  d = ((e << 5) | (e >> 27)) + ((a & b) | ((~a) & c)) + d + 1518500249 + w[11]; a = (a << 30) | (a >> 2);
  c = ((d << 5) | (d >> 27)) + ((e & a) | ((~e) & b)) + c + 1518500249 + w[12]; e = (e << 30) | (e >> 2);
  b = ((c << 5) | (c >> 27)) + ((d & e) | ((~d) & a)) + b + 1518500249 + w[13]; d = (d << 30) | (d >> 2);
  a = ((b << 5) | (b >> 27)) + ((c & d) | ((~c) & e)) + a + 1518500249 + w[14]; c = (c << 30) | (c >> 2);
  e = ((a << 5) | (a >> 27)) + ((b & c) | ((~b) & d)) + e + 1518500249 + w[15]; b = (b << 30) | (b >> 2);
  t = w[13] ^ w[8] ^ w[2] ^ w[0]; w[0] = (t << 1) | (t >> 31); d = ((e << 5) | (e >> 27)) + ((a & b) | ((~a) & c)) + d + 1518500249 + w[0]; a = (a << 30) | (a >> 2);
  t = w[14] ^ w[9] ^ w[3] ^ w[1]; w[1] = (t << 1) | (t >> 31); c = ((d << 5) | (d >> 27)) + ((e & a) | ((~e) & b)) + c + 1518500249 + w[1]; e = (e << 30) | (e >> 2);
  t = w[15] ^ w[10] ^ w[4] ^ w[2]; w[2] = (t << 1) | (t >> 31); b = ((c << 5) | (c >> 27)) + ((d & e) | ((~d) & a)) + b + 1518500249 + w[2]; d = (d << 30) | (d >> 2);
  t = w[0] ^ w[11] ^ w[5] ^ w[3]; w[3] = (t << 1) | (t >> 31); a = ((b << 5) | (b >> 27)) + ((c & d) | ((~c) & e)) + a + 1518500249 + w[3]; c = (c << 30) | (c >> 2);
  t = w[1] ^ w[12] ^ w[6] ^ w[4]; w[4] = (t << 1) | (t >> 31); e = ((a << 5) | (a >> 27)) + (b ^ c ^ d) + e + 1859775393 + w[4]; b = (b << 30) | (b >> 2);
  t = w[2] ^ w[13] ^ w[7] ^ w[5]; w[5] = (t << 1) | (t >> 31); d = ((e << 5) | (e >> 27)) + (a ^ b ^ c) + d + 1859775393 + w[5]; a = (a << 30) | (a >> 2);
  t = w[3] ^ w[14] ^ w[8] ^ w[6]; w[6] = (t << 1) | (t >> 31); c = ((d << 5) | (d >> 27)) + (e ^ a ^ b) + c + 1859775393 + w[6]; e = (e << 30) | (e >> 2);
  t = w[4] ^ w[15] ^ w[9] ^ w[7]; w[7] = (t << 1) | (t >> 31); b = ((c << 5) | (c >> 27)) + (d ^ e ^ a) + b + 1859775393 + w[7]; d = (d << 30) | (d >> 2);
  t = w[5] ^ w[0] ^ w[10] ^ w[8]; w[8] = (t << 1) | (t >> 31); a = ((b << 5) | (b >> 27)) + (c ^ d ^ e) + a + 1859775393 + w[8]; c = (c << 30) | (c >> 2);
  t = w[6] ^ w[1] ^ w[11] ^ w[9]; w[9] = (t << 1) | (t >> 31); e = ((a << 5) | (a >> 27)) + (b ^ c ^ d) + e + 1859775393 + w[9]; b = (b << 30) | (b >> 2);
  t = w[7] ^ w[2] ^ w[12] ^ w[10]; w[10] = (t << 1) | (t >> 31); d = ((e << 5) | (e >> 27)) + (a ^ b ^ c) + d + 1859775393 + w[10]; a = (a << 30) | (a >> 2);
  t = w[8] ^ w[3] ^ w[13] ^ w[11]; w[11] = (t << 1) | (t >> 31); c = ((d << 5) | (d >> 27)) + (e ^ a ^ b) + c + 1859775393 + w[11]; e = (e << 30) | (e >> 2);
  t = w[9] ^ w[4] ^ w[14] ^ w[12]; w[12] = (t << 1) | (t >> 31); b = ((c << 5) | (c >> 27)) + (d ^ e ^ a) + b + 1859775393 + w[12]; d = (d << 30) | (d >> 2);
  t = w[10] ^ w[5] ^ w[15] ^ w[13]; w[13] = (t << 1) | (t >> 31); a = ((b << 5) | (b >> 27)) + (c ^ d ^ e) + a + 1859775393 + w[13]; c = (c << 30) | (c >> 2);
  t = w[11] ^ w[6] ^ w[0] ^ w[14]; w[14] = (t << 1) | (t >> 31); e = ((a << 5) | (a >> 27)) + (b ^ c ^ d) + e + 1859775393 + w[14]; b = (b << 30) | (b >> 2);
  t = w[12] ^ w[7] ^ w[1] ^ w[15]; w[15] = (t << 1) | (t >> 31); d = ((e << 5) | (e >> 27)) + (a ^ b ^ c) + d + 1859775393 + w[15]; a = (a << 30) | (a >> 2);
  t = w[13] ^ w[8] ^ w[2] ^ w[0]; w[0] = (t << 1) | (t >> 31); c = ((d << 5) | (d >> 27)) + (e ^ a ^ b) + c + 1859775393 + w[0]; e = (e << 30) | (e >> 2);
  t = w[14] ^ w[9] ^ w[3] ^ w[1]; w[1] = (t << 1) | (t >> 31); b = ((c << 5) | (c >> 27)) + (d ^ e ^ a) + b + 1859775393 + w[1]; d = (d << 30) | (d >> 2);
  t = w[15] ^ w[10] ^ w[4] ^ w[2]; w[2] = (t << 1) | (t >> 31); a = ((b << 5) | (b >> 27)) + (c ^ d ^ e) + a + 1859775393 + w[2]; c = (c << 30) | (c >> 2);
  t = w[0] ^ w[11] ^ w[5] ^ w[3]; w[3] = (t << 1) | (t >> 31); e = ((a << 5) | (a >> 27)) + (b ^ c ^ d) + e + 1859775393 + w[3]; b = (b << 30) | (b >> 2);
  t = w[1] ^ w[12] ^ w[6] ^ w[4]; w[4] = (t << 1) | (t >> 31); d = ((e << 5) | (e >> 27)) + (a ^ b ^ c) + d + 1859775393 + w[4]; a = (a << 30) | (a >> 2);
  t = w[2] ^ w[13] ^ w[7] ^ w[5]; w[5] = (t << 1) | (t >> 31); c = ((d << 5) | (d >> 27)) + (e ^ a ^ b) + c + 1859775393 + w[5]; e = (e << 30) | (e >> 2);
  t = w[3] ^ w[14] ^ w[8] ^ w[6]; w[6] = (t << 1) | (t >> 31); b = ((c << 5) | (c >> 27)) + (d ^ e ^ a) + b + 1859775393 + w[6]; d = (d << 30) | (d >> 2);
  t = w[4] ^ w[15] ^ w[9] ^ w[7]; w[7] = (t << 1) | (t >> 31); a = ((b << 5) | (b >> 27)) + (c ^ d ^ e) + a + 1859775393 + w[7]; c = (c << 30) | (c >> 2);
  t = w[5] ^ w[0] ^ w[10] ^ w[8]; w[8] = (t << 1) | (t >> 31); e = ((a << 5) | (a >> 27)) + ((b & c) | (b & d) | (c & d)) + e + 2400959708 + w[8]; b = (b << 30) | (b >> 2);
  t = w[6] ^ w[1] ^ w[11] ^ w[9]; w[9] = (t << 1) | (t >> 31); d = ((e << 5) | (e >> 27)) + ((a & b) | (a & c) | (b & c)) + d + 2400959708 + w[9]; a = (a << 30) | (a >> 2);
  t = w[7] ^ w[2] ^ w[12] ^ w[10]; w[10] = (t << 1) | (t >> 31); c = ((d << 5) | (d >> 27)) + ((e & a) | (e & b) | (a & b)) + c + 2400959708 + w[10]; e = (e << 30) | (e >> 2);
  t = w[8] ^ w[3] ^ w[13] ^ w[11]; w[11] = (t << 1) | (t >> 31); b = ((c << 5) | (c >> 27)) + ((d & e) | (d & a) | (e & a)) + b + 2400959708 + w[11]; d = (d << 30) | (d >> 2);
  t = w[9] ^ w[4] ^ w[14] ^ w[12]; w[12] = (t << 1) | (t >> 31); a = ((b << 5) | (b >> 27)) + ((c & d) | (c & e) | (d & e)) + a + 2400959708 + w[12]; c = (c << 30) | (c >> 2);
  t = w[10] ^ w[5] ^ w[15] ^ w[13]; w[13] = (t << 1) | (t >> 31); e = ((a << 5) | (a >> 27)) + ((b & c) | (b & d) | (c & d)) + e + 2400959708 + w[13]; b = (b << 30) | (b >> 2);
  t = w[11] ^ w[6] ^ w[0] ^ w[14]; w[14] = (t << 1) | (t >> 31); d = ((e << 5) | (e >> 27)) + ((a & b) | (a & c) | (b & c)) + d + 2400959708 + w[14]; a = (a << 30) | (a >> 2);
  t = w[12] ^ w[7] ^ w[1] ^ w[15]; w[15] = (t << 1) | (t >> 31); c = ((d << 5) | (d >> 27)) + ((e & a) | (e & b) | (a & b)) + c + 2400959708 + w[15]; e = (e << 30) | (e >> 2);
  t = w[13] ^ w[8] ^ w[2] ^ w[0]; w[0] = (t << 1) | (t >> 31); b = ((c << 5) | (c >> 27)) + ((d & e) | (d & a) | (e & a)) + b + 2400959708 + w[0]; d = (d << 30) | (d >> 2);
  t = w[14] ^ w[9] ^ w[3] ^ w[1]; w[1] = (t << 1) | (t >> 31); a = ((b << 5) | (b >> 27)) + ((c & d) | (c & e) | (d & e)) + a + 2400959708 + w[1]; c = (c << 30) | (c >> 2);
  t = w[15] ^ w[10] ^ w[4] ^ w[2]; w[2] = (t << 1) | (t >> 31); e = ((a << 5) | (a >> 27)) + ((b & c) | (b & d) | (c & d)) + e + 2400959708 + w[2]; b = (b << 30) | (b >> 2);
  t = w[0] ^ w[11] ^ w[5] ^ w[3]; w[3] = (t << 1) | (t >> 31); d = ((e << 5) | (e >> 27)) + ((a & b) | (a & c) | (b & c)) + d + 2400959708 + w[3]; a = (a << 30) | (a >> 2);
  t = w[1] ^ w[12] ^ w[6] ^ w[4]; w[4] = (t << 1) | (t >> 31); c = ((d << 5) | (d >> 27)) + ((e & a) | (e & b) | (a & b)) + c + 2400959708 + w[4]; e = (e << 30) | (e >> 2);
  t = w[2] ^ w[13] ^ w[7] ^ w[5]; w[5] = (t << 1) | (t >> 31); b = ((c << 5) | (c >> 27)) + ((d & e) | (d & a) | (e & a)) + b + 2400959708 + w[5]; d = (d << 30) | (d >> 2);
  t = w[3] ^ w[14] ^ w[8] ^ w[6]; w[6] = (t << 1) | (t >> 31); a = ((b << 5) | (b >> 27)) + ((c & d) | (c & e) | (d & e)) + a + 2400959708 + w[6]; c = (c << 30) | (c >> 2);
  t = w[4] ^ w[15] ^ w[9] ^ w[7]; w[7] = (t << 1) | (t >> 31); e = ((a << 5) | (a >> 27)) + ((b & c) | (b & d) | (c & d)) + e + 2400959708 + w[7]; b = (b << 30) | (b >> 2);
  t = w[5] ^ w[0] ^ w[10] ^ w[8]; w[8] = (t << 1) | (t >> 31); d = ((e << 5) | (e >> 27)) + ((a & b) | (a & c) | (b & c)) + d + 2400959708 + w[8]; a = (a << 30) | (a >> 2);
  t = w[6] ^ w[1] ^ w[11] ^ w[9]; w[9] = (t << 1) | (t >> 31); c = ((d << 5) | (d >> 27)) + ((e & a) | (e & b) | (a & b)) + c + 2400959708 + w[9]; e = (e << 30) | (e >> 2);
  t = w[7] ^ w[2] ^ w[12] ^ w[10]; w[10] = (t << 1) | (t >> 31); b = ((c << 5) | (c >> 27)) + ((d & e) | (d & a) | (e & a)) + b + 2400959708 + w[10]; d = (d << 30) | (d >> 2);
  t = w[8] ^ w[3] ^ w[13] ^ w[11]; w[11] = (t << 1) | (t >> 31); a = ((b << 5) | (b >> 27)) + ((c & d) | (c & e) | (d & e)) + a + 2400959708 + w[11]; c = (c << 30) | (c >> 2);
  t = w[9] ^ w[4] ^ w[14] ^ w[12]; w[12] = (t << 1) | (t >> 31); e = ((a << 5) | (a >> 27)) + (b ^ c ^ d) + e + 3395469782 + w[12]; b = (b << 30) | (b >> 2);
  t = w[10] ^ w[5] ^ w[15] ^ w[13]; w[13] = (t << 1) | (t >> 31); d = ((e << 5) | (e >> 27)) + (a ^ b ^ c) + d + 3395469782 + w[13]; a = (a << 30) | (a >> 2);
  t = w[11] ^ w[6] ^ w[0] ^ w[14]; w[14] = (t << 1) | (t >> 31); c = ((d << 5) | (d >> 27)) + (e ^ a ^ b) + c + 3395469782 + w[14]; e = (e << 30) | (e >> 2);
  t = w[12] ^ w[7] ^ w[1] ^ w[15]; w[15] = (t << 1) | (t >> 31); b = ((c << 5) | (c >> 27)) + (d ^ e ^ a) + b + 3395469782 + w[15]; d = (d << 30) | (d >> 2);
  t = w[13] ^ w[8] ^ w[2] ^ w[0]; w[0] = (t << 1) | (t >> 31); a = ((b << 5) | (b >> 27)) + (c ^ d ^ e) + a + 3395469782 + w[0]; c = (c << 30) | (c >> 2);
  t = w[14] ^ w[9] ^ w[3] ^ w[1]; w[1] = (t << 1) | (t >> 31); e = ((a << 5) | (a >> 27)) + (b ^ c ^ d) + e + 3395469782 + w[1]; b = (b << 30) | (b >> 2);
  t = w[15] ^ w[10] ^ w[4] ^ w[2]; w[2] = (t << 1) | (t >> 31); d = ((e << 5) | (e >> 27)) + (a ^ b ^ c) + d + 3395469782 + w[2]; a = (a << 30) | (a >> 2);
  t = w[0] ^ w[11] ^ w[5] ^ w[3]; w[3] = (t << 1) | (t >> 31); c = ((d << 5) | (d >> 27)) + (e ^ a ^ b) + c + 3395469782 + w[3]; e = (e << 30) | (e >> 2);
  t = w[1] ^ w[12] ^ w[6] ^ w[4]; w[4] = (t << 1) | (t >> 31); b = ((c << 5) | (c >> 27)) + (d ^ e ^ a) + b + 3395469782 + w[4]; d = (d << 30) | (d >> 2);
  t = w[2] ^ w[13] ^ w[7] ^ w[5]; w[5] = (t << 1) | (t >> 31); a = ((b << 5) | (b >> 27)) + (c ^ d ^ e) + a + 3395469782 + w[5]; c = (c << 30) | (c >> 2);
  t = w[3] ^ w[14] ^ w[8] ^ w[6]; w[6] = (t << 1) | (t >> 31); e = ((a << 5) | (a >> 27)) + (b ^ c ^ d) + e + 3395469782 + w[6]; b = (b << 30) | (b >> 2);
  t = w[4] ^ w[15] ^ w[9] ^ w[7]; w[7] = (t << 1) | (t >> 31); d = ((e << 5) | (e >> 27)) + (a ^ b ^ c) + d + 3395469782 + w[7]; a = (a << 30) | (a >> 2);
  t = w[5] ^ w[0] ^ w[10] ^ w[8]; w[8] = (t << 1) | (t >> 31); c = ((d << 5) | (d >> 27)) + (e ^ a ^ b) + c + 3395469782 + w[8]; e = (e << 30) | (e >> 2);
  t = w[6] ^ w[1] ^ w[11] ^ w[9]; w[9] = (t << 1) | (t >> 31); b = ((c << 5) | (c >> 27)) + (d ^ e ^ a) + b + 3395469782 + w[9]; d = (d << 30) | (d >> 2);
  t = w[7] ^ w[2] ^ w[12] ^ w[10]; w[10] = (t << 1) | (t >> 31); a = ((b << 5) | (b >> 27)) + (c ^ d ^ e) + a + 3395469782 + w[10]; c = (c << 30) | (c >> 2);
  t = w[8] ^ w[3] ^ w[13] ^ w[11]; w[11] = (t << 1) | (t >> 31); e = ((a << 5) | (a >> 27)) + (b ^ c ^ d) + e + 3395469782 + w[11]; b = (b << 30) | (b >> 2);
  t = w[9] ^ w[4] ^ w[14] ^ w[12]; w[12] = (t << 1) | (t >> 31); d = ((e << 5) | (e >> 27)) + (a ^ b ^ c) + d + 3395469782 + w[12]; a = (a << 30) | (a >> 2);
  t = w[10] ^ w[5] ^ w[15] ^ w[13]; w[13] = (t << 1) | (t >> 31); c = ((d << 5) | (d >> 27)) + (e ^ a ^ b) + c + 3395469782 + w[13]; e = (e << 30) | (e >> 2);
  t = w[11] ^ w[6] ^ w[0] ^ w[14]; w[14] = (t << 1) | (t >> 31); b = ((c << 5) | (c >> 27)) + (d ^ e ^ a) + b + 3395469782 + w[14]; d = (d << 30) | (d >> 2);
  t = w[12] ^ w[7] ^ w[1] ^ w[15]; w[15] = (t << 1) | (t >> 31); a = ((b << 5) | (b >> 27)) + (c ^ d ^ e) + a + 3395469782 + w[15]; c = (c << 30) | (c >> 2);
  return array<u32, 5>(IV[0] + a, IV[1] + b, IV[2] + c, IV[3] + d, IV[4] + e);
}

fn hmac_seed(password: ptr<function, array<u32, 16>>, XOR: u32) -> array<u32, 5> {
  var data: array<u32, 16>;
  for (var i = 0; i < 16; i++) { data[i] = password[i] ^ XOR; }
  return sha1_round(&data, array<u32, 5>(0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u));
}

fn set_main_buf(main_buf: ptr<function, array<u32, 16>>, r1: ptr<function, array<u32, 5>>) {
  for (var i = 0; i < 5; i++) { main_buf[i] = r1[i]; }
  for (var i = 5; i < 16; i++) { main_buf[i] = 0; }
  main_buf[5] = 0x80000000;
  main_buf[15] = 84 * 8;
}

fn pbkdf2_block(seed1: array<u32, 5>, seed2: array<u32, 5>, main_buf_init: array<u32, 16>) -> array<u32, 5> {
  var dk: array<u32, 5>;
  var main_buf = main_buf_init;
  var r1 = sha1_round(&main_buf, seed1);
  set_main_buf(&main_buf, &r1);
  r1 = sha1_round(&main_buf, seed2);
  for (var i = 0; i < 5; i++) { dk[i] = r1[i]; }
  
  for (var j = 1; j < 4096; j++) {
    set_main_buf(&main_buf, &r1);
    r1 = sha1_round(&main_buf, seed1);
    set_main_buf(&main_buf, &r1);
    r1 = sha1_round(&main_buf, seed2);
    for (var i = 0; i < 5; i++) { dk[i] = dk[i] ^ r1[i]; }
  }
  return dk;
}

fn calcPtk(dk1: array<u32, 5>, dk2: array<u32, 5>) -> array<u32, 5> {
  var tmp_array: array<u32, 16>;
  for (var i = 0; i < 16; i++) { tmp_array[i] = 0; }
  for (var i = 0; i < 5; i++) { tmp_array[i] = dk1[i]; }
  for (var i = 0; i < 3; i++) { tmp_array[i + 5] = dk2[i]; }
  var state = hmac_seed(&tmp_array, 0x36363636);
  var seed2 = hmac_seed(&tmp_array, 0x5c5c5c5c);
  for (var i = 0; i < PTK_HASHDATA_LEN; i++) {
    tmp_array = PTK_HASHDATA[i];
    state = sha1_round(&tmp_array, state);
  }
  set_main_buf(&tmp_array, &state);
  return sha1_round(&tmp_array, seed2);
}

fn calcMic(ptk: array<u32, 5>) -> array<u32, 5> {
  var tmp_array: array<u32, 16>;
  for (var i = 0; i < 16; i++) { tmp_array[i] = 0; }
  for (var i = 0; i < 4; i++) { tmp_array[i] = ptk[i]; }
  var state = hmac_seed(&tmp_array, 0x36363636);
  var seed2 = hmac_seed(&tmp_array, 0x5c5c5c5c);
  for (var i = 0; i < EAPOL_HASHDATA_LEN; i++) {
    tmp_array = EAPOL_HASHDATA[i];
    state = sha1_round(&tmp_array, state);
  }
  set_main_buf(&tmp_array, &state);
  return sha1_round(&tmp_array, seed2);
}

fn calcPmkid(dk1: array<u32, 5>, dk2: array<u32, 5>) -> array<u32, 5> {
  var tmp_array: array<u32, 16>;
  for (var i = 0; i < 16; i++) { tmp_array[i] = 0; }
  for (var i = 0; i < 5; i++) { tmp_array[i] = dk1[i]; }
  for (var i = 0; i < 3; i++) { tmp_array[i + 5] = dk2[i]; }
  var state = hmac_seed(&tmp_array, 0x36363636);
  var seed2 = hmac_seed(&tmp_array, 0x5c5c5c5c);
  tmp_array = PMK_NAME_BUF;
  state = sha1_round(&tmp_array, state);
  set_main_buf(&tmp_array, &state);
  return sha1_round(&tmp_array, seed2);
}

const masks = array<u32, 4>(0x00ffffff, 0xff00ffff, 0xffff00ff, 0xffffff00);
fn setByteArr(buf: ptr<function, array<u32, 16>>, idx: u32, byte: u32) {
  let i = idx/4;
  let sh = idx%4;
  buf[i] = (buf[i] & masks[sh]) + (byte << (24 - sh * 8));
}
fn initPasswordBuffer(passOffset: u32) -> array<u32, 16> {
  var password: array<u32, 16>;
  for (var i = 0; i < 16; i++) { password[i] = 0; }
  for (var i = 0u; i < 64; i++) {
    var offset = passOffset + i;
    var b = (input[offset / 4] >> ((offset % 4) * 8)) & 0xff;
    if (b == 0x0Au) { break; }
    setByteArr(&password, i, b);
  }
  return password;
}


@group(0) @binding(0) var<storage, read> input: array<u32>;
@group(0) @binding(1) var<storage, read_write> output: array<u32>;

@compute @workgroup_size(WORKGROUP_SIZE)
fn eapol(@builtin(global_invocation_id) gid: vec3<u32>) {
  if (gid.x == 0) { output[0] = 0xffffffff; }
  var password = initPasswordBuffer(input[gid.x]);
  var seed1 = hmac_seed(&password, 0x36363636);
  var seed2 = hmac_seed(&password, 0x5c5c5c5c);
  var dk1 = pbkdf2_block(seed1, seed2, ESSID_HASHDATA[0]);
  var dk2 = pbkdf2_block(seed1, seed2, ESSID_HASHDATA[1]);
  var ptk = calcPtk(dk1, dk2);
  var mic = calcMic(ptk);
  var found = true;
  for (var i = 0; i < 4; i++) { if (AUTH_MIC[i] != mic[i]) { found = false; } }
  if (found) {
    output[0] = gid.x;
  }
}

@compute @workgroup_size(WORKGROUP_SIZE)
fn pmkid(@builtin(global_invocation_id) gid: vec3<u32>) {
  if (gid.x == 0) { output[0] = 0xffffffff; }
  var password = initPasswordBuffer(input[gid.x]);
  var seed1 = hmac_seed(&password, 0x36363636);
  var seed2 = hmac_seed(&password, 0x5c5c5c5c);
  var dk1 = pbkdf2_block(seed1, seed2, ESSID_HASHDATA[0]);
  var dk2 = pbkdf2_block(seed1, seed2, ESSID_HASHDATA[1]);
  var pmkid = calcPmkid(dk1, dk2);
  var found = true;
  for (var i = 0; i < 4; i++) { if (EXPECTED_PMKID[i] != pmkid[i]) { found = false; } }
  if (found) {
    output[0] = gid.x;
  }
}

