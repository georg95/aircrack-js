const std = @import("std");
const mem = std.mem;

const Vec = @Vector(4, u32);

inline fn sha1_block_20(state: [5]Vec, in: [5]Vec) [5]Vec {
    var a = state[0];
    var b = state[1];
    var c = state[2];
    var d = state[3];
    var e = state[4];

    var w: [16]Vec = undefined;
    w[0] = in[0];
    w[1] = in[1];
    w[2] = in[2];
    w[3] = in[3];
    w[4] = in[4];
    w[5] = @splat(0x80000000);
    w[6] = @splat(0);
    w[7] = @splat(0);
    w[8] = @splat(0);
    w[9] = @splat(0);
    w[10] = @splat(0);
    w[11] = @splat(0);
    w[12] = @splat(0);
    w[13] = @splat(0);
    w[14] = @splat(0);
    w[15] = @splat(672);

    const K0: Vec = @splat(0x5A827999);
    const K1: Vec = @splat(0x6ED9EBA1);
    const K2: Vec = @splat(0x8F1BBCDC);
    const K3: Vec = @splat(0xCA62C1D6);

    const ROT1 = 1;
    const ROT5 = 5;
    const ROT30 = 30;

    inline for (0..80) |r| {
        if (r >= 16) {
            w[r % 16] = std.math.rotl(Vec, w[(r - 3) % 16] ^ w[(r - 8) % 16] ^ w[(r - 14) % 16] ^ w[(r - 16) % 16], ROT1);
        }

        const k = comptime switch (r) {
            0...19 => K0,
            20...39 => K1,
            40...59 => K2,
            60...79 => K3,
            else => unreachable,
        };

        const f = switch (r) {
            0...19 => d ^ (b & (c ^ d)),
            20...39 => b ^ c ^ d,
            40...59 => (b & c) | (d & (b | c)),
            60...79 => b ^ c ^ d,
            else => unreachable,
        };

        const temp = std.math.rotl(Vec, a, ROT5) +% f +% e +% k +% w[r % 16];
        e = d;
        d = c;
        c = std.math.rotl(Vec, b, ROT30);
        b = a;
        a = temp;
    }

    return [5]Vec{
        state[0] +% a,
        state[1] +% b,
        state[2] +% c,
        state[3] +% d,
        state[4] +% e,
    };
}

pub fn pbkdf2_loop(seed1: [5]Vec, seed2: [5]Vec, init_r: [5]Vec) [16]u32 {
    var dk = init_r;
    var msg = init_r;
    for (1..4096) |_| {
        msg = sha1_block_20(seed1, msg);
        msg = sha1_block_20(seed2, msg);
        dk[0] ^= msg[0];
        dk[1] ^= msg[1];
        dk[2] ^= msg[2];
        dk[3] ^= msg[3];
        dk[4] ^= msg[4];
    }
    return [16]u32{ dk[0][0], dk[1][0], dk[2][0], dk[3][0], dk[4][0], dk[0][1], dk[1][1], dk[2][1], dk[0][2], dk[1][2], dk[2][2], dk[3][2], dk[4][2], dk[0][3], dk[1][3], dk[2][3] };
}

pub fn sha1(input: *const [16]u32, IV: [5]u32) [5]u32 {
    var a: u32 = IV[0];
    var b: u32 = IV[1];
    var c: u32 = IV[2];
    var d: u32 = IV[3];
    var e: u32 = IV[4];

    var w: [16]u32 = undefined;
    @memcpy(w[0..], input);

    const K0: u32 = 0x5A827999;
    const K1: u32 = 0x6ED9EBA1;
    const K2: u32 = 0x8F1BBCDC;
    const K3: u32 = 0xCA62C1D6;

    inline for (0..80) |r| {
        if (r >= 16) {
            w[r % 16] = std.math.rotl(u32, w[(r - 3) % 16] ^ w[(r - 8) % 16] ^ w[(r - 14) % 16] ^ w[(r - 16) % 16], 1);
        }

        const k = comptime switch (r) {
            0...19 => K0,
            20...39 => K1,
            40...59 => K2,
            60...79 => K3,
            else => unreachable,
        };

        const f = switch (r) {
            0...19 => d ^ (b & (c ^ d)),
            20...39 => b ^ c ^ d,
            40...59 => (b & c) | (d & (b | c)),
            60...79 => b ^ c ^ d,
            else => unreachable,
        };

        const temp = std.math.rotl(u32, a, 5) +% f +% e +% k +% w[r % 16];
        e = d;
        d = c;
        c = std.math.rotl(u32, b, 30);
        b = a;
        a = temp;
    }

    return [_]u32{
        IV[0] +% a,
        IV[1] +% b,
        IV[2] +% c,
        IV[3] +% d,
        IV[4] +% e,
    };
}

var IV_ = [_]u32{ 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };

pub fn get_seed(paswd: []const u8, xor: u8) [5]u32 {
    var main_buf: [16]u32 = [_]u32{0} ** 16;
    for (0..64) |i| {
        var pbyte = if (i < paswd.len) paswd[i] else 0;
        if (pbyte == 0x0D) {
            pbyte = 0;
        }
        main_buf[@divFloor(i, 4)] += @as(u32, pbyte ^ xor) << @truncate((3 - (i % 4)) * 8);
    }
    return sha1(main_buf[0..], IV_);
}
pub fn get_init_data(SSID_BUF: *[16]u32, seed1: [5]u32, seed2: [5]u32) [5]u32 {
    const r1: [5]u32 = sha1(SSID_BUF, seed1);
    var main_buf: [16]u32 = [_]u32{0} ** 16;
    for (0..5) |i| main_buf[i] = r1[i];
    main_buf[5] = 0x80000000;
    main_buf[15] = 84 * 8;
    return sha1(main_buf[0..], seed2);
}

pub fn pbkdf2(paswd1: []const u8, paswd2: []const u8) [16]u32 {
    const seed1: [5]u32 = get_seed(paswd1, 0x36);
    const seed2: [5]u32 = get_seed(paswd1, 0x5c);
    const seed3: [5]u32 = get_seed(paswd2, 0x36);
    const seed4: [5]u32 = get_seed(paswd2, 0x5c);

    const r1 = get_init_data(SSID_BUF1[0..], seed1, seed2);
    const r2 = get_init_data(SSID_BUF2[0..], seed1, seed2);
    const r3 = get_init_data(SSID_BUF1[0..], seed3, seed4);
    const r4 = get_init_data(SSID_BUF2[0..], seed3, seed4);

    var s1: [5]Vec = undefined;
    var s2: [5]Vec = undefined;
    var r: [5]Vec = undefined;
    for (0..5) |i| {
        s1[i] = Vec{ seed1[i], seed1[i], seed3[i], seed3[i] };
        s2[i] = Vec{ seed2[i], seed2[i], seed4[i], seed4[i] };
        r[i] = Vec{ r1[i], r2[i], r3[i], r4[i] };
    }
    return pbkdf2_loop(s1, s2, r);
}

fn hmac_seed(password: *[16]u32, XOR: u32) [5]u32 {
    var tmp_buf = [_]u32{0} ** 16;
    for (0..16) |i| tmp_buf[i] = password[i] ^ XOR;
    return sha1(&tmp_buf, IV_);
}

fn calcPtk(pmk: *[8]u32) [5]u32 {
    var tmp_buf = [_]u32{0} ** 16;
    for (0..8) |i| tmp_buf[i] = pmk[i];
    var state = hmac_seed(&tmp_buf, 0x36363636);
    const seed2 = hmac_seed(&tmp_buf, 0x5c5c5c5c);
    state = sha1(PTK_HASHDATA[0..16], state);
    state = sha1(PTK_HASHDATA[16..32], state);
    for (0..5) |i| tmp_buf[i] = state[i];
    for (5..16) |i| tmp_buf[i] = 0;
    tmp_buf[5] = 0x80000000;
    tmp_buf[15] = 84 * 8;
    return sha1(&tmp_buf, seed2);
}

fn calcMic(ptk: [5]u32) [5]u32 {
    var tmp_buf = [_]u32{0} ** 16;
    for (0..4) |i| tmp_buf[i] = ptk[i];
    var state = hmac_seed(&tmp_buf, 0x36363636);
    const seed2 = hmac_seed(&tmp_buf, 0x5c5c5c5c);
    for (0..EAPOL_HASHDATA_LEN) |i| {
        state = sha1(EAPOL_HASHDATA[i * 16 ..][0..16], state);
    }
    for (0..5) |i| tmp_buf[i] = state[i];
    for (5..16) |i| tmp_buf[i] = 0;
    tmp_buf[5] = 0x80000000;
    tmp_buf[15] = 84 * 8;
    return sha1(&tmp_buf, seed2);
}

fn calcPmkid(pmk: *[8]u32) [5]u32 {
    var tmp_buf = [_]u32{0} ** 16;
    for (0..8) |i| tmp_buf[i] = pmk[i];
    var state = hmac_seed(&tmp_buf, 0x36363636);
    const seed2 = hmac_seed(&tmp_buf, 0x5c5c5c5c);
    state = sha1(PMK_NAME_BUF[0..16], state);
    for (0..5) |i| tmp_buf[i] = state[i];
    for (5..16) |i| tmp_buf[i] = 0;
    tmp_buf[5] = 0x80000000;
    tmp_buf[15] = 84 * 8;
    return sha1(&tmp_buf, seed2);
}

test "sha1" {
    var pass: [16]u32 = [_]u32{0} ** 16;
    const res: [5]u32 = sha1(&pass, IV_);
    const resExp = [5]u32{ 2461271269, 1448643821, 1813695822, 3204792168, 167197331 };
    try std.testing.expectEqualSlices(u32, resExp[0..], res[0..]);
}

test "pbkdf2" {
    const passwd1 = "11234223";
    const passwd2_withr = "11234226\r";
    const passwd2 = "11234226";
    const ssid = "Netgear";
    setSsidBuf(ssid);
    const pmk = pbkdf2(passwd1, passwd2_withr);
    var dk_bytes: [64]u8 = undefined;
    for (0..16) |i| mem.writeInt(u32, dk_bytes[i * 4 ..][0..4], pmk[i], .big);
    try std.testing.expectEqualSlices(u8, mnemoToSeed(passwd1, ssid)[0..32], dk_bytes[0..32]);
    try std.testing.expectEqualSlices(u8, mnemoToSeed(passwd2, ssid)[0..32], dk_bytes[32..64]);
}
pub fn setSsidBuf(ssid: []const u8) void {
    SSID_BUF1 = [_]u32{0} ** 16;
    var block_bytes: *[64]u8 = @ptrCast(&SSID_BUF1);
    @memcpy(block_bytes[0..ssid.len], ssid);
    block_bytes[ssid.len + 3] = 1;
    block_bytes[ssid.len + 4] = 0x80;
    for (0..16) |i| SSID_BUF1[i] = @byteSwap(SSID_BUF1[i]);
    SSID_BUF1[15] = @truncate((68 + ssid.len) * 8);

    SSID_BUF2 = [_]u32{0} ** 16;
    var block_bytes2: *[64]u8 = @ptrCast(&SSID_BUF2);
    @memcpy(block_bytes2[0..ssid.len], ssid);
    block_bytes2[ssid.len + 3] = 2;
    block_bytes2[ssid.len + 4] = 0x80;
    for (0..16) |i| SSID_BUF2[i] = @byteSwap(SSID_BUF2[i]);
    SSID_BUF2[15] = @truncate((68 + ssid.len) * 8);
}
fn mnemoToSeed(paswd: []const u8, seed: []const u8) [32]u8 {
    var res: [32]u8 = undefined;
    std.crypto.pwhash.pbkdf2(&res, paswd, seed, 4096, std.crypto.auth.hmac.HmacSha1) catch unreachable;
    return res;
}

test "pbkdf-hmac-sha1+eapol" {
    SSID_BUF1 = [_]u32{ 1214345835, 1869505902, 1, 2147483648, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 608 };
    SSID_BUF2 = [_]u32{ 1214345835, 1869505902, 2, 2147483648, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 608 };
    PTK_HASHDATA = [_]u32{ 1348561266, 2003399525, 543909241, 543520880, 1634628457, 1869479936, 323419698, 201331820, 2118156322, 1481945156, 1306767110, 3511233413, 696578124, 4129770510, 840480872, 391546445, 3080738137, 378258341, 3742947102, 4217644019, 1074302379, 2652611259, 3313916384, 2067227824, 3733286912, 2147483648, 0, 0, 0, 0, 0, 1312 };
    EAPOL_HASHDATA = [_]u32{ 16973941, 33622528, 268435456, 0, 22615691, 3282427672, 3609131876, 603144200, 2376834587, 2730214790, 1507883831, 1689312901, 1879048192, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5680, 335609856, 262931457, 4012, 67174400, 262930945, 8388608, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1480, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    EAPOL_HASHDATA_LEN = 3;
    EXPECTED_MIC = [_]u32{ 2474584346, 3896858003, 387660936, 1324511926, 488096956 };

    const pass1 = "test";
    const pass2 = "";
    @memcpy(password1[0..pass1.len], pass1);
    @memcpy(password2[0..pass2.len], pass2);
    try std.testing.expectEqual(1, pbkdf1_eapol(pass1.len, pass2.len));
}
test "pbkdf-hmac-sha1+pmkid" {
    SSID_BUF1 = [_]u32{ 1297042737, 1, 2147483648, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 576 };
    SSID_BUF2 = [_]u32{ 1297042737, 2, 2147483648, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 576 };
    PMK_NAME_BUF = [_]u32{ 1347242784, 1315007845, 2173298, 2736324641, 11228585, 2147483648, 0, 0, 0, 0, 0, 0, 0, 0, 0, 672 };
    EXPECTED_PMKID = [_]u32{ 402982421, 3563370659, 2368904345, 4192947124 };

    const pass1 = "";
    const pass2 = "MOM12345";
    @memcpy(password1[0..pass1.len], pass1);
    @memcpy(password2[0..pass2.len], pass2);
    try std.testing.expectEqual(1, pbkdf2_pmkid(pass1.len, pass2.len));
}

export var password1: [64]u8 = undefined;
export var password2: [64]u8 = undefined;
export var SSID_BUF1: [16]u32 = undefined;
export var SSID_BUF2: [16]u32 = undefined;
export var PTK_HASHDATA: [32]u32 = undefined;
export var EAPOL_HASHDATA: [64]u32 = undefined;
export var EAPOL_HASHDATA_LEN: u32 = 0;
export var EXPECTED_MIC: [5]u32 = undefined;
export var EXPECTED_PMKID: [4]u32 = undefined;
export var PMK_NAME_BUF: [16]u32 = undefined;

export fn pbkdf1_eapol(passLen1: u32, passLen2: u32) u32 {
    var pmk = pbkdf2(password1[0..passLen1], password2[0..passLen2]);
    for (0..2) |i| {
        const ptk = calcPtk(pmk[i * 8 ..][0..8]);
        const mic = calcMic(ptk);
        if (std.mem.eql(u32, EXPECTED_MIC[0..4], mic[0..4])) {
            return @intCast(i);
        }
    }
    return 0xffffffff;
}
export fn pbkdf2_pmkid(passLen1: u32, passLen2: u32) u32 {
    var pmk = pbkdf2(password1[0..passLen1], password2[0..passLen2]);
    for (0..2) |i| {
        const pmkid = calcPmkid(pmk[i * 8 ..][0..8]);
        if (std.mem.eql(u32, EXPECTED_PMKID[0..4], pmkid[0..4])) {
            return @intCast(i);
        }
    }
    return 0xffffffff;
}
