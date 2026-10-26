#
# Tests for the Apple Continuity and CoreCapture dissectors
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Apple Continuity and CoreCapture tests.

Every frame here is synthetic and built by this file at run time: the
addresses, the handshake's ephemeral key and the shared secret are made-up
values, so no capture of a real device is needed and none is committed.

The protected bodies were sealed once with an independent ChaCha20-Poly1305
implementation (Python's `cryptography`) under keys derived from
SHARED_SECRET, with the nonce a per-direction count of protected frames and
the frame's four-byte header as associated data, and are embedded as bytes.
The derivation is recomputed below with the standard library, so a key log
naming the direction keys and one naming only the shared secret are checked
against the same frames. What each body holds is stated beside it; the tests
assert what the dissector reads out of them, which is therefore checked
against an encoder that is not this dissector.
'''

import hashlib
import hmac
import math
import struct
import subprocess

import pytest

# The handshake's cleartext ephemeral public key names the session.
EPHEMERAL_KEY = bytes(range(0xa0, 0xc0))
SHARED_SECRET = bytes(range(0x40, 0x60))
SESSION = EPHEMERAL_KEY.hex()

# REQUESTS[i]: {"_i": "_systemInfo", "_t": 2, "_x": i + 1, "_c": {}}, sealed
# under the client key at counter i. RESPONSES[i]: {"_t": 3, "_x": i + 1,
# "_c": {}}, sealed under the server key at counter i.
REQUESTS = [
    bytes.fromhex('0800002ce77eeacc1ad43b674d18114691dcbff5dd2a0133139fe4ab0468e943687b6ac78982aee1eef24a818c9e31d7'),
    bytes.fromhex('0800002c135eeba3dce1b3cc55766e278226de0159e3ffeee471706f9af27a2a30250f95b654f6379168d03cc390e906'),
    bytes.fromhex('0800002c366134040c8284148d423c00145c40d2deffc7418ef6b9f0d28fbbe399f0e7cf8779ef74149026dc40758d41'),
    bytes.fromhex('0800002c4b32a31852c1ccd087a0d9c86b79f8900af49a3d79717cc4ff1c1f35f789ac8dab210d101fd9445c6025e38e'),
]
RESPONSES = [
    bytes.fromhex('0800001dff9d56ce7df74bc987c0c22939341007a4e9a7f732fc1c810179f8efe0'),
    bytes.fromhex('0800001d5607fa54b1c0918131e0259fbe3e1dd1ec3a33db193ab264b30ae6520b'),
    bytes.fromhex('0800001d1f9498ae2f894ea249bed41535f391c0a73e3f3978e38c1f8205129a73'),
    bytes.fromhex('0800001d9de83745f26da391a25e63ed007c162a44d9be0423096f75eb8e90d347'),
]
# {"_i": ["x"], "_t": 2, "_x": 9, "_c": {}}, client key, counter 0.
EVENT_IN_ARRAY = bytes.fromhex('08000023e77eeacc80ca305c61187e6987cac8d8c016952de1a49f016e4ace029c3e1b096a3cea')
# {"_i": "_ping", "_t": "2", "_x": "9"}, client key, counter 0.
WRONG_TYPES = bytes.fromhex('08000024e07eeacc14d43877500b3674acf3ebd8c00d3400af1c32185b12bc9730138f54010f2a5b')
# {"_i": "_streamStart", "_t": 2, "_x": 5, "_c": {"_streamID":
# "ABCD1234:ContinuityCaptureMediaMicrophone", "_streamType": 3,
# "_streamPort": 40000}}, server key, counter 0.
STREAM_REQUEST = bytes.fromhex('0800007ef89d56d33aea67c5fce7fc278a74d950143572e45861413c1e0c94d647896adcea5579334f7003c1b0c9928097db31b2014f8577f1adcec86fa3ac74310728854ab599e834213c6bf8998845bffb79d465f06a78c12b80f6151359c06cc04f3a3ff3e850ab6f6e36a50fe6b3c50982b762c125e714ee9af2ceabfd49f575')
# {"_t": 3, "_x": 5, "_c": {"_streamPort": 40002}}, client key, counter 0.
STREAM_RESPONSE = bytes.fromhex('0800002ce07eead15ac91766332e2b4839f986e9eb0710583c90f3d03206c83f102b0cc0574d49a75c416413201d7e1b')
# {"_i": "_ping", "_t": 2, "_x": 1, "_c": {}}, server key, counter 0.
PEER_SAME_KIND = bytes.fromhex('08000026f89d56d333ea64d8e0e5df15ad0afa7d187e6fcf31c3942cb1024ec15c65e95c5d687fa219b6')
# {"_i": "_systemInfo", "_t": 2, "_x": 1, "_c": {}}, client key, counter 1.
REQUEST_XID1_C1 = bytes.fromhex('0800002c135eeba3dce1b3cc55766e278226de0159e3ffeee471706c9af27a2a6b6669a5d5046e46010e96324ee6e6bc')
# {"_t": 3, "_x": 1, "_c": {}}, server key, counter 1.
RESPONSE_XID1_S1 = bytes.fromhex('0800001d5607fa54b1c0918132e0259fbe46737d943262a47bcf1c1a1b59189b04')

LINKTYPE_ETHERNET = 1
LINKTYPE_IEEE802_11 = 105
LINKTYPE_USER3 = 150
LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR = 201

INITIATOR = (bytes.fromhex('020000000001'), bytes.fromhex('fe800000000000000000000000000001'))
RESPONDER = (bytes.fromhex('020000000002'), bytes.fromhex('fe800000000000000000000000000002'))

# The DLT the CoreCapture dissector is reached through, as Wireshark's own
# User DLTs table spells it.
CORECAPTURE_USER_DLT = '"User 3 (DLT=150)","corecapture","0","","0",""\n'


def hkdf_sha512(secret, label):
    '''One expand block of HKDF-SHA-512 with an empty salt.'''
    prk = hmac.new(b'\x00' * 64, secret, hashlib.sha512).digest()
    return hmac.new(prk, label + b'\x01', hashlib.sha512).digest()[:32]


def write_pcap(path, linktype, frames):
    '''Frames are bytes, or (captured bytes, original length).'''
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for number, frame in enumerate(frames):
            data, length = frame if isinstance(frame, tuple) else (frame, len(frame))
            f.write(struct.pack('<IIII', 1700000000, number * 1000, len(data), length))
            f.write(data)


def write_pcapng(path, linktype, frames):
    '''As write_pcap, in pcapng: the one container that keeps a captured
    length larger than the original one, which CoreCapture records have.'''
    def block(kind, body):
        body += b'\x00' * ((-len(body)) % 4)
        return struct.pack('<II', kind, 12 + len(body)) + body + struct.pack('<I', 12 + len(body))
    with open(path, 'wb') as f:
        f.write(block(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1)))
        f.write(block(1, struct.pack('<HHI', linktype, 0, 0)))
        for number, (data, length) in enumerate(frames):
            f.write(block(6, struct.pack('<IIIII', 0, 0, number, len(data), length) + data))


def checksum(data):
    if len(data) % 2:
        data += b'\x00'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return ~total & 0xffff


def over_ipv6(src, dst, next_header, l4, checksum_at):
    pseudo = src + dst + struct.pack('!IxxxB', len(l4), next_header)
    l4 = l4[:checksum_at] + struct.pack('!H', checksum(pseudo + l4)) + l4[checksum_at + 2:]
    return struct.pack('!IHBB', 6 << 28, len(l4), next_header, 64) + src + dst + l4


def tcp_over_ipv6(src, dst, sport, dport, seq, ack, payload):
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, 0x18, 0xffff, 0, 0)
    return over_ipv6(src, dst, 6, tcp + payload, 16)


def udp_over_ipv6(src, dst, sport, dport, payload):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0)
    return over_ipv6(src, dst, 17, udp + payload, 6)


def over_ethernet(src_mac, dst_mac, ipv6):
    '''As an interface capture on awdl0 or llw0 records it.'''
    return dst_mac + src_mac + b'\x86\xdd' + ipv6


def over_awdl(src_mac, dst_mac, ipv6, seq):
    '''As a monitor-mode capture records it: an AWDL data frame, which the
    AWDL dissector hands to the ethertype table.'''
    dot11 = b'\x08\x00\x00\x00' + dst_mac + src_mac + bytes.fromhex('002500ff9473') + b'\x00\x00'
    llc = bytes.fromhex('aaaa030017f20800')
    awdl = b'\x03\x04' + seq.to_bytes(2, 'little') + b'\x00\x00' + b'\x86\xdd'
    return dot11 + llc + awdl + ipv6


class Connection:
    '''One TCP connection between INITIATOR and RESPONDER, tracking sequence
    numbers so that frames can be built in any order.'''

    def __init__(self, sport=51000, dport=52000):
        self.ports = (sport, dport)
        self.seq = {True: 1000, False: 5000}

    def frame(self, from_initiator, payload, seq=None):
        src, dst = (INITIATOR, RESPONDER) if from_initiator else (RESPONDER, INITIATOR)
        sport, dport = self.ports if from_initiator else self.ports[::-1]
        at = self.seq[from_initiator] if seq is None else seq
        if seq is None:
            self.seq[from_initiator] += len(payload)
        ipv6 = tcp_over_ipv6(src[1], dst[1], sport, dport, at, self.seq[not from_initiator],
                             payload)
        return over_ethernet(src[0], dst[0], ipv6)


# --- OPACK, as the platform encodes it, for the cleartext cases -------------

def o_str(text):
    raw = text.encode()
    return (bytes([0x40 + len(raw)]) if len(raw) <= 32 else bytes([0x61, len(raw)])) + raw


def o_int(value):
    return bytes([0x08 + value])


def o_dict(*pairs):
    return bytes([0xe0 + len(pairs)]) + b''.join(k + v for k, v in pairs)


def o_date(seconds):
    return b'\x06' + struct.pack('<d', seconds)


def pairverify_m1(state=1, keys=1, pd_marker=0x91, extra_entry=False, overrun=False,
                  first_key='_pd'):
    '''The handshake's first message: {"_pd": <TLV8 State, PublicKey, Flags>}.'''
    tlv8 = b'\x06\x01' + bytes([state])
    for _ in range(keys):
        tlv8 += (b'\x03\x30' if overrun else b'\x03\x20') + EPHEMERAL_KEY
    tlv8 += b'' if overrun else b'\x19\x01\x01'
    if pd_marker == 0x91:
        pd = b'\x91' + bytes([len(tlv8)]) + tlv8
    else:
        pd = b'\x92' + len(tlv8).to_bytes(2, 'little') + tlv8
    body = bytes([0xe2 if extra_entry else 0xe1]) + o_str(first_key) + pd
    if extra_entry:
        body += o_str('x') + o_int(1)
    return b'\x05' + len(body).to_bytes(3, 'big') + body


def continue_frame(body):
    '''A cleartext handshake-continuation frame, whose body the object
    decode walks without anything else being derived from it.'''
    return b'\x06' + len(body).to_bytes(3, 'big') + body


def keylog(result_file, lines, name='continuity.keylog'):
    path = result_file(name)
    with open(path, 'w') as f:
        f.write(''.join(line + '\n' for line in lines))
    return path


def shared_keylog(result_file):
    return keylog(result_file, ['RDLINK_SHARED %s %s' % (SESSION, SHARED_SECRET.hex())])


def fields(cmd_tshark, capture, env, names, prefs=(), two_pass=True):
    command = [cmd_tshark, '-r', capture, '-T', 'fields', '-E', 'occurrence=a',
               '-E', 'aggregator=|']
    if two_pass:
        command.insert(1, '-2')
    for pref in prefs:
        command += ['-o', pref]
    for name in names:
        command += ['-e', name]
    stdout = subprocess.check_output(command, encoding='utf-8', env=env)
    return [line.split('\t') for line in stdout.splitlines()]


def keyed(result_file):
    return ('continuity.keylog_file:' + shared_keylog(result_file),)


def capture_of(result_file, name, frames, linktype=LINKTYPE_ETHERNET):
    path = result_file(name)
    write_pcap(path, linktype, frames)
    return path


# --- Registration ----------------------------------------------------------

class TestContinuityRegistration:
    def test_dissectors_are_built_in(self, cmd_tshark, test_env):
        protocols = subprocess.check_output((cmd_tshark, '-G', 'protocols'),
                                            encoding='utf-8', env=test_env)
        filters = {line.split('\t')[2] for line in protocols.splitlines() if line.count('\t') >= 2}
        for name in ('continuity', 'continuity.ble', 'continuity.rdlink', 'continuity.companion',
                     'continuity.opack', 'continuity.media', 'continuity.sidecar',
                     'corecapture', 'cc.awdl', 'corecapture.ethernet'):
            assert name in filters

    def test_preferences_are_registered(self, cmd_tshark, test_env):
        prefs = subprocess.check_output((cmd_tshark, '-G', 'defaultprefs'),
                                        encoding='utf-8', env=test_env)
        assert '#continuity.keylog_file: ' in prefs
        assert '#continuity.media_guess_pt100: FALSE' in prefs

    def test_editcap_can_inject_continuity_keys(self, cmd_editcap, test_env):
        listing = subprocess.run((cmd_editcap, '--inject-secrets', 'help'),
                                 capture_output=True, encoding='utf-8', env=test_env)
        assert 'continuity' in listing.stdout + listing.stderr


# --- CoreCapture -----------------------------------------------------------

def cc_record(stream_type, payload, length=None, padding=None):
    '''A CoreCapture record as macOS writes it: an 8-byte header, then the
    payload; the original length is the payload's, without the header, and
    the captured bytes are padded to a multiple of 4.'''
    data = struct.pack('<II', stream_type, 0) + payload
    pad = (-len(data)) % 4 if padding is None else padding
    return data + b'\x00' * pad, len(payload) if length is None else length


def cc_awdl_text(text):
    '''An AWDLPeerManager record (type 5) whose payload is text.'''
    header = b'\x00' * 140 + b'\x02' + b'\x00' + b'\x00' * 42  # payload type 2: string
    assert len(header) == 184
    return header + text


@pytest.fixture
def cc_env(test_env, conf_path):
    with open(conf_path + '/user_dlts', 'w') as f:
        f.write(CORECAPTURE_USER_DLT)
    return test_env


class TestCoreCapture:
    # Column 3 is whether dissection raised an exception: the "Malformed" group
    # alone is also set by a diagnostic such as an unterminated text.
    names = ('corecapture.awdl.text', '_ws.col.info', '_ws.expert.message', '_ws.malformed',
             'corecapture.padding')

    @staticmethod
    def raised(row):
        return 'Malformed Packet (Exception occurred)' in row[2]

    def dissect(self, cmd_tshark, result_file, cc_env, records):
        path = result_file('cc.pcapng')
        write_pcapng(path, LINKTYPE_USER3, records)
        return fields(cmd_tshark, path, cc_env, self.names)

    @pytest.mark.parametrize('text,shown', [
        (b'\n\x00', ''), (b'hello\n\x00', 'hello'), (b'hello\x00', 'hello')])
    def test_terminated_text(self, cmd_tshark, result_file, cc_env, text, shown):
        (row,) = self.dissect(cmd_tshark, result_file, cc_env, [cc_record(5, cc_awdl_text(text))])
        assert not self.raised(row)
        assert row[1] == shown
        assert 'Text has no terminating NUL' not in row[2]

    def test_empty_text(self, cmd_tshark, result_file, cc_env):
        (row,) = self.dissect(cmd_tshark, result_file, cc_env, [cc_record(5, cc_awdl_text(b''))])
        assert not self.raised(row)
        assert row[1] == ''

    def test_text_without_terminator(self, cmd_tshark, result_file, cc_env):
        (row,) = self.dissect(cmd_tshark, result_file, cc_env,
                              [cc_record(5, cc_awdl_text(b'abcd'), padding=0)])
        assert not self.raised(row)
        assert row[1] == 'abcd'
        assert 'Text has no terminating NUL' in row[2]

    def test_text_cut_by_the_capture(self, cmd_tshark, result_file, cc_env):
        payload = cc_awdl_text(b'abcdefgh\x00')
        data, _ = cc_record(5, payload)
        (row,) = self.dissect(cmd_tshark, result_file, cc_env,
                              [(data[:8 + 184 + 4], len(payload))])
        assert not self.raised(row)
        assert row[1] == 'abcd'
        assert 'Text continues past the captured bytes' in row[2]

    def test_short_header(self, cmd_tshark, result_file, cc_env):
        (row,) = self.dissect(cmd_tshark, result_file, cc_env, [(b'\x05\x00\x00\x00', 4)])
        assert row[0] == ''

    def test_payload_length_and_padding(self, cmd_tshark, result_file, cc_env):
        payload = cc_awdl_text(b'ab\x00')  # 8 + 187 = 195 bytes: one byte of padding
        (row,) = self.dissect(cmd_tshark, result_file, cc_env, [cc_record(5, payload)])
        assert row[4] == '00'
        assert 'More bytes follow the payload' not in row[2]

    def test_excess_padding(self, cmd_tshark, result_file, cc_env):
        (row,) = self.dissect(cmd_tshark, result_file, cc_env,
                              [cc_record(5, cc_awdl_text(b'ab\x00'), padding=9)])
        assert 'More bytes follow the payload' in row[2]

    def test_unknown_stream_type(self, cmd_tshark, result_file, cc_env):
        (row,) = self.dissect(cmd_tshark, result_file, cc_env, [cc_record(99, b'\x01\x02\x03\x04')])
        assert 'No dissector for this CoreCapture stream type' in row[2]

    def test_ethernet_record_reaches_the_decoders_above(self, cmd_tshark, result_file, cc_env):
        frame = Connection().frame(True, pairverify_m1())
        path = result_file('cc-eth.pcapng')
        write_pcapng(path, LINKTYPE_USER3, [cc_record(4, b'\x00' * 56 + frame)])
        (row,) = fields(cmd_tshark, path, cc_env, ('frame.protocols', 'continuity.session'))
        assert row[0].endswith(':eth:ethertype:ipv6:tcp:continuity.rdlink')
        assert row[1] == SESSION


# --- Bluetooth advertisements ----------------------------------------------

def advertisement(apple_messages, received=True):
    apple = b'\x4c\x00' + apple_messages
    data = b'\x02\x01\x06' + bytes([len(apple) + 1, 0xff]) + apple
    if received:
        report = (b'\x02\x01\x00\x01' + bytes.fromhex('0100000000c0')
                  + bytes([len(data)]) + data + b'\xc4')
        return struct.pack('!I', 1) + b'\x04\x3e' + bytes([len(report)]) + report
    # The vendor command a Mac hands its own advertising data to its
    # controller in: instance, data length, data.
    params = b'\x00' + bytes([len(data)]) + data
    return struct.pack('!I', 0) + b'\x01\x4b\xfd' + bytes([len(params)]) + params


NEARBY_INFO = b'\x10\x05\x01\x18\x11\x22\x33'
HANDOFF = b'\x0c\x0e' + bytes(range(1, 15))


class TestContinuityAdvertisement:
    names = ('continuity.ble.type', 'continuity.ble.direction', 'continuity.ble.unknown_type',
             '_ws.expert.message')

    def dissect(self, cmd_tshark, result_file, test_env, frame):
        path = capture_of(result_file, 'ble.pcap', [frame], LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR)
        return fields(cmd_tshark, path, test_env, self.names)

    def test_received_messages_are_decoded(self, cmd_tshark, result_file, test_env):
        (row,) = self.dissect(cmd_tshark, result_file, test_env,
                              advertisement(NEARBY_INFO + HANDOFF))
        assert row[0].split('|') == ['0x10', '0x0c']
        assert row[1] == 'received'

    def test_sent_messages_are_decoded(self, cmd_tshark, result_file, test_env):
        (row,) = self.dissect(cmd_tshark, result_file, test_env,
                              advertisement(NEARBY_INFO, received=False))
        assert row[0] == '0x10'
        assert row[1] == 'sent'

    def test_unknown_type_is_kept(self, cmd_tshark, result_file, test_env):
        (row,) = self.dissect(cmd_tshark, result_file, test_env,
                              advertisement(b'\x7e\x02\xaa\xbb'))
        assert row[2] == '0x7e'

    def test_truncated_message(self, cmd_tshark, result_file, test_env):
        (row,) = self.dissect(cmd_tshark, result_file, test_env,
                              advertisement(b'\x0c\x0e\x01\x02\x03'))
        assert 'Declares 14 byte(s) but only 3 are present' in row[3]

    def test_the_umbrella_selects_it(self, cmd_tshark, result_file, test_env):
        path = capture_of(result_file, 'ble.pcap', [advertisement(NEARBY_INFO)],
                          LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR)
        stdout = subprocess.check_output((cmd_tshark, '-r', path, '-Y', 'continuity'),
                                         encoding='utf-8', env=test_env)
        assert len(stdout.splitlines()) == 1


# --- OPACK -----------------------------------------------------------------

class TestOpack:
    '''Cleartext bodies, carried as handshake continuations after an M1.'''

    def walk(self, cmd_tshark, result_file, test_env, body):
        conn = Connection()
        path = capture_of(result_file, 'opack.pcap',
                          [conn.frame(True, pairverify_m1()),
                           conn.frame(False, continue_frame(body))])
        rows = fields(cmd_tshark, path, test_env,
                      ('continuity.opack.member', '_ws.expert.message', 'continuity.opack.bytes'))
        members, experts, byte_fields = rows[1]
        return members.split('|') if members else [], experts, byte_fields

    def test_scalars_and_containers(self, cmd_tshark, result_file, test_env):
        body = o_dict((o_str('a'), o_int(0)), (o_str('b'), b'\xd2' + o_int(1) + o_int(2)),
                      (o_str('c'), b'\xef' + o_str('d') + b'\x01' + b'\x03'))
        members, experts, _ = self.walk(cmd_tshark, result_file, test_env, body)
        assert members == ['a = 0', 'b[0] = 1', 'b[1] = 2', 'c.d = true']
        assert experts == ''

    def test_integer_widths_and_signedness(self, cmd_tshark, result_file, test_env):
        body = o_dict((o_str('a'), b'\x30\xff'), (o_str('b'), b'\x31\xff\xff'),
                      (o_str('c'), b'\x32\xbc\x60\x69\xa5'), (o_str('d'), b'\x33' + b'\xff' * 8))
        members, _, _ = self.walk(cmd_tshark, result_file, test_env, body)
        assert members == ['a = 255', 'b = 65535', 'c = %d' % (0xa56960bc - (1 << 32)), 'd = -1']

    def test_back_reference(self, cmd_tshark, result_file, test_env):
        # Table: "a" (0), "xyz" (1), "b" (2); 0xa1 names "xyz".
        body = o_dict((o_str('a'), o_str('xyz')), (o_str('b'), b'\xa1'))
        members, experts, _ = self.walk(cmd_tshark, result_file, test_env, body)
        assert members == ['a = xyz', 'b = xyz']
        assert experts == ''

    @pytest.mark.parametrize('body,message', [
        (b'\xe2' + o_str('a') + o_int(0),
         'the dictionary declares 2 entries and the body ends after 1'),
        (o_dict((o_str('a'), b'\xd3' + o_int(0) + o_int(1))),
         'the array declares 3 entries and the body ends after 2'),
        (b'\xe1' + o_str('a'), 'has no value before the body ends'),
        (b'\xef' + o_str('a') + o_int(0), 'the dictionary has no terminator before the body ends'),
        (o_dict((o_str('a'), b'\xdf' + o_int(0))), 'the array has no terminator before the body ends'),
        (o_dict((o_str('a'), b'\xfe')), 'an unrecognised marker'),
        (o_dict((o_str('a'), b'\xa5')), 'unresolvable reference (index 5, table size 1)'),
    ])
    def test_malformed_structure_is_diagnosed(self, cmd_tshark, result_file, test_env, body,
                                              message):
        _, experts, _ = self.walk(cmd_tshark, result_file, test_env, body)
        assert message in experts

    def test_dates(self, cmd_tshark, result_file, test_env):
        body = o_dict((o_str('a'), o_date(700000000.5)), (o_str('b'), o_date(0.9999996)),
                      (o_str('c'), o_date(math.nan)), (o_str('d'), o_date(math.inf)),
                      (o_str('e'), o_date(1e300)))
        members, experts, _ = self.walk(cmd_tshark, result_file, test_env, body)
        assert members[0] == 'a = 2023-03-08T20:26:40.500000Z'
        assert members[1] == 'b = 2001-01-01T00:00:01.000000Z'
        assert all(m.split(' = ')[1].startswith('<unrepresentable date') for m in members[2:])
        assert experts.count('The date is not a representable time') == 3

    def test_long_byte_string_member_is_cut(self, cmd_tshark, result_file, test_env):
        body = o_dict((o_str('b'), b'\x91\x64' + bytes(range(100))))
        members, _, byte_fields = self.walk(cmd_tshark, result_file, test_env, body)
        assert members[0].endswith(':…') and members[0].count(':') == 64
        assert len(byte_fields.replace(':', '')) == 200

    def test_reference_expansion_is_bounded(self, cmd_tshark, result_file, test_env):
        # Table: "a" (0), the 2000 bytes (1), "b" (2); 1000 references to
        # index 1 would put 2 MB of value into the tree from 3 KB of body.
        body = o_dict((o_str('a'), b'\x92' + (2000).to_bytes(2, 'little') + b'\x5a' * 2000),
                      (o_str('b'), b'\xdf' + b'\xa1' * 1000 + b'\x03'))
        members, experts, byte_fields = self.walk(cmd_tshark, result_file, test_env, body)
        assert 'exceed 1048576 bytes' in experts
        values = byte_fields.split('|')
        assert len(values) == 1 + (1048576 - 2000) // 2000
        # One member per value, and one saying where the walk stopped.
        assert len(members) == len(values) + 1 and '<undecoded:' in members[-1]


# --- RDLink handshake, decryption and keys -----------------------------------

class TestContinuityRDLink:
    names = ('continuity.rdlink.type', 'continuity.session', 'continuity.rdlink.read',
             'continuity.rdlink.key_label', 'continuity.rdlink.unavailable',
             'continuity.companion.event', 'continuity.companion.xid',
             'continuity.companion.answered_in', 'continuity.companion.answers',
             'continuity.rdlink.counter', 'continuity.companion.unpaired', '_ws.expert.message')

    def exchange(self, result_file):
        conn = Connection()
        return capture_of(result_file, 'rdlink.pcap', [conn.frame(True, pairverify_m1()),
                                                       conn.frame(True, REQUESTS[0]),
                                                       conn.frame(False, RESPONSES[0])])

    def check_opened(self, rows):
        request, response = rows[1], rows[2]
        assert request[2:4] == ['True', 'client']
        assert response[2:4] == ['True', 'server']
        assert request[5] == '_systemInfo'
        assert request[6] == response[6] == '0x0000000000000001'
        assert request[7] == '3' and response[8] == '2'

    def test_the_handshake_names_the_session(self, cmd_tshark, result_file, test_env):
        rows = fields(cmd_tshark, self.exchange(result_file), test_env, self.names)
        assert [row[0] for row in rows] == ['0x05', '0x08', '0x08']
        assert [set(row[1].split('|')) for row in rows] == [{SESSION}] * 3

    @pytest.mark.parametrize('m1', [pairverify_m1(pd_marker=0x92),
                                    pairverify_m1(extra_entry=True)])
    def test_equivalent_handshake_encodings(self, cmd_tshark, result_file, test_env, m1):
        path = capture_of(result_file, 'm1.pcap', [Connection().frame(True, m1)])
        (row,) = fields(cmd_tshark, path, test_env, self.names)
        assert row[1] == SESSION

    @pytest.mark.parametrize('m1,message', [
        (pairverify_m1(state=2), 'the State element is not 1'),
        (pairverify_m1(keys=2), 'exactly one 32-byte public key'),
        (pairverify_m1(overrun=True), 'disagrees with its own lengths'),
    ])
    def test_malformed_handshake_names_no_session(self, cmd_tshark, result_file, test_env, m1,
                                                  message):
        path = capture_of(result_file, 'm1.pcap', [Connection().frame(True, m1)])
        (row,) = fields(cmd_tshark, path, test_env, self.names)
        assert row[1] == ''
        assert message in row[11]

    def test_a_body_without_pd_names_no_session(self, cmd_tshark, result_file, test_env):
        path = capture_of(result_file, 'm1.pcap',
                          [Connection().frame(True, pairverify_m1(first_key='_pe'))])
        (row,) = fields(cmd_tshark, path, test_env, self.names)
        assert row[1] == ''
        assert 'the body has no _pd byte string at its top level' in row[11]

    @pytest.mark.parametrize('payload', [
        b'GET / HTTP/1.1\r\nHost: x\r\n\r\n',
        b'\x05\x00\x00\x30' + b'\x00' * 8,   # a known type whose length does not fit
        b'\x05\x00\x00\x06\xe1\x43_pd',    # the handshake prefix, its body cut short
    ])
    def test_unrelated_tcp_is_not_claimed(self, cmd_tshark, result_file, test_env, payload):
        path = capture_of(result_file, 'tcp.pcap', [Connection().frame(True, payload)])
        (row,) = fields(cmd_tshark, path, test_env, ('frame.protocols',))
        assert 'continuity' not in row[0]

    def test_protected_bodies_without_keys(self, cmd_tshark, result_file, test_env):
        rows = fields(cmd_tshark, self.exchange(result_file), test_env, self.names)
        for row in rows[1:]:
            assert row[2] == 'False'
            assert row[4] == 'no key material was supplied'
            assert row[5] == ''

    def test_a_shared_secret_opens_both_directions(self, cmd_tshark, result_file, test_env):
        self.check_opened(fields(cmd_tshark, self.exchange(result_file), test_env, self.names,
                                 keyed(result_file)))

    def test_direction_keys_open_both_directions(self, cmd_tshark, result_file, test_env):
        path = keylog(result_file, [
            'RDLINK_CLIENT_ENC %s %s' % (SESSION, hkdf_sha512(SHARED_SECRET, b'ClientEncrypt-main').hex()),
            'RDLINK_SERVER_ENC %s %s' % (SESSION, hkdf_sha512(SHARED_SECRET, b'ServerEncrypt-main').hex()),
        ])
        self.check_opened(fields(cmd_tshark, self.exchange(result_file), test_env, self.names,
                                 ('continuity.keylog_file:' + path,)))

    def test_one_direction_key_opens_one_direction(self, cmd_tshark, result_file, test_env):
        path = keylog(result_file, ['RDLINK_CLIENT_ENC %s %s' % (
            SESSION, hkdf_sha512(SHARED_SECRET, b'ClientEncrypt-main').hex())])
        rows = fields(cmd_tshark, self.exchange(result_file), test_env, self.names,
                      ('continuity.keylog_file:' + path,))
        assert rows[1][2] == 'True' and rows[2][2] == 'False'

    def test_an_unbound_secret_is_found_by_trial(self, cmd_tshark, result_file, test_env):
        path = keylog(result_file, ['RDLINK_SHARED %s %s' % ('00' * 32, SHARED_SECRET.hex())])
        rows = fields(cmd_tshark, self.exchange(result_file), test_env,
                      ('continuity.rdlink.read', 'continuity.rdlink.key_binding'),
                      ('continuity.keylog_file:' + path,))
        assert rows[1] == ['True', 'found by trial against the unbound secrets']

    def test_a_wrong_key_does_not_authenticate(self, cmd_tshark, result_file, test_env):
        path = keylog(result_file, ['RDLINK_SHARED %s %s' % (SESSION, '11' * 32)])
        rows = fields(cmd_tshark, self.exchange(result_file), test_env, self.names,
                      ('continuity.keylog_file:' + path,))
        assert rows[1][2] == 'False'
        assert rows[1][4] == 'no key for this session authenticated this frame'

    def test_malformed_key_lines_are_skipped_and_reported(self, cmd_tshark, result_file,
                                                          test_env):
        valid = 'RDLINK_SHARED %s %s' % (SESSION, SHARED_SECRET.hex())
        path = keylog(result_file, ['# a comment', 'RDLINK_SHARED abcd',
                                    'RDLINK_SHARED %s zz' % SESSION, valid])
        self.check_opened(fields(cmd_tshark, self.exchange(result_file), test_env, self.names,
                                 ('continuity.keylog_file:' + path,)))
        path = keylog(result_file, ['RDLINK_SHARED %s 1234' % SESSION], name='bad.keylog')
        rows = fields(cmd_tshark, self.exchange(result_file), test_env, self.names,
                      ('continuity.keylog_file:' + path,))
        assert 'key log line(s) named a key of this format and could not be used' in rows[1][4]

    def test_an_unreadable_key_log_is_reported(self, cmd_tshark, result_file, test_env):
        rows = fields(cmd_tshark, self.exchange(result_file), test_env, self.names,
                      ('continuity.keylog_file:' + result_file('missing.keylog'),))
        assert 'the key log file could not be read' in rows[1][4]

    def test_keys_carried_in_the_capture(self, cmd_tshark, cmd_editcap, result_file, test_env):
        carried = result_file('rdlink-dsb.pcapng')
        subprocess.check_call((cmd_editcap, '--inject-secrets',
                               'continuity,' + shared_keylog(result_file),
                               self.exchange(result_file), carried), env=test_env)
        self.check_opened(fields(cmd_tshark, carried, test_env, self.names))

    def test_a_missing_frame_is_skipped_and_reported(self, cmd_tshark, result_file, test_env):
        conn = Connection()
        path = capture_of(result_file, 'rdlink.pcap', [conn.frame(True, pairverify_m1()),
                                                       conn.frame(True, REQUESTS[0]),
                                                       conn.frame(True, REQUESTS[2])])
        rows = fields(cmd_tshark, path, test_env,
                      ('continuity.rdlink.read', 'continuity.rdlink.counter',
                       'continuity.rdlink.counter_skipped'), keyed(result_file))
        assert rows[1] == ['True', '0', '']
        assert rows[2] == ['True', '2', '1']

    def test_a_session_joined_after_its_handshake(self, cmd_tshark, result_file, test_env):
        path = capture_of(result_file, 'rdlink.pcap', [Connection().frame(True, REQUESTS[1])])
        (row,) = fields(cmd_tshark, path, test_env, self.names, keyed(result_file))
        assert row[0] == '0x08'
        assert row[4].startswith("the session's handshake is not in this capture")

    def test_read_inside_awdl_data_frames(self, cmd_tshark, result_file, test_env):
        conn = Connection()
        frames = [conn.frame(True, pairverify_m1()), conn.frame(True, REQUESTS[0]),
                  conn.frame(False, RESPONSES[0])]
        awdl = [over_awdl(frame[6:12], frame[0:6], frame[14:], seq)
                for seq, frame in enumerate(frames)]
        path = capture_of(result_file, 'rdlink-awdl.pcap', awdl, LINKTYPE_IEEE802_11)
        rows = fields(cmd_tshark, path, test_env, ('frame.protocols',) + self.names,
                      keyed(result_file))
        assert [row[0] for row in rows] == ['wlan:llc:awdl_data:ipv6:tcp:continuity.rdlink'] * 3
        self.check_opened([row[1:] for row in rows])


# --- Messages, exchanges and redissection ------------------------------------

class TestContinuityExchanges:
    names = ('continuity.companion.event', 'continuity.companion.xid',
             'continuity.companion.answers', 'continuity.companion.answered_in',
             'continuity.companion.unpaired', 'continuity.rdlink.counter',
             '_ws.expert.message')

    def run(self, cmd_tshark, result_file, test_env, frames, two_pass=True):
        path = capture_of(result_file, 'exchanges.pcap', frames)
        return fields(cmd_tshark, path, test_env, self.names, keyed(result_file), two_pass)

    def test_several_messages_in_one_segment(self, cmd_tshark, result_file, test_env):
        conn = Connection()
        rows = self.run(cmd_tshark, result_file, test_env, [
            conn.frame(True, pairverify_m1()),
            conn.frame(True, REQUESTS[0] + REQUESTS[1]),
            conn.frame(False, RESPONSES[0] + RESPONSES[1])])
        assert rows[1][0] == '_systemInfo|_systemInfo'
        assert rows[1][1] == '0x0000000000000001|0x0000000000000002'
        assert rows[1][3] == '3|3'
        assert rows[1][5] == '0|1'
        assert rows[2][1] == '0x0000000000000001|0x0000000000000002'
        assert rows[2][2] == '2|2'

    def test_a_message_split_across_segments(self, cmd_tshark, result_file, test_env):
        conn = Connection()
        rows = self.run(cmd_tshark, result_file, test_env, [
            conn.frame(True, pairverify_m1()),
            conn.frame(True, REQUESTS[0][:10]),
            conn.frame(True, REQUESTS[0][10:]),
            conn.frame(False, RESPONSES[0])])
        assert rows[2][0] == '_systemInfo' and rows[2][5] == '0'
        assert rows[3][2] == '3'

    def test_a_retransmission_advances_nothing(self, cmd_tshark, result_file, test_env):
        conn = Connection()
        first = conn.seq[True] + len(pairverify_m1())
        rows = self.run(cmd_tshark, result_file, test_env, [
            conn.frame(True, pairverify_m1()),
            conn.frame(True, REQUESTS[0]),
            conn.frame(True, REQUESTS[0], seq=first),
            conn.frame(True, REQUESTS[1])])
        assert [rows[1][5], rows[3][5]] == ['0', '1']

    def test_redissection_reports_the_same(self, cmd_tshark, result_file, test_env):
        conn = Connection()
        frames = [conn.frame(True, pairverify_m1()), conn.frame(True, REQUESTS[0] + REQUESTS[1]),
                  conn.frame(False, RESPONSES[0]), conn.frame(True, REQUESTS[2])]
        one = self.run(cmd_tshark, result_file, test_env, frames, two_pass=False)
        two = self.run(cmd_tshark, result_file, test_env, frames)
        assert [(r[0], r[1], r[2], r[5]) for r in one] == [(r[0], r[1], r[2], r[5]) for r in two]

    def test_simultaneous_conversations_pair_separately(self, cmd_tshark, result_file, test_env):
        a, b = Connection(51000, 52000), Connection(51001, 52001)
        rows = self.run(cmd_tshark, result_file, test_env, [
            a.frame(True, pairverify_m1()), b.frame(True, pairverify_m1()),
            a.frame(True, REQUESTS[0]), b.frame(True, REQUESTS[0]),
            b.frame(False, RESPONSES[0]), a.frame(False, RESPONSES[0])])
        assert rows[4][2] == '4' and rows[5][2] == '3'
        assert rows[2][3] == '6' and rows[3][3] == '5'

    def test_a_message_of_the_same_kind_is_no_answer(self, cmd_tshark, result_file, test_env):
        conn = Connection()
        rows = self.run(cmd_tshark, result_file, test_env, [
            conn.frame(True, pairverify_m1()), conn.frame(True, REQUESTS[0]),
            conn.frame(False, PEER_SAME_KIND)])
        assert rows[2][0] == '_ping' and rows[2][2] == ''
        assert 'with the same kind (2)' in rows[2][4]

    def test_an_id_used_again_after_its_exchange(self, cmd_tshark, result_file, test_env):
        conn = Connection()
        rows = self.run(cmd_tshark, result_file, test_env, [
            conn.frame(True, pairverify_m1()),
            conn.frame(True, REQUESTS[0]), conn.frame(False, RESPONSES[0]),
            conn.frame(True, REQUEST_XID1_C1), conn.frame(False, RESPONSE_XID1_S1)])
        assert rows[2][2] == '2' and rows[4][2] == '4'
        assert rows[1][3] == '3' and rows[3][3] == '5'

    def test_an_ambiguous_answer_is_not_paired(self, cmd_tshark, result_file, test_env):
        conn = Connection()
        rows = self.run(cmd_tshark, result_file, test_env, [
            conn.frame(True, pairverify_m1()),
            conn.frame(True, REQUESTS[0]), conn.frame(True, REQUEST_XID1_C1),
            conn.frame(False, RESPONSES[0])])
        assert 'already sent this exchange id from this side' in rows[2][4]
        assert rows[3][2] == '' and 'more than one unanswered message' in rows[3][4]

    @pytest.mark.parametrize('body,message', [
        (EVENT_IN_ARRAY, "the envelope's _i is an array, not a string"),
        (WRONG_TYPES, "the envelope's _t is a string, not an integer"),
        (WRONG_TYPES, "the envelope's _x is a string, not an integer"),
    ])
    def test_envelope_entries_of_the_wrong_type(self, cmd_tshark, result_file, test_env, body,
                                                message):
        conn = Connection()
        rows = self.run(cmd_tshark, result_file, test_env,
                        [conn.frame(True, pairverify_m1()), conn.frame(True, body)])
        assert rows[1][0] == ''
        assert message in rows[1][6]


# --- Media -----------------------------------------------------------------

def rtp(payload_type, seq=1):
    return struct.pack('!BBHII', 0x80, payload_type, seq, 0, 0x11223344) + b'\x00' * 20


RTCP_RR = struct.pack('!BBHI', 0x80, 201, 1, 0x55667788)


class TestContinuityMedia:
    names = ('frame.protocols', 'continuity.media.stream_id', 'continuity.session',
             'rtp.p_type', 'rtcp.pt', 'continuity.media.guessed', 'rtp.setup-method')

    def capture(self, result_file):
        conn = Connection()
        frames = [conn.frame(True, pairverify_m1()), conn.frame(False, STREAM_REQUEST),
                  conn.frame(True, STREAM_RESPONSE)]
        # The stream's sender is the side that asked for it, from its port.
        frames.append(over_ethernet(RESPONDER[0], INITIATOR[0], udp_over_ipv6(
            RESPONDER[1], INITIATOR[1], 40000, 40002, rtp(101))))
        frames.append(over_ethernet(INITIATOR[0], RESPONDER[0], udp_over_ipv6(
            INITIATOR[1], RESPONDER[1], 40002, 40000, RTCP_RR)))
        # Unrelated RTP of the type the camera's video uses.
        frames.append(over_ethernet(RESPONDER[0], INITIATOR[0], udp_over_ipv6(
            RESPONDER[1], INITIATOR[1], 50000, 50002, rtp(100))))
        return capture_of(result_file, 'media.pcap', frames)

    def test_a_negotiated_flow(self, cmd_tshark, result_file, test_env):
        rows = fields(cmd_tshark, self.capture(result_file), test_env, self.names,
                      keyed(result_file))
        rtp_row, rtcp_row = rows[3], rows[4]
        assert 'continuity.media:rtp' in rtp_row[0] and 'rtpevent' not in rtp_row[0]
        assert rtp_row[1] == 'ABCD1234:ContinuityCaptureMediaMicrophone'
        assert rtp_row[2] == SESSION and rtp_row[3] == '101'
        assert rtp_row[6] == 'Continuity'
        assert 'continuity.media' in rtcp_row[0] and rtcp_row[4] == '201'

    def test_unrelated_rtp_is_not_claimed(self, cmd_tshark, result_file, test_env):
        rows = fields(cmd_tshark, self.capture(result_file), test_env, self.names,
                      keyed(result_file))
        assert 'continuity' not in rows[5][0]

    def test_without_keys_no_flow_is_identified(self, cmd_tshark, result_file, test_env):
        rows = fields(cmd_tshark, self.capture(result_file), test_env, self.names)
        assert all('continuity.media' not in row[0] for row in rows[3:])

    def test_the_payload_type_guess_is_opt_in(self, cmd_tshark, result_file, test_env):
        rows = fields(cmd_tshark, self.capture(result_file), test_env, self.names,
                      ('continuity.media_guess_pt100:TRUE',))
        assert 'continuity.media' in rows[5][0] and rows[5][5] != ''
        assert 'continuity.media' not in rows[3][0]
