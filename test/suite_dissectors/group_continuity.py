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
import json
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


def checked_run(command, env, artifact, timeout=120, **kwargs):
    '''Run a command with a bounded time. On a non-zero exit or a timeout its
    complete stdout and stderr are written beside `artifact` (the test's
    capture, in its result directory) and named in the failure, which shows
    only their ends.'''
    def keep(stdout, stderr, why):
        out_path, err_path = artifact + '.stdout.txt', artifact + '.stderr.txt'
        for path, data in ((out_path, stdout), (err_path, stderr)):
            if isinstance(data, bytes):
                data = data.decode('utf-8', 'replace')
            with open(path, 'w', encoding='utf-8') as f:
                f.write(data or '')
        return ('%s: %s\nfull stdout: %s\nfull stderr: %s\nstdout ends:\n%s\nstderr ends:\n%s'
                % (' '.join(str(c) for c in command), why, out_path, err_path,
                   (stdout or '')[-1500:], (stderr or '')[-1500:]))
    try:
        completed = subprocess.run(command, capture_output=True, encoding='utf-8', env=env,
                                   timeout=timeout, **kwargs)
    except subprocess.TimeoutExpired as expired:
        raise AssertionError(keep(expired.stdout, expired.stderr,
                                  'timed out after %d s' % timeout)) from None
    assert completed.returncode == 0, keep(completed.stdout, completed.stderr,
                                           'exited %d' % completed.returncode)
    return completed


def fields(cmd_tshark, capture, env, names, prefs=(), two_pass=True):
    command = [cmd_tshark, '-r', capture, '-T', 'fields', '-E', 'occurrence=a',
               '-E', 'aggregator=|']
    if two_pass:
        command.insert(1, '-2')
    for pref in prefs:
        command += ['-o', pref]
    for name in names:
        command += ['-e', name]
    completed = checked_run(command, env, capture)
    return [line.split('\t') for line in completed.stdout.splitlines()]


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


@pytest.fixture(scope='session')
def cmd_sharkd(program):
    return program('sharkd')


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
        (b'\n\x00', ''), (b'hello\n\x00', 'hello'), (b'hello\x00', 'hello')], ids=['empty-text', 'text-newline-nul', 'text-nul'])
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
    ], ids=['dict-short', 'array-short', 'key-without-value', 'endless-dict-unterminated', 'endless-array-unterminated', 'unknown-marker', 'unresolvable-reference'])
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
                                    pairverify_m1(extra_entry=True)], ids=['pd-length-0x92', 'extra-entry'])
    def test_equivalent_handshake_encodings(self, cmd_tshark, result_file, test_env, m1):
        path = capture_of(result_file, 'm1.pcap', [Connection().frame(True, m1)])
        (row,) = fields(cmd_tshark, path, test_env, self.names)
        assert row[1] == SESSION

    @pytest.mark.parametrize('m1,message', [
        (pairverify_m1(state=2), 'the State element is not 1'),
        (pairverify_m1(keys=2), 'exactly one 32-byte public key'),
        (pairverify_m1(overrun=True), 'disagrees with its own lengths'),
    ], ids=['state-2', 'two-keys', 'tlv-overrun'])
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
    ], ids=['http', 'known-type-bad-length', 'handshake-prefix-cut-short'])
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
    ], ids=['event-in-array', 'type-is-string', 'xid-is-string'])
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
        # Unrelated RTP of the type the microphone stream was once bound to.
        frames.append(over_ethernet(RESPONDER[0], INITIATOR[0], udp_over_ipv6(
            RESPONDER[1], INITIATOR[1], 50004, 50006, rtp(101))))
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
        assert 'continuity' not in rows[6][0]

    def test_without_keys_no_flow_is_identified(self, cmd_tshark, result_file, test_env):
        rows = fields(cmd_tshark, self.capture(result_file), test_env, self.names)
        assert all('continuity.media' not in row[0] for row in rows[3:])

    def test_the_payload_type_guess_is_opt_in(self, cmd_tshark, result_file, test_env):
        rows = fields(cmd_tshark, self.capture(result_file), test_env, self.names,
                      ('continuity.media_guess_pt100:TRUE',))
        assert 'continuity.media' in rows[5][0] and rows[5][5] != ''
        assert 'continuity.media' not in rows[3][0]
        # The guess is for type 100 only.
        assert 'continuity' not in rows[6][0]

    def test_a_guessed_flow_is_set_up_once(self, cmd_tshark, result_file, test_env):
        # RTP is told about a guessed flow on the packet the heuristic claims,
        # not again on each later packet: every packet names the same setup.
        frames = [udp_frame(addr6(PHONE_STREAM_ADDR), 50000, addr6(MAC_STREAM_ADDR), 50002,
                            rtp_packet(100, seq, seq * 800)) for seq in range(4)]
        rows = fields(cmd_tshark, capture_of(result_file, 'guessed.pcap', frames), test_env,
                      ('continuity.media.guessed', 'rtp.setup-frame', 'rtp.p_type'),
                      ('continuity.media_guess_pt100:TRUE',))
        assert all(row[0] != '' for row in rows)
        assert [row[1] for row in rows] == ['1'] * 4


# --- Sealing protected frames ----------------------------------------------
#
# A from-scratch ChaCha20-Poly1305 (RFC 8439), so that further protected
# frames can be built from readable plaintext at run time rather than embedded
# as opaque bytes. It is not Wireshark's implementation (libgcrypt), and it is
# pinned two ways: to the RFC's own AEAD test vector, and to the frames above,
# which were sealed by Python's `cryptography`.
#
# The construction a frame uses:
#   key        = HKDF-SHA-512(salt = 64 zero bytes, ikm = shared secret,
#                info = "ClientEncrypt-main" for frames from the connection's
#                initiator, "ServerEncrypt-main" for frames from the responder),
#                first 32 bytes
#   nonce      = the per-direction count of protected frames before this one,
#                little-endian in 8 bytes, then 4 zero bytes
#   aad        = the frame's 4-byte header: 0x08, then the body length
#                (ciphertext + 16-byte tag) as 24-bit big-endian
#   body       = ChaCha20 ciphertext of the OPACK plaintext, then the tag

def _rotl32(value, shift):
    return ((value << shift) | (value >> (32 - shift))) & 0xffffffff


def _chacha20_block(key, counter, nonce):
    constants = (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)
    state = (list(constants) + list(struct.unpack('<8I', key)) + [counter]
             + list(struct.unpack('<3I', nonce)))
    working = state[:]

    def quarter(a, b, c, d):
        working[a] = (working[a] + working[b]) & 0xffffffff
        working[d] = _rotl32(working[d] ^ working[a], 16)
        working[c] = (working[c] + working[d]) & 0xffffffff
        working[b] = _rotl32(working[b] ^ working[c], 12)
        working[a] = (working[a] + working[b]) & 0xffffffff
        working[d] = _rotl32(working[d] ^ working[a], 8)
        working[c] = (working[c] + working[d]) & 0xffffffff
        working[b] = _rotl32(working[b] ^ working[c], 7)

    for _ in range(10):
        quarter(0, 4, 8, 12)
        quarter(1, 5, 9, 13)
        quarter(2, 6, 10, 14)
        quarter(3, 7, 11, 15)
        quarter(0, 5, 10, 15)
        quarter(1, 6, 11, 12)
        quarter(2, 7, 8, 13)
        quarter(3, 4, 9, 14)
    return struct.pack('<16I', *((w + s) & 0xffffffff for w, s in zip(working, state)))


def _chacha20_xor(key, counter, nonce, data):
    out = bytearray()
    for block in range(0, len(data), 64):
        stream = _chacha20_block(key, counter + block // 64, nonce)
        out += bytes(x ^ y for x, y in zip(data[block:block + 64], stream))
    return bytes(out)


def _poly1305(key, message):
    r = int.from_bytes(key[:16], 'little') & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:], 'little')
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(message), 16):
        chunk = message[i:i + 16] + b'\x01'
        acc = (acc + int.from_bytes(chunk, 'little')) * r % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, 'little')


def aead_seal(key, nonce, plaintext, aad):
    otk = _chacha20_block(key, 0, nonce)[:32]
    ciphertext = _chacha20_xor(key, 1, nonce, plaintext)

    def pad16(data):
        return b'\x00' * ((-len(data)) % 16)
    mac_data = (aad + pad16(aad) + ciphertext + pad16(ciphertext)
                + struct.pack('<QQ', len(aad), len(ciphertext)))
    return ciphertext + _poly1305(otk, mac_data)


CLIENT_KEY = hkdf_sha512(SHARED_SECRET, b'ClientEncrypt-main')
SERVER_KEY = hkdf_sha512(SHARED_SECRET, b'ServerEncrypt-main')


def seal(from_initiator, counter, plaintext):
    '''An RDLink EncryptedData frame carrying `plaintext`.'''
    header = b'\x08' + (len(plaintext) + 16).to_bytes(3, 'big')
    nonce = counter.to_bytes(8, 'little') + b'\x00' * 4
    return header + aead_seal(CLIENT_KEY if from_initiator else SERVER_KEY, nonce, plaintext, header)


def o_bytes(data):
    if len(data) <= 32:
        return bytes([0x70 + len(data)]) + data
    if len(data) <= 0xff:
        return b'\x91' + bytes([len(data)]) + data
    return b'\x92' + len(data).to_bytes(2, 'little') + data


def o_uint(value):
    '''An integer in the smallest form the platform reads as this value.'''
    if 0 <= value <= 39:
        return o_int(value)
    if value <= 0xff:
        return b'\x30' + bytes([value])
    if value <= 0xffff:
        return b'\x31' + value.to_bytes(2, 'little')
    if value <= 0x7fffffff:
        return b'\x32' + value.to_bytes(4, 'little')
    return b'\x33' + value.to_bytes(8, 'little')


def envelope(event, kind, xid, content=b'\xe0'):
    pairs = []
    if event is not None:
        pairs.append((o_str('_i'), o_str(event)))
    pairs += [(o_str('_t'), o_int(kind)), (o_str('_x'), o_uint(xid)), (o_str('_c'), content)]
    return o_dict(*pairs)


class TestSealing:
    def test_rfc8439_aead_vector(self):
        # RFC 8439, section 2.8.2.
        key = bytes(range(0x80, 0xa0))
        nonce = bytes.fromhex('070000004041424344454647')
        aad = bytes.fromhex('50515253c0c1c2c3c4c5c6c7')
        plaintext = (b"Ladies and Gentlemen of the class of '99: If I could offer you only "
                     b"one tip for the future, sunscreen would be it.")
        sealed = aead_seal(key, nonce, plaintext, aad)
        assert sealed[-16:].hex() == '1ae10b594f09e26a7e902ecbd0600691'
        assert sealed[:16].hex() == 'd31a8d34648e60db7b86afbc53ef7ec2'

    def test_matches_the_independently_sealed_frames(self):
        for i in range(4):
            assert seal(True, i, envelope('_systemInfo', 2, i + 1)) == REQUESTS[i]
            assert seal(False, i, envelope(None, 3, i + 1)) == RESPONSES[i]


def run_tshark(cmd_tshark, capture, env, args, timeout=120):
    '''Run tshark with a bounded time and keep its output for the failure report.'''
    return checked_run([cmd_tshark] + args + ['-r', capture], env, capture, timeout).stdout


# --- Media flow identity -----------------------------------------------------

def stream_start(xid, stream_id, port, addr=None, port_encoding=None):
    content = [(o_str('_streamID'), o_str(stream_id)), (o_str('_streamType'), o_int(3))]
    if addr is not None:
        content.append((o_str('_streamAddr'), o_str(addr)))
    content.append((o_str('_streamPort'), port_encoding if port_encoding is not None else o_uint(port)))
    return envelope('_streamStart', 2, xid, o_dict(*content))


def stream_answer(xid, port, addr=None):
    content = []
    if addr is not None:
        content.append((o_str('_streamAddr'), o_str(addr)))
    content.append((o_str('_streamPort'), o_uint(port)))
    return envelope(None, 3, xid, o_dict(*content))


VIDEO = 'ABCD1234:ContinuityCaptureMediaIdentifierDefaultVideo'
DESKCAM = 'ABCD1234:ContinuityCaptureMediaIdentifierDeskcamVideo'
MICROPHONE = 'ABCD1234:ContinuityCaptureMediaMicrophone'
OTHER_STREAM = 'ABCD1234:SomethingNotObserved'
DISPLAY = 'ABCD1234:AVCVideoStream'

PHONE_STREAM_ADDR = 'fd00::a'
MAC_STREAM_ADDR = 'fd00::b'


def addr6(text):
    import ipaddress
    return ipaddress.IPv6Address(text).packed


class Endpoints:
    '''A control connection's two ends, and media sent between chosen addresses.'''

    def __init__(self, initiator=INITIATOR, responder=RESPONDER, ports=(51000, 52000)):
        self.initiator, self.responder = initiator, responder
        self.conn = Connection(*ports)
        self.conn_ends = (initiator, responder)

    def tcp(self, from_initiator, payload):
        src, dst = (self.initiator, self.responder) if from_initiator else (self.responder, self.initiator)
        sport, dport = self.conn.ports if from_initiator else self.conn.ports[::-1]
        at = self.conn.seq[from_initiator]
        self.conn.seq[from_initiator] += len(payload)
        return over_ethernet(src[0], dst[0], tcp_over_ipv6(
            src[1], dst[1], sport, dport, at, self.conn.seq[not from_initiator], payload))


def udp_frame(src_ip, sport, dst_ip, dport, payload, src_mac=RESPONDER[0], dst_mac=INITIATOR[0]):
    return over_ethernet(src_mac, dst_mac, udp_over_ipv6(src_ip, dst_ip, sport, dport, payload))


def rtp_packet(payload_type, seq, timestamp, ssrc=0x11223344, size=20):
    return struct.pack('!BBHII', 0x80, payload_type, seq, timestamp, ssrc) + b'\x5a' * size


def negotiate(ends, server_counter, client_counter, request, answer):
    '''The phone (the control connection's responder) asks; the Mac answers.'''
    return [ends.tcp(False, seal(False, server_counter, request)),
            ends.tcp(True, seal(True, client_counter, answer))]


class TestMediaFlows:
    names = ('frame.number', 'frame.protocols', 'continuity.media.stream_id',
             'continuity.media.negotiated_in', 'continuity.media.ambiguous',
             'continuity.session', 'rtp.p_type', 'continuity.media.payload_binding')

    def dissect(self, cmd_tshark, result_file, test_env, frames, prefs=(), two_pass=True):
        path = capture_of(result_file, 'media-flows.pcap', frames)
        rows = fields(cmd_tshark, path, test_env, self.names, keyed(result_file) + tuple(prefs),
                      two_pass)
        return {int(row[0]): row for row in rows}

    def video_session(self, ends=None, phone_addr=PHONE_STREAM_ADDR, mac_addr=MAC_STREAM_ADDR,
                      xid=5, counters=(0, 0), handshake=True):
        ends = ends or Endpoints()
        frames = [ends.tcp(True, pairverify_m1())] if handshake else []
        frames += negotiate(ends, counters[0], counters[1],
                            stream_start(xid, VIDEO, 40000, phone_addr),
                            stream_answer(xid, 40002, mac_addr))
        return ends, frames

    def video_packet(self, phone_addr=PHONE_STREAM_ADDR, mac_addr=MAC_STREAM_ADDR, seq=1,
                     ports=(40000, 40002)):
        return udp_frame(addr6(phone_addr), ports[0], addr6(mac_addr), ports[1],
                         rtp_packet(100, seq, seq * 800))

    def test_a_negotiated_flow_at_its_announced_addresses(self, cmd_tshark, result_file, test_env):
        _, frames = self.video_session()
        frames.append(self.video_packet())
        rows = self.dissect(cmd_tshark, result_file, test_env, frames)
        assert rows[4][2] == VIDEO and rows[4][3] == '3' and rows[4][5] == SESSION

    def test_a_negotiated_flow_at_the_control_addresses(self, cmd_tshark, result_file, test_env):
        # The message spec observed media sent to the address the control
        # connection uses rather than the one announced.
        _, frames = self.video_session()
        frames.append(udp_frame(RESPONDER[1], 40000, INITIATOR[1], 40002, rtp_packet(100, 1, 800)))
        rows = self.dissect(cmd_tshark, result_file, test_env, frames)
        assert rows[4][2] == VIDEO

    def test_the_same_ports_between_other_endpoints(self, cmd_tshark, result_file, test_env):
        _, frames = self.video_session()
        frames.append(self.video_packet(phone_addr='fd00::99', mac_addr='fd00::98'))
        rows = self.dissect(cmd_tshark, result_file, test_env, frames)
        assert 'continuity' not in rows[4][1]

    def test_media_in_the_other_direction(self, cmd_tshark, result_file, test_env):
        _, frames = self.video_session()
        frames.append(udp_frame(addr6(MAC_STREAM_ADDR), 40002, addr6(PHONE_STREAM_ADDR), 40000,
                                RTCP_RR, src_mac=INITIATOR[0], dst_mac=RESPONDER[0]))
        rows = self.dissect(cmd_tshark, result_file, test_env, frames)
        assert rows[4][2] == VIDEO

    def test_ports_swapped_between_the_ends(self, cmd_tshark, result_file, test_env):
        # The phone's port at the Mac's address: not the negotiated flow.
        _, frames = self.video_session()
        frames.append(self.video_packet(ports=(40002, 40000)))
        rows = self.dissect(cmd_tshark, result_file, test_env, frames)
        assert 'continuity' not in rows[4][1]

    def test_a_packet_before_its_negotiation(self, cmd_tshark, result_file, test_env):
        ends = Endpoints()
        frames = [ends.tcp(True, pairverify_m1()), self.video_packet(seq=1)]
        frames += negotiate(ends, 0, 0, stream_start(5, VIDEO, 40000, PHONE_STREAM_ADDR),
                            stream_answer(5, 40002, MAC_STREAM_ADDR))
        frames.append(self.video_packet(seq=2))
        rows = self.dissect(cmd_tshark, result_file, test_env, frames)
        assert 'continuity' not in rows[2][1]
        assert rows[5][2] == VIDEO and rows[5][3] == '4'

    def test_a_later_session_reusing_the_ports(self, cmd_tshark, result_file, test_env):
        ends, frames = self.video_session()
        frames.append(self.video_packet(seq=1))                                  # 4: first session
        frames += negotiate(ends, 1, 1, stream_start(6, VIDEO, 40000, 'fd00::c'),
                            stream_answer(6, 40002, 'fd00::d'))                 # 5, 6
        frames.append(self.video_packet(phone_addr='fd00::c', mac_addr='fd00::d', seq=2))  # 7
        frames.append(self.video_packet(seq=3))                                  # 8: first session
        for two_pass in (False, True):
            rows = self.dissect(cmd_tshark, result_file, test_env, frames, two_pass=two_pass)
            assert rows[4][3] == '3' and rows[7][3] == '6' and rows[8][3] == '3'

    def test_identical_negotiations_are_ambiguous(self, cmd_tshark, result_file, test_env):
        ends, frames = self.video_session()
        frames.append(self.video_packet(seq=1))                                  # 4
        frames += negotiate(ends, 1, 1, stream_start(6, VIDEO, 40000, PHONE_STREAM_ADDR),
                            stream_answer(6, 40002, MAC_STREAM_ADDR))           # 5, 6
        frames.append(self.video_packet(seq=2))                                  # 7
        rows = self.dissect(cmd_tshark, result_file, test_env, frames)
        assert rows[4][3] == '3' and rows[4][4] == ''
        assert rows[7][2] == '' and rows[7][3] == ''
        assert 'frames 3 and 6' in rows[7][4]

    def test_concurrent_sessions_with_the_same_ports(self, cmd_tshark, result_file, test_env):
        other = (bytes.fromhex('020000000003'), bytes.fromhex('fe800000000000000000000000000003'))
        other_peer = (bytes.fromhex('020000000004'), bytes.fromhex('fe800000000000000000000000000004'))
        a, b = Endpoints(), Endpoints(other, other_peer, (51001, 52001))
        frames = [a.tcp(True, pairverify_m1()), b.tcp(True, pairverify_m1())]
        frames += negotiate(a, 0, 0, stream_start(5, VIDEO, 40000), stream_answer(5, 40002))  # 3, 4
        frames += negotiate(b, 0, 0, stream_start(5, MICROPHONE, 40000), stream_answer(5, 40002))  # 5, 6
        frames.append(udp_frame(RESPONDER[1], 40000, INITIATOR[1], 40002, rtp_packet(100, 1, 800)))  # 7
        frames.append(udp_frame(other_peer[1], 40000, other[1], 40002, rtp_packet(101, 1, 480)))  # 8
        rows = self.dissect(cmd_tshark, result_file, test_env, frames)
        assert rows[7][2] == VIDEO and rows[7][3] == '4'
        assert rows[8][2] == MICROPHONE and rows[8][3] == '6'

    @pytest.mark.parametrize('port_encoding', [
        b'\x32' + (70000).to_bytes(4, 'little'),   # out of range
        o_int(0),                                  # zero
        o_str('40000'),                            # a string, not an integer
    ], ids=['port-out-of-range', 'port-zero', 'port-as-string'])
    def test_an_invalid_port_negotiates_nothing(self, cmd_tshark, result_file, test_env,
                                                port_encoding):
        ends = Endpoints()
        frames = [ends.tcp(True, pairverify_m1())]
        frames += negotiate(ends, 0, 0, stream_start(5, VIDEO, None, PHONE_STREAM_ADDR,
                                                     port_encoding=port_encoding),
                            stream_answer(5, 40002, MAC_STREAM_ADDR))
        frames.append(self.video_packet())
        rows = self.dissect(cmd_tshark, result_file, test_env, frames)
        assert 'continuity' not in rows[4][1]

    def test_a_negotiation_without_its_answer(self, cmd_tshark, result_file, test_env):
        ends = Endpoints()
        frames = [ends.tcp(True, pairverify_m1()),
                  ends.tcp(False, seal(False, 0, stream_start(5, VIDEO, 40000, PHONE_STREAM_ADDR))),
                  self.video_packet()]
        rows = self.dissect(cmd_tshark, result_file, test_env, frames)
        assert 'continuity' not in rows[3][1]

    def test_random_revisits_keep_their_association(self, cmd_sharkd, result_file, base_env):
        ends, frames = self.video_session()
        frames.append(self.video_packet(seq=1))                                  # 4
        frames += negotiate(ends, 1, 1, stream_start(6, VIDEO, 40000, 'fd00::c'),
                            stream_answer(6, 40002, 'fd00::d'))                 # 5, 6
        frames.append(self.video_packet(phone_addr='fd00::c', mac_addr='fd00::d', seq=2))  # 7
        frames.append(self.video_packet(seq=3))                                  # 8
        path = capture_of(result_file, 'revisits.pcap', frames)
        order = [8, 4, 7, 4, 8, 7, 4]
        replies = sharkd_frames(cmd_sharkd, base_env, path, shared_keylog(result_file), order)
        expected = {4: 'Negotiated in: 3', 7: 'Negotiated in: 6', 8: 'Negotiated in: 3'}
        for frame, reply in zip(order, replies):
            assert expected[frame] in reply, (frame, reply[:2000])


def sharkd_frames(cmd_sharkd, env, path, keylog_path, order, prefs=()):
    '''Dissect the frames in `order`, one request each, in a single sharkd
    session -- revisits in an arbitrary order after one load. Returns each
    frame's reply as JSON text, in the order asked.'''
    requests = [{'jsonrpc': '2.0', 'id': 1, 'method': 'setconf',
                 'params': {'name': 'continuity.keylog_file', 'value': keylog_path}}]
    for i, pref in enumerate(prefs):
        name, value = pref.split(':', 1)
        requests.append({'jsonrpc': '2.0', 'id': 2 + i, 'method': 'setconf',
                         'params': {'name': name, 'value': value}})
    requests.append({'jsonrpc': '2.0', 'id': 9, 'method': 'load', 'params': {'file': path}})
    for i, frame in enumerate(order):
        requests.append({'jsonrpc': '2.0', 'id': 10 + i, 'method': 'frame',
                         'params': {'frame': frame, 'proto': True}})
    completed = checked_run((cmd_sharkd, '-'), env, path,
                            input='\n'.join(json.dumps(r) for r in requests))
    replies = {r['id']: json.dumps(r) for r in map(json.loads, completed.stdout.splitlines())
               if 'id' in r}
    return [replies[10 + i] for i in range(len(order))]


# --- RTP/RTCP and the clock rates ------------------------------------------

def rtp_streams(cmd_tshark, capture, env, prefs):
    args = ['-q', '-z', 'rtp,streams']
    for pref in prefs:
        args += ['-o', pref]
    return run_tshark(cmd_tshark, capture, env, args)


class TestMediaTiming:
    def flow(self, stream_id, payload_type, ticks_per_packet, interval, count=20):
        ends = Endpoints()
        frames = [ends.tcp(True, pairverify_m1())]
        frames += negotiate(ends, 0, 0, stream_start(5, stream_id, 40000, PHONE_STREAM_ADDR),
                            stream_answer(5, 40002, MAC_STREAM_ADDR))
        times = [0.0, 0.0, 0.0]
        for i in range(count):
            frames.append(udp_frame(addr6(PHONE_STREAM_ADDR), 40000, addr6(MAC_STREAM_ADDR), 40002,
                                    rtp_packet(payload_type, i + 1, 1000 + i * ticks_per_packet)))
            times.append(1.0 + i * interval)
        return frames, times

    def write(self, result_file, frames, times):
        path = result_file('timing.pcap')
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))
            for frame, at in zip(frames, times):
                f.write(struct.pack('<IIII', 1700000000 + int(at), round((at % 1) * 1e6),
                                    len(frame), len(frame)))
                f.write(frame)
        return path

    def max_jitter(self, output):
        # The rtp,streams table: one row per stream; Max Jitter is the third
        # number from the end, before Mean Jitter and the problem flag.
        rows = [line for line in output.splitlines() if 'fd00::a' in line]
        assert len(rows) == 1, output
        numbers = [float(x) for x in rows[0].replace('X', ' ').split()
                   if x.replace('.', '', 1).isdigit()]
        return numbers[-3]

    # Video timestamps advance at 24 kHz: measured on six real Camera streams
    # at 24,004 to 24,225 ticks a second, and on Sidecar Display's video at
    # 24,005 to 24,136.
    @pytest.mark.parametrize('stream_id,payload_type,ticks,interval', [
        (VIDEO, 100, 800, 1 / 30),          # 30 frames a second
        (DESKCAM, 100, 400, 1 / 60),        # 60 frames a second
        (DISPLAY, 100, 400, 1 / 60),
    ], ids=['camera-video-30fps', 'deskcam-60fps', 'display-60fps'])
    def test_the_bound_clock_rate(self, cmd_tshark, result_file, test_env, stream_id,
                                  payload_type, ticks, interval):
        # Timestamps that advance exactly in step with arrival at the bound
        # rate have no jitter; at any other rate they have.
        frames, times = self.flow(stream_id, payload_type, ticks, interval)
        output = rtp_streams(cmd_tshark, self.write(result_file, frames, times), test_env,
                             keyed(result_file))
        assert self.max_jitter(output) < 0.01, output
        assert 'Continuity media (opaque payload)' in output or str(payload_type) in output

    def test_a_wrong_clock_would_show(self, cmd_tshark, result_file, test_env):
        # The control: the same video stream with 90 kHz timestamps.
        frames, times = self.flow(VIDEO, 100, 3000, 1 / 30)
        output = rtp_streams(cmd_tshark, self.write(result_file, frames, times), test_env,
                             keyed(result_file))
        assert self.max_jitter(output) > 1.0, output

    def test_an_unobserved_stream_is_not_bound(self, cmd_tshark, result_file, test_env):
        frames, times = self.flow(OTHER_STREAM, 100, 800, 1 / 30, count=2)
        path = self.write(result_file, frames, times)
        rows = fields(cmd_tshark, path, test_env,
                      ('continuity.media.stream_id', 'continuity.media.payload_binding',
                       'frame.protocols'), keyed(result_file))
        assert rows[3][0] == OTHER_STREAM
        assert rows[3][1].startswith('none:')
        assert 'rtpevent' not in rows[3][2]

    def test_a_bound_stream_says_so(self, cmd_tshark, result_file, test_env):
        frames, times = self.flow(VIDEO, 100, 800, 1 / 30, count=2)
        rows = fields(cmd_tshark, self.write(result_file, frames, times), test_env,
                      ('continuity.media.payload_binding', 'frame.protocols'), keyed(result_file))
        assert rows[3][0] == 'payload type 100 at 24000 Hz'
        assert 'rtpevent' not in rows[3][1]

    def test_a_display_stream_is_bound(self, cmd_tshark, result_file, test_env):
        frames, times = self.flow(DISPLAY, 100, 400, 1 / 60, count=2)
        rows = fields(cmd_tshark, self.write(result_file, frames, times), test_env,
                      ('continuity.media.payload_binding', 'frame.protocols'), keyed(result_file))
        assert rows[3][0] == 'payload type 100 at 24000 Hz'
        assert 'rtpevent' not in rows[3][1]

    def test_the_microphone_is_not_bound(self, cmd_tshark, result_file, test_env):
        # Its payload type is chosen by the Mac's answer and no real-Mac
        # capture has shown it, so neither its type nor its clock is assumed;
        # it is still not read as telephone events.
        frames, times = self.flow(MICROPHONE, 101, 480, 0.010)
        path = self.write(result_file, frames, times)
        rows = fields(cmd_tshark, path, test_env,
                      ('continuity.media.stream_id', 'continuity.media.payload_binding',
                       'frame.protocols'), keyed(result_file))
        assert rows[3][0] == MICROPHONE
        assert rows[3][1].startswith('none:')
        assert 'rtpevent' not in rows[3][2]
        output = rtp_streams(cmd_tshark, path, test_env, keyed(result_file))
        assert 'clock rate unknown' in output, output

    def test_rtcp_before_any_rtp(self, cmd_tshark, result_file, test_env):
        ends = Endpoints()
        frames = [ends.tcp(True, pairverify_m1())]
        frames += negotiate(ends, 0, 0, stream_start(5, VIDEO, 40000, PHONE_STREAM_ADDR),
                            stream_answer(5, 40002, MAC_STREAM_ADDR))
        frames.append(udp_frame(addr6(MAC_STREAM_ADDR), 40002, addr6(PHONE_STREAM_ADDR), 40000,
                                RTCP_RR, src_mac=INITIATOR[0], dst_mac=RESPONDER[0]))
        frames.append(udp_frame(addr6(PHONE_STREAM_ADDR), 40000, addr6(MAC_STREAM_ADDR), 40002,
                                rtp_packet(100, 1, 800)))
        rows = fields(cmd_tshark, capture_of(result_file, 'rtcp-first.pcap', frames), test_env,
                      ('continuity.media.stream_id', 'rtcp.pt', 'rtp.p_type'), keyed(result_file))
        assert rows[3] == [VIDEO, '201', '']
        assert rows[4] == [VIDEO, '', '100']

    @pytest.mark.parametrize('payload', [b'\x80', b'\x80\x64\x00', b'\x40' + b'\x00' * 15], ids=['one-byte', 'three-bytes', 'rtp-version-1'])
    def test_short_or_other_version_packets(self, cmd_tshark, result_file, test_env, payload):
        ends = Endpoints()
        frames = [ends.tcp(True, pairverify_m1())]
        frames += negotiate(ends, 0, 0, stream_start(5, VIDEO, 40000, PHONE_STREAM_ADDR),
                            stream_answer(5, 40002, MAC_STREAM_ADDR))
        frames.append(udp_frame(addr6(PHONE_STREAM_ADDR), 40000, addr6(MAC_STREAM_ADDR), 40002,
                                payload))
        rows = fields(cmd_tshark, capture_of(result_file, 'short.pcap', frames), test_env,
                      ('frame.protocols', '_ws.expert.message'), keyed(result_file))
        assert 'continuity.media' not in rows[3][0]


# --- Handshake validity --------------------------------------------------------

def m1_body(*pairs, dict_marker=None, after=b''):
    """A PubKey frame whose body is a dictionary of `pairs`: counted, or with
    `dict_marker` as given (0xef, the endless form, gains its terminator), and
    `after` appended inside the frame's declared body."""
    marker = dict_marker if dict_marker is not None else 0xe0 + len(pairs)
    body = bytes([marker]) + b''.join(k + v for k, v in pairs)
    if marker == 0xef:
        body += b'\x03'
    body += after
    return b'\x05' + len(body).to_bytes(3, 'big') + body


def tlv8(*elements):
    return b''.join(bytes([tag, len(value)]) + value for tag, value in elements)


STATE_1 = (0x06, b'\x01')
STATE_2 = (0x06, b'\x02')
PUBLIC_KEY = (0x03, EPHEMERAL_KEY)
OTHER_KEY = (0x03, bytes(range(0x10, 0x30)))
FLAGS = (0x19, b'\x01')


class TestHandshakeValidity:
    def session_of(self, cmd_tshark, result_file, test_env, *m1s):
        conn = Connection()
        frames = [conn.frame(True, m1) for m1 in m1s] + [conn.frame(True, REQUESTS[0])]
        rows = fields(cmd_tshark, capture_of(result_file, 'm1.pcap', frames), test_env,
                      ('continuity.session', '_ws.expert.message', 'continuity.rdlink.read'),
                      keyed(result_file))
        return rows

    @pytest.mark.parametrize('m1', [
        m1_body((o_str('_pd'), o_bytes(tlv8(STATE_1, PUBLIC_KEY, FLAGS)))),
        m1_body((o_str('_pd'), b'\x92' + (40).to_bytes(2, 'little') + tlv8(STATE_1, PUBLIC_KEY, FLAGS))),
        m1_body((o_str('x'), o_int(1)), (o_str('_pd'), o_bytes(tlv8(STATE_1, PUBLIC_KEY, FLAGS)))),
        m1_body((o_str('_pd'), o_bytes(tlv8(PUBLIC_KEY, STATE_1)))),
        m1_body((o_str('_pd'), o_bytes(tlv8(STATE_1, PUBLIC_KEY, FLAGS))), dict_marker=0xef),
    ], ids=['pd-0x91', 'pd-0x92', 'pd-after-other-key', 'key-before-state', 'endless-dict'])
    def test_equivalent_valid_handshakes(self, cmd_tshark, result_file, test_env, m1):
        rows = self.session_of(cmd_tshark, result_file, test_env, m1)
        assert rows[0][0] == SESSION
        assert rows[1][2] == 'True'

    @pytest.mark.parametrize('m1,reason', [
        # A dictionary declaring two entries and carrying one: the object
        # decode reports it truncated, so nothing inside it is used.
        (m1_body((o_str('_pd'), o_bytes(tlv8(STATE_1, PUBLIC_KEY, FLAGS))), dict_marker=0xe2),
         'the object encoding around _pd is incomplete or malformed'),
        (m1_body((o_str('_pd'), o_bytes(tlv8(STATE_1, STATE_2, PUBLIC_KEY)))),
         'more than one State element'),
        (m1_body((o_str('_pd'), o_bytes(tlv8(STATE_1, STATE_1, PUBLIC_KEY)))),
         'more than one State element'),
        (m1_body((o_str('_pd'), o_bytes(tlv8(PUBLIC_KEY, FLAGS)))),
         'carries no State element'),
        (m1_body((o_str('_pd'), o_bytes(tlv8(STATE_1, FLAGS)))),
         'exactly one 32-byte public key'),
        (m1_body((o_str('_pd'), o_bytes(tlv8(STATE_1, PUBLIC_KEY, OTHER_KEY)))),
         'exactly one 32-byte public key'),
        (m1_body((o_str('_pd'), o_bytes(tlv8(STATE_1, (0x03, EPHEMERAL_KEY[:31]))))),
         'exactly one 32-byte public key'),
        (m1_body((o_str('_pd'), o_bytes(tlv8(STATE_1, PUBLIC_KEY) + b'\x19'))),
         'disagrees with its own lengths'),
        (m1_body((o_str('_pd'), o_bytes(tlv8(STATE_1, PUBLIC_KEY) + b'\x19\x05\x01'))),
         'disagrees with its own lengths'),
        (m1_body((o_str('_pd'), o_str('not bytes'))),
         'no _pd byte string'),
        (m1_body((o_str('_pd'), o_bytes(tlv8(STATE_1, PUBLIC_KEY))),
                 (o_str('_pd'), o_bytes(tlv8(STATE_1, OTHER_KEY)))),
         'more than one _pd'),
        (m1_body((o_str('_pd'), o_bytes(tlv8(STATE_1, PUBLIC_KEY))), after=b'\x01'),
         'the object encoding around _pd is incomplete or malformed'),
        # A whole _pd, then an entry the walk stops in at its value limit.
        (m1_body((o_str('_pd'), o_bytes(tlv8(STATE_1, PUBLIC_KEY))),
                 (o_str('x'), b'\xdf' + b'\x01' * 16384 + b'\x03')),
         'the object encoding around _pd is incomplete or malformed'),
    ], ids=['dict-declares-two-holds-one', 'conflicting-state', 'duplicate-state', 'no-state', 'no-public-key', 'two-public-keys', 'short-public-key', 'tlv-header-truncated', 'tlv-value-truncated', 'pd-not-bytes', 'duplicate-pd', 'trailing-byte', 'value-limit-stop-after-pd'])
    def test_malformed_handshakes_name_no_session(self, cmd_tshark, result_file, test_env, m1,
                                                  reason):
        rows = self.session_of(cmd_tshark, result_file, test_env, m1)
        assert rows[0][0] == ''
        assert reason in rows[0][1]
        assert rows[1][2] == 'False'

    def test_an_invalid_handshake_does_not_replace_a_valid_one(self, cmd_tshark, result_file,
                                                               test_env):
        bad = m1_body((o_str('_pd'), o_bytes(tlv8(STATE_1, STATE_2, OTHER_KEY))))
        rows = self.session_of(cmd_tshark, result_file, test_env, pairverify_m1(), bad)
        # The conversation's session is still reported on the invalid message:
        # it is unchanged, not replaced by the other key.
        assert [set(row[0].split('|')) - {''} for row in rows] == [{SESSION}] * 3
        assert 'names no session' in rows[1][1]
        assert rows[2][2] == 'True'

    def test_a_valid_handshake_after_an_invalid_one(self, cmd_tshark, result_file, test_env):
        bad = m1_body((o_str('_pd'), o_bytes(tlv8(STATE_1, STATE_2, OTHER_KEY))))
        rows = self.session_of(cmd_tshark, result_file, test_env, bad, pairverify_m1())
        assert rows[0][0] == '' and rows[1][0] == SESSION and rows[2][2] == 'True'


# --- OPACK resource limits -----------------------------------------------------

OPACK_VALUES_MAX = 16384
OPACK_TEXT_MAX = 1024 * 1024


class TestOpackLimits:
    def walk(self, cmd_tshark, result_file, test_env, *bodies):
        conn = Connection()
        frames = [conn.frame(True, pairverify_m1())]
        for body in bodies:
            # A body longer than an IPv6 packet holds goes in several segments.
            frame = continue_frame(body)
            for at in range(0, len(frame), 60000):
                frames.append(conn.frame(False, frame[at:at + 60000]))
        path = capture_of(result_file, 'limits.pcap', frames)
        output = run_tshark(cmd_tshark, path, test_env,
                            ['-T', 'fields', '-E', 'occurrence=a', '-E', 'aggregator=|',
                             '-e', 'continuity.opack.member', '-e', '_ws.expert.message',
                             '-e', 'continuity.opack.bool', '-e', 'continuity.opack.undecoded'],
                            timeout=300)
        rows = [line.split('\t') for line in output.splitlines()][1:]
        # Only the frames that completed a message.
        return [row for row in rows if row[0] or row[1] or row[2] or row[3]]

    def booleans(self, count):
        return b'\xdf' + b'\x01' * count + b'\x03'

    @pytest.mark.parametrize('count,stopped', [
        (OPACK_VALUES_MAX - 2, False),
        (OPACK_VALUES_MAX - 1, False),   # the array and its entries: exactly the limit
        (OPACK_VALUES_MAX, True),
        (100000, True),
    ])
    def test_the_value_count_limit(self, cmd_tshark, result_file, test_env, count, stopped):
        (row,) = self.walk(cmd_tshark, result_file, test_env, self.booleans(count))
        decoded = len(row[2].split('|')) if row[2] else 0
        if stopped:
            assert 'more than %d values' % OPACK_VALUES_MAX in row[1]
            assert decoded == OPACK_VALUES_MAX - 1
            assert row[3] != ''
        else:
            assert 'values' not in row[1] and decoded == count

    def long_strings(self, extra):
        """A root array of 400-byte strings whose member text ("[i] = <s>")
        totals the text budget exactly, plus `extra` bytes on the last one.
        Long enough that the reference table (4096 entries) and the value
        expansion (1 MiB) are not what stops the walk."""
        budget = OPACK_TEXT_MAX - (256 + 64)
        texts, total, i = [], 0, 0
        while True:
            cost = len('[%d]' % i) + 3 + 400
            if total + cost > budget:
                break
            texts.append(400)
            total += cost
            i += 1
        # Lengthen the last string so the total lands exactly on the budget.
        texts[-1] += budget - total + extra
        body = b'\xdf' + b''.join(b'\x62' + n.to_bytes(2, 'little') + b's' * n for n in texts)
        return body + b'\x03', len(texts)

    @pytest.mark.parametrize('extra,stopped', [(-1, False), (0, False), (1, True)])
    def test_the_text_limit_boundary(self, cmd_tshark, result_file, test_env, extra, stopped):
        body, count = self.long_strings(extra)
        (row,) = self.walk(cmd_tshark, result_file, test_env, body)
        members = row[0].split('|')
        if stopped:
            assert 'generated text exceeds' in row[1]
            assert len(members) == count  # count - 1 values, and the stop
        else:
            assert row[1] == '' and len(members) == count

    @pytest.mark.parametrize('references,stopped', [(254, False), (255, False), (256, True)])
    def test_the_expansion_limit_boundary(self, cmd_tshark, result_file, test_env, references,
                                          stopped):
        # 4096 bytes sent once and referred to: (1 + references) x 4096 bytes
        # of value, which is exactly 1 MiB at 255 references.
        body = b'\xdf' + o_bytes(bytes(4096)) + b'\xa0' * references + b'\x03'
        (row,) = self.walk(cmd_tshark, result_file, test_env, body)
        assert ('exceed 1048576 bytes' in row[1]) == stopped
        if not stopped:
            assert row[1] == '' and len(row[0].split('|')) == 1 + references

    def test_member_text_is_charged_before_it_is_made(self, cmd_tshark, result_file, test_env):
        # A 250-byte key and an array of 5,000 references to one short string:
        # each member's text repeats the key, so the text is ~260 bytes per
        # 1-byte reference.
        key = 'k' * 250
        body = o_dict((o_str(key[:32]), o_str('x')),
                      (b'\x61' + bytes([len(key)]) + key.encode(), b'\xdf' + b'\xa1' * 5000 + b'\x03'))
        (row,) = self.walk(cmd_tshark, result_file, test_env, body)
        members = row[0].split('|')
        assert 'generated text exceeds %d bytes' % OPACK_TEXT_MAX in row[1]
        assert sum(len(m) for m in members) <= OPACK_TEXT_MAX
        assert row[3] != ''

    def test_a_message_after_a_stopped_one_is_whole(self, cmd_tshark, result_file, test_env):
        normal = o_dict((o_str('a'), o_int(1)), (o_str('b'), o_str('ok')))
        rows = self.walk(cmd_tshark, result_file, test_env, self.booleans(OPACK_VALUES_MAX + 5),
                         normal)
        assert 'more than' in rows[0][1]
        assert rows[1][0] == 'a = 1|b = ok' and rows[1][1] == ''

    def test_depth_limit_still_applies(self, cmd_tshark, result_file, test_env):
        nested = b'\xd1' * 17 + o_int(0)
        (row,) = self.walk(cmd_tshark, result_file, test_env, nested)
        assert 'nests deeper than this decode walks' in row[1]

    def test_reference_table_limit_still_applies(self, cmd_tshark, result_file, test_env):
        strings = b'\xdf' + b''.join(o_str('s%d' % i) for i in range(4097)) + b'\x03'
        (row,) = self.walk(cmd_tshark, result_file, test_env, strings)
        assert "reference table's bound of 4096" in row[1]


# --- Framing, pairing and counters, continued ------------------------------------

class TestTransport:
    names = ('continuity.companion.event', 'continuity.companion.xid',
             'continuity.companion.answers', 'continuity.rdlink.counter',
             'continuity.rdlink.read', 'continuity.session', 'continuity.rdlink.unavailable')

    def run(self, cmd_tshark, result_file, test_env, frames, prefs=(), two_pass=True):
        path = capture_of(result_file, 'transport.pcap', frames)
        return fields(cmd_tshark, path, test_env, self.names, keyed(result_file) + tuple(prefs),
                      two_pass)

    def test_different_events_in_one_segment(self, cmd_tshark, result_file, test_env):
        conn = Connection()
        ping = seal(True, 1, envelope('_ping', 2, 2))
        # The answers in the other order of exchange ids, each at the counter
        # its position in the stream gives it.
        answers = seal(False, 0, envelope(None, 3, 2)) + seal(False, 1, envelope(None, 3, 1))
        rows = self.run(cmd_tshark, result_file, test_env, [
            conn.frame(True, pairverify_m1()), conn.frame(True, REQUESTS[0] + ping),
            conn.frame(False, answers)])
        assert rows[1][0] == '_systemInfo|_ping'
        assert rows[1][1] == '0x0000000000000001|0x0000000000000002'
        assert rows[2][1] == '0x0000000000000002|0x0000000000000001'
        assert rows[2][2] == '2|2'

    def test_a_reassembled_message_and_a_whole_one_in_one_frame(self, cmd_tshark, result_file,
                                                                test_env):
        conn = Connection()
        rows = self.run(cmd_tshark, result_file, test_env, [
            conn.frame(True, pairverify_m1()), conn.frame(True, REQUESTS[0][:10]),
            conn.frame(True, REQUESTS[0][10:] + REQUESTS[1])])
        assert rows[2][1] == '0x0000000000000001|0x0000000000000002'
        assert rows[2][3] == '0|1'

    def test_several_split_messages(self, cmd_tshark, result_file, test_env):
        conn = Connection()
        stream = REQUESTS[0] + REQUESTS[1] + REQUESTS[2]
        cuts = [0, 7, 30, 52, 70, 100, len(stream)]
        frames = [conn.frame(True, pairverify_m1())]
        frames += [conn.frame(True, stream[a:b]) for a, b in zip(cuts, cuts[1:])]
        rows = self.run(cmd_tshark, result_file, test_env, frames)
        counters = [c for row in rows for c in row[3].split('|') if c]
        assert counters == ['0', '1', '2']

    def test_reordered_segments(self, cmd_tshark, result_file, test_env):
        conn = Connection()
        m1 = conn.frame(True, pairverify_m1())
        first = conn.frame(True, REQUESTS[0][:20])
        second = conn.frame(True, REQUESTS[0][20:])
        third = conn.frame(True, REQUESTS[1])
        rows = self.run(cmd_tshark, result_file, test_env, [m1, second, first, third],
                        prefs=('tcp.reassemble_out_of_order:TRUE',))
        counters = [c for row in rows for c in row[3].split('|') if c]
        assert counters == ['0', '1']

    def test_a_segment_missing_from_the_capture(self, cmd_tshark, result_file, test_env):
        conn = Connection()
        frames = [conn.frame(True, pairverify_m1()), conn.frame(True, REQUESTS[0])]
        conn.frame(True, REQUESTS[1])                     # sent, not captured
        frames.append(conn.frame(True, REQUESTS[2]))
        rows = self.run(cmd_tshark, result_file, test_env, frames)
        assert rows[2][3] == '2' and rows[2][4] == 'True'

    @pytest.mark.parametrize('missing,read', [(16, True), (17, False)])
    def test_the_counter_search_bound(self, cmd_tshark, result_file, test_env, missing, read):
        conn = Connection()
        late = seal(True, missing, envelope('_systemInfo', 2, 30))
        rows = self.run(cmd_tshark, result_file, test_env, [
            conn.frame(True, pairverify_m1()), conn.frame(True, late),
            conn.frame(True, seal(True, missing + 1, envelope('_systemInfo', 2, 31)))])
        assert rows[1][4] == str(read)
        if read:
            assert rows[1][3] == str(missing) and rows[2][3] == str(missing + 1)

    def test_a_frame_that_fails_authentication(self, cmd_tshark, result_file, test_env):
        conn = Connection()
        broken = REQUESTS[0][:-1] + bytes([REQUESTS[0][-1] ^ 1])
        rows = self.run(cmd_tshark, result_file, test_env, [
            conn.frame(True, pairverify_m1()), conn.frame(True, broken),
            conn.frame(True, REQUESTS[1])])
        assert rows[1][4] == 'False'
        assert rows[1][6] == 'no key for this session authenticated this frame'
        assert rows[2][4] == 'True' and rows[2][3] == '1'

    def test_one_and_two_passes_agree(self, cmd_tshark, result_file, test_env):
        conn = Connection()
        frames = [conn.frame(True, pairverify_m1()), conn.frame(True, REQUESTS[0][:10]),
                  conn.frame(True, REQUESTS[0][10:] + REQUESTS[1]),
                  conn.frame(False, RESPONSES[1] + RESPONSES[0])]
        one = self.run(cmd_tshark, result_file, test_env, frames, two_pass=False)
        two = self.run(cmd_tshark, result_file, test_env, frames)
        # The answer links point back, so they are known on the first pass too.
        assert one == two

    @pytest.mark.parametrize('pd_marker', [0x91, 0x92])
    @pytest.mark.parametrize('first_cut,named', [
        # Header and the "_pd" key: recognised from the first segment.
        pytest.param(9, True, id='cut-at-9-recognised'),
        # LIMITATION, asserted as such: a first segment shorter than that is
        # not recognised, and the connection stays plain TCP until a later
        # segment is exactly tiled (see doc/README.continuity).
        pytest.param(6, False, id='LIMITATION-cut-at-6-not-recognised'),
    ])
    def test_a_fragmented_first_handshake_message(self, cmd_tshark, result_file, test_env,
                                                  first_cut, named, pd_marker):
        conn = Connection()
        m1 = pairverify_m1(pd_marker=pd_marker)
        rows = self.run(cmd_tshark, result_file, test_env, [
            conn.frame(True, m1[:first_cut]), conn.frame(True, m1[first_cut:]),
            conn.frame(True, REQUESTS[0])])
        assert (rows[2][4] == 'True') == named

    def test_a_reordered_first_message_in_one_segment(self, cmd_tshark, result_file, test_env):
        conn = Connection()
        m1 = m1_body((o_str('x'), o_int(1)), (o_str('_pd'), o_bytes(tlv8(STATE_1, PUBLIC_KEY))))
        rows = self.run(cmd_tshark, result_file, test_env,
                        [conn.frame(True, m1), conn.frame(True, REQUESTS[0])])
        assert rows[0][5] == SESSION and rows[1][4] == 'True'

    def test_limitation_a_reordered_and_fragmented_first_message(self, cmd_tshark, result_file,
                                                                 test_env):
        # Neither the "_pd" prefix nor exact tiling is visible in the first
        # segment, so the handshake is not recognised (documented limitation).
        # The next whole frame is still recognised by exact tiling, and says
        # why it cannot be read.
        conn = Connection()
        m1 = m1_body((o_str('x'), o_int(1)), (o_str('_pd'), o_bytes(tlv8(STATE_1, PUBLIC_KEY))))
        rows = self.run(cmd_tshark, result_file, test_env, [
            conn.frame(True, m1[:12]), conn.frame(True, m1[12:]), conn.frame(True, REQUESTS[0])])
        assert rows[0][5] == '' and rows[1][5] == ''
        assert rows[2][4] == 'False'
        assert rows[2][6].startswith("the session's handshake is not in this capture")


# --- Sidecar ---------------------------------------------------------------------

def sidecar_message(inner, outer=None):
    '''{"_i": "com.apple.sidecar", "_t": 2, "_x": 7, "_c": {0: <inner>}}, as observed.'''
    content = outer if outer is not None else o_dict((o_int(0), o_bytes(inner)))
    return envelope('com.apple.sidecar', 2, 7, content)


class TestSidecar:
    names = ('continuity.sidecar.service', 'continuity.sidecar.uninterpreted',
             'continuity.service', 'continuity.sidecar.version', 'continuity.sidecar.nested',
             '_ws.expert.message')

    def dissect(self, cmd_tshark, result_file, test_env, plaintext):
        conn = Connection()
        frames = [conn.frame(True, pairverify_m1()), conn.frame(True, seal(True, 0, plaintext))]
        rows = fields(cmd_tshark, capture_of(result_file, 'sidecar.pcap', frames), test_env,
                      self.names, keyed(result_file))
        return rows[1]

    def test_the_observed_capture_message(self, cmd_tshark, result_file, test_env):
        inner = o_dict((o_int(5), o_str('com.apple.sidecar.capture')), (o_int(2), o_int(3)),
                       (o_int(3), o_int(1)))
        row = self.dissect(cmd_tshark, result_file, test_env, sidecar_message(inner))
        assert row[0] == 'com.apple.sidecar.capture'
        assert row[1] == ''
        assert row[2].split('|') == ['com.apple.sidecar', 'com.apple.sidecar.capture']

    def test_an_unknown_sidecar_sub_service(self, cmd_tshark, result_file, test_env):
        inner = o_dict((o_int(5), o_str('com.apple.sidecar.display')), (o_int(2), o_int(3)))
        row = self.dissect(cmd_tshark, result_file, test_env, sidecar_message(inner))
        assert row[0] == 'com.apple.sidecar.display'
        assert row[1].startswith("this sub-service's objects are not interpreted")
        assert row[2] == 'com.apple.sidecar'

    def body(self, cmd_tshark, result_file, test_env, content):
        conn = Connection()
        frames = [conn.frame(True, pairverify_m1()),
                  conn.frame(True, seal(True, 0, envelope('com.apple.sidecar', 2, 7, content)))]
        return fields(cmd_tshark, capture_of(result_file, 'sidecar-body.pcap', frames), test_env,
                      ('continuity.sidecar.body', 'continuity.sidecar.body_uninterpreted',
                       'continuity.opack.member', 'continuity.sidecar.service'),
                      keyed(result_file))[1]

    # Sidecar Display's messages, as observed: a first nested object under key
    # 0 and a second under key 1, the second holding the message's names.
    HEADER = o_dict((o_int(7), o_uint(0x1234)), (o_int(4), o_uint(0x123c0ecf)))
    BODY = o_dict((o_int(0), o_int(3)),
                  (o_int(1), b'\xd1' + o_dict((o_int(3), o_str('vdisp')), (o_int(2), o_int(8)))))

    def test_a_second_nested_object_is_walked(self, cmd_tshark, result_file, test_env):
        row = self.body(cmd_tshark, result_file, test_env,
                        o_dict((o_int(0), o_bytes(self.HEADER)), (o_int(1), o_bytes(self.BODY))))
        assert row[0] != ''
        assert row[1].startswith('the second nested object is shown as encoded')
        assert 'vdisp' in row[2]

    @pytest.mark.parametrize('content', [
        # Key 1 without the first object before it, and key 1 holding no bytes.
        o_dict((o_int(1), o_bytes(BODY)), (o_int(0), o_bytes(HEADER))),
        o_dict((o_int(0), o_bytes(HEADER)), (o_int(1), o_str('vdisp'))),
    ], ids=['body-before-header', 'body-not-bytes'])
    def test_other_shapes_have_no_second_object(self, cmd_tshark, result_file, test_env,
                                                content):
        row = self.body(cmd_tshark, result_file, test_env, content)
        assert row[0] == '' and row[1] == ''

    def test_a_version_is_not_a_service(self, cmd_tshark, result_file, test_env):
        inner = o_dict((o_int(10), o_str('279')), (o_int(2), o_int(6)))
        row = self.dissect(cmd_tshark, result_file, test_env, sidecar_message(inner))
        assert row[0] == '' and row[3] == '279'

    @pytest.mark.parametrize('value', ['hello', 'com.apple.sidecar.', 'com.apple.sidecar.a b',
                                       'com.apple.sidecarx'])
    def test_other_strings_are_not_services(self, cmd_tshark, result_file, test_env, value):
        inner = o_dict((o_int(5), o_str(value)), (o_int(2), o_int(3)))
        row = self.dissect(cmd_tshark, result_file, test_env, sidecar_message(inner))
        assert row[0] == ''

    def test_a_service_named_first_in_another_entry_is_not_taken(self, cmd_tshark, result_file,
                                                                  test_env):
        # Only key 5 carried the sub-service in every observed message.
        inner = o_dict((o_int(10), o_str('com.apple.sidecar.capture')), (o_int(2), o_int(3)))
        row = self.dissect(cmd_tshark, result_file, test_env, sidecar_message(inner))
        assert row[0] == ''

    def test_a_long_identifier_and_a_long_byte_string(self, cmd_tshark, result_file, test_env):
        name = 'com.apple.sidecar.' + 'x' * 40
        inner = o_dict((o_int(5), o_str(name)), (o_int(4), o_uint(0x123c0ecf)),
                       (o_int(6), o_bytes(bytes(40))))
        assert len(inner) > 32
        row = self.dissect(cmd_tshark, result_file, test_env, sidecar_message(inner))
        assert row[0] == name

    def test_a_service_sent_as_a_reference(self, cmd_tshark, result_file, test_env):
        # The string enters the table at index 0 when first sent in full.
        inner = o_dict((o_int(1), o_str('com.apple.sidecar.capture')), (o_int(5), b'\xa0'))
        row = self.dissect(cmd_tshark, result_file, test_env, sidecar_message(inner))
        assert row[0] == 'com.apple.sidecar.capture'

    @pytest.mark.parametrize('inner', [
        b'',                                                   # empty
        b'\xe3' + o_int(5) + o_str('com.apple.sidecar.capture'),  # truncated dictionary
        b'\xd1' + o_str('com.apple.sidecar.capture'),          # an array, not a dictionary
        o_dict((o_int(5), o_str('com.apple.sidecar.capture'))) + b'\x01',  # trailing byte
    ], ids=['empty', 'dict-short', 'array-not-dict', 'trailing-byte'])
    def test_malformed_or_other_nested_objects_name_nothing(self, cmd_tshark, result_file,
                                                            test_env, inner):
        row = self.dissect(cmd_tshark, result_file, test_env, sidecar_message(inner))
        assert row[0] == ''

    @pytest.mark.parametrize('outer', [
        o_bytes(o_dict((o_int(5), o_str('com.apple.sidecar.capture')))),     # _c is the bytes
        o_dict((o_str('a'), o_bytes(o_dict((o_int(5), o_str('com.apple.sidecar.capture')))))),
    ], ids=['content-is-bytes', 'nested-under-string-key'])
    def test_other_content_shapes_name_nothing(self, cmd_tshark, result_file, test_env, outer):
        row = self.dissect(cmd_tshark, result_file, test_env, sidecar_message(None, outer=outer))
        assert row[0] == '' and row[4] == ''


# --- Test identifiers ------------------------------------------------------------

class TestSuiteHygiene:
    def test_collected_ids_are_bounded(self, request):
        # pytest puts a test's id into PYTEST_CURRENT_TEST, and Windows refuses
        # an environment value over 32,767 characters; a binary fixture spelled
        # out in its id once exceeded that. Every case here has a short id.
        ids = [item.nodeid for item in request.session.items
               if item.nodeid.startswith(request.node.nodeid.split('::')[0])]
        assert ids
        too_long = [i[:120] for i in ids if len(i) > 200]
        unreadable = [i[:120] for i in ids if not i.isascii() or '\\x' in i]
        assert not too_long and not unreadable, (too_long, unreadable)
        assert len(ids) == len(set(ids))


# --- Control messages that must not change state -------------------------------

def declares_one_more(plaintext):
    '''The same object with its outer dictionary declaring one more entry than
    it holds (a counted dictionary marker, 0xe1..0xee).'''
    assert 0xe0 < plaintext[0] < 0xef
    return bytes([plaintext[0] + 1]) + plaintext[1:]


def stream_start_with(xid, content_pairs, envelope_pairs=None):
    pairs = envelope_pairs if envelope_pairs is not None else [
        (o_str('_i'), o_str('_streamStart')), (o_str('_t'), o_int(2)), (o_str('_x'), o_uint(xid))]
    return o_dict(*(pairs + [(o_str('_c'), o_dict(*content_pairs))]))


def video_request_pairs(port=40000, addr=PHONE_STREAM_ADDR):
    return [(o_str('_streamID'), o_str(VIDEO)), (o_str('_streamType'), o_int(3)),
            (o_str('_streamAddr'), o_str(addr)), (o_str('_streamPort'), o_uint(port))]


LIMIT_TAIL = (o_str('pad'), b'\xdf' + b'\x01' * 16384 + b'\x03')


# Requests the decoder must show but not act on. Each keeps the stream entries
# a negotiation needs, so only the defect named in its id makes it unusable.
UNUSABLE_REQUESTS = [
    pytest.param(declares_one_more(stream_start(5, VIDEO, 40000, PHONE_STREAM_ADDR)),
                 'the dictionary declares 5 entries', False, id='declares-five-holds-four'),
    pytest.param(stream_start(5, VIDEO, 40000, PHONE_STREAM_ADDR) + b'\x01',
                 'bytes follow the object', False, id='trailing-byte'),
    pytest.param(o_dict((o_str('_i'), o_str('_streamStart')), (o_str('_t'), o_int(2)),
                        (o_str('_x'), o_uint(5)),
                        (o_str('_c'), b'\xe5' + b''.join(k + v for k, v in video_request_pairs()))),
                 'the dictionary declares 5 entries and the body ends after 4', False,
                 id='nested-dict-short'),
    pytest.param(stream_start_with(5, video_request_pairs() + [LIMIT_TAIL]),
                 'more than 16384 values', False, id='value-limit-after-stream-fields'),
    pytest.param(stream_start_with(5, video_request_pairs(), [
        (o_str('_i'), o_str('_streamStart')), (o_str('_t'), o_str('2')), (o_str('_x'), o_uint(5))]),
                 "the envelope's _t is a string", False, id='kind-is-string'),
    pytest.param(stream_start_with(5, video_request_pairs(), [
        (o_str('_i'), o_str('_streamStart')), (o_str('_t'), o_int(2)), (o_str('_x'), o_uint(5)),
        (o_str('_x'), o_uint(9))]), 'carries _x more than once', False, id='duplicate-xid'),
    pytest.param(stream_start_with(5, video_request_pairs() + [(o_str('_streamPort'), o_uint(40004))]),
                 '_c carries _streamPort more than once', True, id='duplicate-stream-port'),
    pytest.param(stream_start_with(5, [(o_str('_streamID'), o_str(VIDEO)),
                                       (o_str('_streamType'), o_str('3')),
                                       (o_str('_streamAddr'), o_str(PHONE_STREAM_ADDR)),
                                       (o_str('_streamPort'), o_uint(40000))]),
                 '_streamType is not an integer', True, id='stream-type-string'),
]


def answer_with(xid, content_pairs, envelope_pairs=None):
    pairs = envelope_pairs if envelope_pairs is not None else [
        (o_str('_t'), o_int(3)), (o_str('_x'), o_uint(xid))]
    return o_dict(*(pairs + [(o_str('_c'), o_dict(*content_pairs))]))


ANSWER_PAIRS = [(o_str('_streamAddr'), o_str(MAC_STREAM_ADDR)), (o_str('_streamPort'), o_uint(40002))]

UNUSABLE_ANSWERS = [
    pytest.param(declares_one_more(stream_answer(5, 40002, MAC_STREAM_ADDR)),
                 'the dictionary declares 4 entries', id='declares-four-holds-three'),
    pytest.param(stream_answer(5, 40002, MAC_STREAM_ADDR) + b'\x01', 'bytes follow the object',
                 id='trailing-byte'),
    pytest.param(answer_with(5, ANSWER_PAIRS + [LIMIT_TAIL]), 'more than 16384 values',
                 id='value-limit-after-stream-fields'),
    pytest.param(answer_with(5, ANSWER_PAIRS, [(o_str('_t'), o_int(3)), (o_str('_x'), o_uint(5)),
                                               (o_str('_t'), o_int(2))]),
                 'carries _t more than once', id='duplicate-kind'),
]


class TestControlState:
    names = ('frame.number', 'frame.protocols', 'continuity.media.negotiated_in',
             'continuity.companion.answers', 'continuity.companion.answered_in',
             'continuity.companion.unpaired', '_ws.expert.message', 'continuity.rdlink.read')

    def rows(self, cmd_tshark, result_file, test_env, frames, two_pass=True):
        path = capture_of(result_file, 'control-state.pcap', frames)
        return {int(r[0]): r for r in fields(cmd_tshark, path, test_env, self.names,
                                             keyed(result_file), two_pass)}

    def media(self, ports=(40000, 40002), seq=1):
        return udp_frame(addr6(PHONE_STREAM_ADDR), ports[0], addr6(MAC_STREAM_ADDR), ports[1],
                         rtp_packet(100, seq, seq * 800))

    def later_valid_negotiation(self, ends, counters):
        # A different exchange and different ports, right after the rejected
        # input: it must negotiate as if nothing had happened before it.
        return negotiate(ends, counters[0], counters[1],
                         stream_start(7, VIDEO, 41000, PHONE_STREAM_ADDR),
                         stream_answer(7, 41002, MAC_STREAM_ADDR)) + [self.media((41000, 41002))]

    @pytest.mark.parametrize('request_body,reason,content_level', UNUSABLE_REQUESTS)
    def test_an_unusable_request_negotiates_nothing(self, cmd_tshark, result_file, test_env,
                                                    request_body, reason, content_level):
        # Envelope-level defects (an incomplete object, a conflicting or
        # mistyped _x/_t/_i/_c) leave the message out of exchange pairing
        # altogether. Content-level defects (a stream entry repeated or of the
        # wrong type inside an otherwise sound envelope) still pair -- the
        # correlation is sound -- but negotiate nothing.
        ends = Endpoints()
        frames = [ends.tcp(True, pairverify_m1()),                                    # 1
                  *negotiate(ends, 0, 0, request_body, stream_answer(5, 40002, MAC_STREAM_ADDR)),  # 2, 3
                  self.media(),                                                       # 4
                  *self.later_valid_negotiation(ends, (1, 1))]                        # 5, 6, 7
        for two_pass in (False, True):
            rows = self.rows(cmd_tshark, result_file, test_env, frames, two_pass)
            # The effects first: no flow, and the exchange handled as defined.
            assert 'continuity.media' not in rows[4][1], ('negotiated anyway', rows[4])
            if content_level:
                assert rows[3][3] == '2'
            else:
                assert rows[3][3] == '', 'the answer must not pair with the rejected request'
            assert rows[7][2] == '6', 'a later valid negotiation is unaffected'
            # Then that it is still shown, and says why.
            assert rows[2][7] == 'True', 'the request decrypted and is shown'
            assert reason in rows[2][6], rows[2][6]
            assert 'This _streamStart is not taken as part of a stream negotiation' in rows[2][6]
            if not content_level:
                assert 'not paired and not recorded' in rows[2][5]

    @pytest.mark.parametrize('answer_body,reason', UNUSABLE_ANSWERS)
    def test_an_unusable_answer_neither_completes_nor_consumes(self, cmd_tshark, result_file,
                                                               test_env, answer_body, reason):
        ends = Endpoints()
        frames = [ends.tcp(True, pairverify_m1()),                                    # 1
                  *negotiate(ends, 0, 0, stream_start(5, VIDEO, 40000, PHONE_STREAM_ADDR),
                             answer_body),                                            # 2, 3
                  self.media(seq=1),                                                  # 4
                  ends.tcp(True, seal(True, 1, stream_answer(5, 40002, MAC_STREAM_ADDR))),  # 5
                  self.media(seq=2),                                                  # 6
                  *self.later_valid_negotiation(ends, (1, 2))]                        # 7, 8, 9
        for two_pass in (False, True):
            rows = self.rows(cmd_tshark, result_file, test_env, frames, two_pass)
            assert 'continuity.media' not in rows[4][1], ('completed by frame 3', rows[4])
            assert rows[3][3] == '', ('frame 3 consumed the exchange', rows[3])
            assert rows[5][3] == '2', 'the open exchange is still answered by the valid answer'
            assert rows[6][2] == '5'
            assert rows[9][2] == '8'
            assert reason in rows[3][5] + rows[3][6], rows[3]
            assert 'not paired and not recorded' in rows[3][5]

    def test_an_answer_with_conflicting_stream_entries(self, cmd_tshark, result_file, test_env):
        # A sound envelope whose content repeats _streamPort: it is the
        # exchange's answer, so it pairs and closes the exchange, but which port
        # was meant is not knowable, so nothing is negotiated -- and a later
        # second answer to the same exchange is not taken either.
        ends = Endpoints()
        conflicting = answer_with(5, ANSWER_PAIRS + [(o_str('_streamPort'), o_uint(40006))])
        frames = [ends.tcp(True, pairverify_m1()),                                    # 1
                  *negotiate(ends, 0, 0, stream_start(5, VIDEO, 40000, PHONE_STREAM_ADDR),
                             conflicting),                                            # 2, 3
                  self.media(seq=1),                                                  # 4
                  udp_frame(addr6(PHONE_STREAM_ADDR), 40000, addr6(MAC_STREAM_ADDR), 40006,
                            rtp_packet(100, 2, 1600)),                                # 5
                  ends.tcp(True, seal(True, 1, stream_answer(5, 40002, MAC_STREAM_ADDR))),  # 6
                  self.media(seq=3),                                                  # 7
                  *self.later_valid_negotiation(ends, (1, 2))]                        # 8, 9, 10
        rows = self.rows(cmd_tshark, result_file, test_env, frames)
        assert all('continuity.media' not in rows[n][1] for n in (4, 5, 7)), \
            [rows[n][1] for n in (4, 5, 7)]
        assert rows[3][3] == '2' and rows[6][3] == ''
        assert rows[10][2] == '9'
        assert '_c carries _streamPort more than once' in rows[3][6]

    def test_a_rejected_repeat_of_an_open_exchange_id_changes_nothing(self, cmd_tshark,
                                                                      result_file, test_env):
        # A malformed message reusing the open exchange's id from the same side
        # would otherwise mark the exchange ambiguous and leave it unanswered.
        ends = Endpoints()
        bad = declares_one_more(stream_start(5, VIDEO, 40008, PHONE_STREAM_ADDR))
        frames = [ends.tcp(True, pairverify_m1()),                                    # 1
                  ends.tcp(False, seal(False, 0, stream_start(5, VIDEO, 40000, PHONE_STREAM_ADDR))),  # 2
                  ends.tcp(False, seal(False, 1, bad)),                               # 3
                  ends.tcp(True, seal(True, 0, stream_answer(5, 40002, MAC_STREAM_ADDR))),  # 4
                  self.media()]                                                       # 5
        rows = self.rows(cmd_tshark, result_file, test_env, frames)
        assert rows[4][3] == '2' and rows[2][4] == '4'
        assert rows[5][2] == '4'

    def test_rejected_and_valid_messages_in_one_segment(self, cmd_tshark, result_file, test_env):
        ends = Endpoints()
        bad = declares_one_more(stream_start(5, VIDEO, 40000, PHONE_STREAM_ADDR))
        frames = [ends.tcp(True, pairverify_m1()),                                    # 1
                  ends.tcp(False, seal(False, 0, bad) +
                           seal(False, 1, stream_start(6, VIDEO, 40010, PHONE_STREAM_ADDR))),  # 2
                  ends.tcp(True, seal(True, 0, stream_answer(5, 40002, MAC_STREAM_ADDR)) +
                           seal(True, 1, stream_answer(6, 40012, MAC_STREAM_ADDR))),  # 3
                  self.media(),                                                       # 4
                  self.media((40010, 40012))]                                         # 5
        rows = self.rows(cmd_tshark, result_file, test_env, frames)
        assert 'continuity.media' not in rows[4][1]
        assert rows[5][2] == '3'

    def test_a_rejected_answer_is_stable_across_revisits(self, cmd_sharkd, result_file,
                                                         base_env):
        ends = Endpoints()
        frames = [ends.tcp(True, pairverify_m1()),
                  *negotiate(ends, 0, 0, stream_start(5, VIDEO, 40000, PHONE_STREAM_ADDR),
                             declares_one_more(stream_answer(5, 40002, MAC_STREAM_ADDR))),
                  self.media(seq=1),
                  ends.tcp(True, seal(True, 1, stream_answer(5, 40002, MAC_STREAM_ADDR))),
                  self.media(seq=2)]
        path = capture_of(result_file, 'control-revisits.pcap', frames)
        order = [6, 4, 3, 6, 4]
        replies = sharkd_frames(cmd_sharkd, base_env, path, shared_keylog(result_file), order)
        for frame, reply in zip(order, replies):
            if frame == 6:
                assert 'Negotiated in: 5' in reply
            elif frame == 4:
                assert 'Continuity Media' not in reply
            else:
                assert 'not paired and not recorded' in reply


# --- Ambiguous media and RTP's payload mapping ---------------------------------

def stream_names(output):
    '''(source, destination, payload names) per line of `-z rtp,streams`.'''
    streams = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) > 7 and parts[2].count(':') and parts[3].isdigit():
            streams.append((parts[2], parts[4], line))
    return streams


class TestAmbiguousBindings:
    names = ('frame.number', 'frame.protocols', 'continuity.media.ambiguous',
             'continuity.media.payload_binding', 'continuity.media.negotiated_in',
             'continuity.media.stream_id', 'rtp.p_type', 'rtp.setup-frame')

    def negotiations(self, first, second):
        ends = Endpoints()
        return ends, [ends.tcp(True, pairverify_m1()),
                      *negotiate(ends, 0, 0, stream_start(5, first, 40000, PHONE_STREAM_ADDR),
                                 stream_answer(5, 40002, MAC_STREAM_ADDR)),
                      *negotiate(ends, 1, 1, stream_start(6, second, 40000, PHONE_STREAM_ADDR),
                                 stream_answer(6, 40002, MAC_STREAM_ADDR))]

    def forward(self, payload):
        return udp_frame(addr6(PHONE_STREAM_ADDR), 40000, addr6(MAC_STREAM_ADDR), 40002, payload)

    def backward(self, payload):
        return udp_frame(addr6(MAC_STREAM_ADDR), 40002, addr6(PHONE_STREAM_ADDR), 40000, payload,
                         src_mac=INITIATOR[0], dst_mac=RESPONDER[0])

    def dissect(self, cmd_tshark, result_file, test_env, frames, two_pass=True):
        path = capture_of(result_file, 'ambiguous.pcap', frames)
        rows = {int(r[0]): r for r in fields(cmd_tshark, path, test_env, self.names,
                                             keyed(result_file), two_pass)}
        return path, rows

    @pytest.mark.parametrize('first,second,binding', [
        pytest.param(VIDEO, MICROPHONE, 'none: the negotiations that fit bind it differently',
                     id='video-vs-unknown'),
        pytest.param(VIDEO, DESKCAM, 'payload type 100 at 24000 Hz, as every negotiation',
                     id='same-binding-different-names'),
        pytest.param(MICROPHONE, OTHER_STREAM, 'none: no negotiation that fits has an observed',
                     id='unknown-vs-unknown'),
    ])
    def test_media_after_both_negotiations(self, cmd_tshark, result_file, test_env, first,
                                           second, binding):
        _, frames = self.negotiations(first, second)
        frames += [self.forward(RTCP_RR),                                   # 6: RTCP first
                   self.forward(rtp_packet(100, 1, 800)),                   # 7
                   self.forward(rtp_packet(101, 2, 1600)),                  # 8
                   self.backward(rtp_packet(101, 1, 800, ssrc=0x55667788))]  # 9
        path, rows = self.dissect(cmd_tshark, result_file, test_env, frames)
        for n in (6, 7, 8, 9):
            assert 'rtpevent' not in rows[n][1], ('read as telephone events', n, rows[n][1])
        assert rows[7][7] == rows[8][7] == '6', 'one RTP setup for the forward conversation'
        for n in (6, 7, 8, 9):
            assert rows[n][2].startswith('2 negotiations fit'), rows[n]
            assert rows[n][5] == '' and rows[n][4] == '', 'no stream or negotiation is claimed'
            assert rows[n][3].startswith(binding), rows[n][3]
        names = run_tshark(cmd_tshark, path, test_env,
                           ['-q', '-z', 'rtp,streams', '-o', keyed(result_file)[0]])
        assert 'rtpevent' not in names
        if binding.startswith('none'):
            assert 'clock rate unknown' in names
        else:
            assert 'Continuity media (opaque payload)' in names

    def test_a_second_negotiation_after_media_started(self, cmd_tshark, cmd_sharkd, result_file,
                                                      test_env, base_env):
        ends = Endpoints()
        frames = [ends.tcp(True, pairverify_m1()),                                    # 1
                  *negotiate(ends, 0, 0, stream_start(5, VIDEO, 40000, PHONE_STREAM_ADDR),
                             stream_answer(5, 40002, MAC_STREAM_ADDR)),               # 2, 3
                  self.forward(rtp_packet(100, 1, 800)),                              # 4
                  *negotiate(ends, 1, 1, stream_start(6, MICROPHONE, 40000, PHONE_STREAM_ADDR),
                             stream_answer(6, 40002, MAC_STREAM_ADDR)),               # 5, 6
                  self.forward(rtp_packet(100, 2, 1600)),                             # 7
                  self.forward(rtp_packet(101, 3, 2400))]                             # 8
        path, rows = self.dissect(cmd_tshark, result_file, test_env, frames)
        _, one_pass = self.dissect(cmd_tshark, result_file, test_env, frames, two_pass=False)
        assert rows == one_pass
        assert rows[4][5] == VIDEO and rows[4][4] == '3' and rows[4][2] == ''
        for n in (7, 8):
            assert 'rtpevent' not in rows[n][1], ('read as telephone events', n, rows[n][1])
            assert rows[n][7] == '7', ('not re-read opaque from the ambiguity', n, rows[n][7])
        assert rows[4][3] == 'payload type 100 at 24000 Hz' and rows[4][7] == '4'
        for n in (7, 8):
            assert rows[n][2].startswith('2 negotiations fit')
            assert rows[n][3].startswith('none: the negotiations that fit bind it differently')
        replies = sharkd_frames(cmd_sharkd, base_env, path, shared_keylog(result_file),
                                [8, 4, 7, 4])
        assert 'Negotiated in: 3' in replies[1] and 'Negotiated in: 3' in replies[3]
        assert 'Ambiguous' in replies[0] and 'Ambiguous' in replies[2]


class TestAlternatePaths:
    '''One negotiation allows each end its announced address and its control
    address. RTP is set up per actual transport conversation, so each of them
    needs its own setup, once.'''
    names = ('frame.number', 'frame.protocols', 'continuity.media.stream_id',
             'continuity.media.negotiated_in', 'rtp.setup-frame', 'rtp.p_type')

    def session(self, stream_id):
        ends = Endpoints()
        return [ends.tcp(True, pairverify_m1()),
                *negotiate(ends, 0, 0, stream_start(5, stream_id, 40000, PHONE_STREAM_ADDR),
                           stream_answer(5, 40002, MAC_STREAM_ADDR))]

    # The phone sends from its announced address; the Mac is reached at its
    # announced address (path A) or at its control address (path B).
    def to_a(self, payload):
        return udp_frame(addr6(PHONE_STREAM_ADDR), 40000, addr6(MAC_STREAM_ADDR), 40002, payload)

    def to_b(self, payload):
        return udp_frame(addr6(PHONE_STREAM_ADDR), 40000, INITIATOR[1], 40002, payload)

    def from_mac_to_a(self, payload):
        return udp_frame(addr6(MAC_STREAM_ADDR), 40002, addr6(PHONE_STREAM_ADDR), 40000, payload,
                         src_mac=INITIATOR[0], dst_mac=RESPONDER[0])

    def from_mac_to_b(self, payload):
        return udp_frame(addr6(MAC_STREAM_ADDR), 40002, RESPONDER[1], 40000, payload,
                         src_mac=INITIATOR[0], dst_mac=RESPONDER[0])

    def dissect(self, cmd_tshark, result_file, test_env, frames, two_pass=True):
        path = capture_of(result_file, 'paths.pcap', frames)
        rows = {int(r[0]): r for r in fields(cmd_tshark, path, test_env, self.names,
                                             keyed(result_file), two_pass)}
        return path, rows

    def test_both_paths_and_back_with_a_bound_stream(self, cmd_tshark, result_file, test_env):
        frames = self.session(VIDEO)
        frames += [self.to_a(rtp_packet(100, 1, 400)),       # 4  path A
                   self.to_b(rtp_packet(100, 1, 400)),       # 5  path B, first time
                   self.to_a(rtp_packet(100, 2, 800)),       # 6  back to A
                   self.to_b(rtp_packet(100, 2, 800)),       # 7
                   self.to_a(rtp_packet(100, 3, 1200, ssrc=0x99)),  # 8  new SSRC on A
                   self.to_a(rtp_packet(101, 4, 1600))]      # 9  a type not bound on A
        path, rows = self.dissect(cmd_tshark, result_file, test_env, frames)
        _, one_pass = self.dissect(cmd_tshark, result_file, test_env, frames, two_pass=False)
        assert rows == one_pass
        assert all(rows[n][2] == VIDEO and rows[n][3] == '3' for n in range(4, 10))
        assert [rows[n][4] for n in (4, 6, 8, 9)] == ['4'] * 4, 'path A set up once'
        assert [rows[n][4] for n in (5, 7)] == ['5'] * 2, 'path B set up once, on its own'
        assert all('rtpevent' not in rows[n][1] for n in range(4, 10))
        streams = run_tshark(cmd_tshark, path, test_env,
                             ['-q', '-z', 'rtp,streams', '-o', keyed(result_file)[0]])
        to_b = [line for line in streams.splitlines() if 'fe80::1 ' in line]
        assert to_b and 'Continuity media (opaque payload)' in to_b[0], streams
        assert 'clock rate unknown' in streams, 'the unbound type on A stays opaque'

    def test_both_paths_with_an_unbound_stream_and_rtcp_first(self, cmd_tshark, result_file,
                                                              test_env):
        frames = self.session(MICROPHONE)
        frames += [self.to_b(RTCP_RR),                       # 4  RTCP first on B
                   self.to_b(rtp_packet(101, 1, 480)),       # 5
                   self.to_a(rtp_packet(101, 1, 480)),       # 6
                   self.from_mac_to_b(RTCP_RR),              # 7  the other direction, B
                   self.from_mac_to_a(rtp_packet(101, 1, 480, ssrc=0x77)),  # 8
                   self.to_b(rtp_packet(101, 2, 960))]       # 9
        path, rows = self.dissect(cmd_tshark, result_file, test_env, frames)
        assert all(rows[n][2] == MICROPHONE for n in range(4, 10))
        assert all('rtpevent' not in rows[n][1] for n in range(4, 10)), \
            [rows[n][1] for n in range(4, 10)]
        assert rows[5][4] == rows[9][4] == '4', 'B set up once, at its RTCP'
        assert rows[6][4] == '6' and rows[8][4] == '8'
        streams = run_tshark(cmd_tshark, path, test_env,
                             ['-q', '-z', 'rtp,streams', '-o', keyed(result_file)[0]])
        assert 'rtpevent' not in streams and streams.count('clock rate unknown') >= 3, streams

    def test_unrelated_addresses_on_the_same_ports(self, cmd_tshark, result_file, test_env):
        frames = self.session(VIDEO)
        frames += [self.to_a(rtp_packet(100, 1, 400)),
                   udp_frame(addr6('fd00::77'), 40000, addr6(MAC_STREAM_ADDR), 40002,
                             rtp_packet(100, 1, 400)),
                   udp_frame(addr6(PHONE_STREAM_ADDR), 40000, addr6('fd00::78'), 40002,
                             rtp_packet(100, 1, 400))]
        _, rows = self.dissect(cmd_tshark, result_file, test_env, frames)
        assert rows[4][2] == VIDEO
        assert 'continuity' not in rows[5][1] and 'continuity' not in rows[6][1]


# --- Stream sub-connections recognised from their negotiation -------------------

def stream_request(xid, stream_id):
    return envelope('_streamStart', 2, xid, o_dict((o_str('_streamID'), o_str(stream_id)),
                                                   (o_str('_streamType'), o_int(2))))


def big_frame(from_initiator=True):
    # A first frame of several kilobytes, as Universal Control's streams send,
    # sealed with the shared secret as a stream's pre-shared key would be.
    return seal(from_initiator, 0, envelope('SYNC', 2, 1, o_dict((o_str('pad'), o_bytes(b'u' * 3000)))))


class TestStreamRecognition:
    names = ('frame.number', 'frame.protocols', 'continuity.rdlink.type', 'continuity.rdlink.read')

    def control(self, xid=8, port=50300, with_negotiation=True):
        ends = Endpoints()
        frames = [ends.tcp(True, pairverify_m1())]                                    # 1
        if with_negotiation:
            # The phone (the control connection's responder) asks for a TCP
            # stream; the Mac answers with the port the phone connects to.
            frames += negotiate(ends, 0, 0, stream_request(xid, 'SYNC:uc'),
                                envelope(None, 3, xid, o_dict((o_str('_streamPort'), o_uint(port)))))
        return frames                                                                  # 2, 3

    def sub_connection(self, src=RESPONDER, port=50300, sport=61000, cut=(1000, 2000)):
        # The phone connects to the Mac; the first frame arrives in three segments.
        ends = Endpoints(initiator=src, responder=INITIATOR, ports=(sport, port))
        payload = big_frame()
        return [ends.tcp(True, payload[:cut[0]]), ends.tcp(True, payload[cut[0]:cut[1]]),
                ends.tcp(True, payload[cut[1]:])]

    def dissect(self, cmd_tshark, result_file, test_env, frames, two_pass=True):
        path = capture_of(result_file, 'streams.pcap', frames)
        log = keylog(result_file, ['RDLINK_SHARED %s %s' % (SESSION, SHARED_SECRET.hex()),
                                   'RDLINK_SHARED %s %s' % ('0' * 64, SHARED_SECRET.hex())])
        return {int(r[0]): r for r in fields(cmd_tshark, path, test_env, self.names,
                                             ('continuity.keylog_file:' + log,), two_pass)}

    def test_a_negotiated_stream_is_read_from_its_first_frame(self, cmd_tshark, result_file,
                                                              test_env):
        frames = self.control() + self.sub_connection()                               # 4, 5, 6
        for two_pass in (False, True):
            rows = self.dissect(cmd_tshark, result_file, test_env, frames, two_pass)
            assert 'continuity.rdlink' in rows[6][1], rows[6]
            assert rows[6][2] == '0x08' and rows[6][3] == 'True'

    @pytest.mark.parametrize('case', ['no-negotiation', 'other-address', 'before-negotiation',
                                      'second-connection'])
    def test_unnegotiated_connections_are_not_claimed(self, cmd_tshark, result_file, test_env,
                                                      case):
        if case == 'no-negotiation':
            frames = self.control(with_negotiation=False) + self.sub_connection()     # 2, 3, 4
            check = [2, 3, 4]
        elif case == 'other-address':
            stranger = (bytes.fromhex('020000000009'),
                        bytes.fromhex('fe800000000000000000000000000009'))
            frames = self.control() + self.sub_connection(src=stranger)               # 4, 5, 6
            check = [4, 5, 6]
        elif case == 'before-negotiation':
            # The whole connection precedes the answer that would expect it.
            frames = self.sub_connection() + self.control()                           # 1-3, 4-6
            check = [1, 2, 3]
        else:
            # One negotiation, one connection: a second connection to the same
            # port is not taken on the strength of the same answer.
            frames = (self.control() + self.sub_connection() +
                      self.sub_connection(sport=61002))                               # 7, 8, 9
            check = [7, 8, 9]
        rows = self.dissect(cmd_tshark, result_file, test_env, frames)
        for n in check:
            assert 'continuity' not in rows[n][1], (n, rows[n][1])
