#
# Tests for the Apple Continuity dissectors
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Apple Continuity tests.

Every frame here is synthetic and built by this file: the addresses, the
handshake's ephemeral key and the shared secret are made-up values, so no
capture of a real device is needed and none is committed. The two protected
bodies were sealed once with an independent ChaCha20-Poly1305 implementation
(Python's `cryptography`) under keys derived from SHARED_SECRET, and are
embedded as bytes; the derivation itself is recomputed below with the standard
library, so a key log naming the direction keys and one naming only the shared
secret are both checked against the same frames.
'''

import hashlib
import hmac
import struct
import subprocess

import pytest

# The handshake's cleartext ephemeral public key names the session.
EPHEMERAL_KEY = bytes(range(0xa0, 0xc0))
SHARED_SECRET = bytes(range(0x40, 0x60))

# {"_i": "_systemInfo", "_t": 2, "_x": 7, "_c": {}} from the initiator, sealed
# under the client key at counter 0, and the same with "_t": 3 from the
# responder under the server key.
SEALED_REQUEST = bytes.fromhex(
    '0800002ce77eeacc1ad43b674d18114691dcbff5dd2a0133139fe4ad0468e943'
    'cc031e4d75c07a0768cee22827d90c71')
SEALED_RESPONSE = bytes.fromhex(
    '0800002cf89d56d33dea67c8fdf6f827906ede4d2228599b107c664b5111a855'
    '1e2cf5e6517a338b3cfa01f2b46606f9')

LINKTYPE_ETHERNET = 1
LINKTYPE_IEEE802_11 = 105
LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR = 201

INITIATOR = (bytes.fromhex('020000000001'), bytes.fromhex('fe800000000000000000000000000001'))
RESPONDER = (bytes.fromhex('020000000002'), bytes.fromhex('fe800000000000000000000000000002'))


def hkdf_sha512(secret, label):
    '''One expand block of HKDF-SHA-512 with an empty salt.'''
    prk = hmac.new(b'\x00' * 64, secret, hashlib.sha512).digest()
    return hmac.new(prk, label + b'\x01', hashlib.sha512).digest()[:32]


def write_pcap(path, linktype, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for number, frame in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000, number * 1000, len(frame), len(frame)))
            f.write(frame)


def checksum(data):
    if len(data) % 2:
        data += b'\x00'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return ~total & 0xffff


def tcp_over_ipv6(src, dst, sport, dport, seq, ack, payload):
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, 0x18, 0xffff, 0, 0)
    pseudo = src + dst + struct.pack('!IxxxB', len(tcp) + len(payload), 6)
    tcp = tcp[:16] + struct.pack('!H', checksum(pseudo + tcp + payload)) + tcp[18:]
    ipv6 = struct.pack('!IHBB', 6 << 28, len(tcp) + len(payload), 6, 64) + src + dst
    return ipv6 + tcp + payload


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


def pairverify_m1():
    '''The handshake's first message: {"_pd": <TLV8 State=1, PublicKey, Flags=1>}.'''
    tlv8 = b'\x06\x01\x01' + b'\x03\x20' + EPHEMERAL_KEY + b'\x19\x01\x01'
    body = b'\xe1\x43_pd' + b'\x91' + bytes([len(tlv8)]) + tlv8
    return b'\x05' + len(body).to_bytes(3, 'big') + body


def rdlink_session():
    '''The handshake's first message and one protected exchange, as
    (sender, receiver, IPv6 packet).'''
    m1 = pairverify_m1()
    return [
        (INITIATOR, RESPONDER,
         tcp_over_ipv6(INITIATOR[1], RESPONDER[1], 51000, 52000, 1000, 5000, m1)),
        (INITIATOR, RESPONDER,
         tcp_over_ipv6(INITIATOR[1], RESPONDER[1], 51000, 52000, 1000 + len(m1), 5000,
                       SEALED_REQUEST)),
        (RESPONDER, INITIATOR,
         tcp_over_ipv6(RESPONDER[1], INITIATOR[1], 52000, 51000, 5000,
                       1000 + len(m1) + len(SEALED_REQUEST), SEALED_RESPONSE)),
    ]


@pytest.fixture
def rdlink_capture(result_file):
    path = result_file('continuity-rdlink.pcap')
    write_pcap(path, LINKTYPE_ETHERNET,
               [over_ethernet(src[0], dst[0], ipv6) for src, dst, ipv6 in rdlink_session()])
    return path


@pytest.fixture
def rdlink_over_awdl_capture(result_file):
    path = result_file('continuity-rdlink-awdl.pcap')
    write_pcap(path, LINKTYPE_IEEE802_11,
               [over_awdl(src[0], dst[0], ipv6, seq)
                for seq, (src, dst, ipv6) in enumerate(rdlink_session())])
    return path


@pytest.fixture
def advertisement_capture(result_file):
    '''A received LE advertising report carrying Apple manufacturer data.'''
    apple = (b'\x4c\x00'
             + b'\x10\x05\x01\x18\x11\x22\x33'       # Nearby Info
             + b'\x0c\x0e' + bytes(range(1, 15)))    # Handoff
    data = b'\x02\x01\x06' + bytes([len(apple) + 1, 0xff]) + apple
    report = (b'\x02\x01\x00\x01' + bytes.fromhex('0100000000c0')
              + bytes([len(data)]) + data + b'\xc4')
    event = b'\x04\x3e' + bytes([len(report)]) + report
    path = result_file('continuity-ble.pcap')
    write_pcap(path, LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR, [struct.pack('!I', 1) + event])
    return path


def keylog(result_file, lines):
    path = result_file('continuity.keylog')
    with open(path, 'w') as f:
        f.write(''.join(line + '\n' for line in lines))
    return path


def shared_keylog(result_file):
    return keylog(result_file, ['RDLINK_SHARED %s %s' % (EPHEMERAL_KEY.hex(), SHARED_SECRET.hex())])


def fields(cmd_tshark, capture, env, names, prefs=()):
    command = [cmd_tshark, '-2', '-r', capture, '-T', 'fields', '-E', 'occurrence=a']
    for pref in prefs:
        command += ['-o', pref]
    for name in names:
        command += ['-e', name]
    stdout = subprocess.check_output(command, encoding='utf-8', env=env)
    return [line.split('\t') for line in stdout.splitlines()]


class TestContinuityRegistration:
    def test_dissectors_are_built_in(self, cmd_tshark, test_env):
        protocols = subprocess.check_output((cmd_tshark, '-G', 'protocols'),
                                            encoding='utf-8', env=test_env)
        filters = {line.split('\t')[2] for line in protocols.splitlines() if line.count('\t') >= 2}
        for name in ('continuity', 'continuity.ble', 'continuity.rdlink', 'continuity.companion',
                     'continuity.opack', 'continuity.media', 'continuity.sidecar'):
            assert name in filters

    def test_editcap_can_inject_continuity_keys(self, cmd_editcap, test_env):
        listing = subprocess.run((cmd_editcap, '--inject-secrets', 'help'),
                                 capture_output=True, encoding='utf-8', env=test_env)
        assert 'continuity' in listing.stdout + listing.stderr


class TestContinuityAdvertisement:
    def test_messages_are_decoded(self, cmd_tshark, advertisement_capture, test_env):
        rows = fields(cmd_tshark, advertisement_capture, test_env,
                      ('continuity.ble.type', 'continuity.ble.direction'))
        assert len(rows) == 1
        types, direction = rows[0]
        assert types.split(',') == ['0x10', '0x0c']
        assert direction == 'received'

    def test_the_umbrella_selects_it(self, cmd_tshark, advertisement_capture, test_env):
        stdout = subprocess.check_output(
            (cmd_tshark, '-r', advertisement_capture, '-Y', 'continuity'),
            encoding='utf-8', env=test_env)
        assert len(stdout.splitlines()) == 1


class TestContinuityRDLink:
    names = ('continuity.rdlink.type', 'continuity.session', 'continuity.rdlink.read',
             'continuity.rdlink.key_label', 'continuity.rdlink.unavailable',
             'continuity.companion.event', 'continuity.companion.xid',
             'continuity.companion.answered_in')

    def test_the_handshake_names_the_session(self, cmd_tshark, rdlink_capture, test_env):
        rows = fields(cmd_tshark, rdlink_capture, test_env, self.names)
        assert [row[0] for row in rows] == ['0x05', '0x08', '0x08']
        # Every frame of the conversation is reported under the session the
        # handshake named, including the two that carry no key of their own.
        assert [set(row[1].split(',')) for row in rows] == [{EPHEMERAL_KEY.hex()}] * 3

    def test_protected_bodies_without_keys(self, cmd_tshark, rdlink_capture, test_env):
        rows = fields(cmd_tshark, rdlink_capture, test_env, self.names)
        for row in rows[1:]:
            assert row[2] == 'False'
            assert row[4] == 'no key material was supplied'
            assert row[5] == ''

    def check_opened(self, rows):
        request, response = rows[1], rows[2]
        assert request[2:4] == ['True', 'client']
        assert response[2:4] == ['True', 'server']
        assert request[5] == response[5] == '_systemInfo'
        assert request[6] == response[6] == '0x0000000000000007'
        assert request[7] == '3'

    def test_a_shared_secret_opens_both_directions(self, cmd_tshark, rdlink_capture,
                                                   result_file, test_env):
        path = shared_keylog(result_file)
        self.check_opened(fields(cmd_tshark, rdlink_capture, test_env, self.names,
                                 ('continuity.keylog_file:' + path,)))

    def test_direction_keys_open_both_directions(self, cmd_tshark, rdlink_capture,
                                                 result_file, test_env):
        session = EPHEMERAL_KEY.hex()
        path = keylog(result_file, [
            'RDLINK_CLIENT_ENC %s %s' % (session, hkdf_sha512(SHARED_SECRET, b'ClientEncrypt-main').hex()),
            'RDLINK_SERVER_ENC %s %s' % (session, hkdf_sha512(SHARED_SECRET, b'ServerEncrypt-main').hex()),
        ])
        self.check_opened(fields(cmd_tshark, rdlink_capture, test_env, self.names,
                                 ('continuity.keylog_file:' + path,)))

    def test_read_inside_awdl_data_frames(self, cmd_tshark, rdlink_over_awdl_capture,
                                          result_file, test_env):
        rows = fields(cmd_tshark, rdlink_over_awdl_capture, test_env,
                      ('frame.protocols',) + self.names,
                      ('continuity.keylog_file:' + shared_keylog(result_file),))
        assert [row[0] for row in rows] == ['wlan:llc:awdl_data:ipv6:tcp:continuity.rdlink'] * 3
        self.check_opened([row[1:] for row in rows])

    def test_keys_carried_in_the_capture(self, cmd_tshark, cmd_editcap, rdlink_capture,
                                         result_file, test_env):
        carried = result_file('continuity-rdlink-dsb.pcapng')
        subprocess.check_call((cmd_editcap, '--inject-secrets',
                               'continuity,' + shared_keylog(result_file),
                               rdlink_capture, carried), env=test_env)
        self.check_opened(fields(cmd_tshark, carried, test_env, self.names))
