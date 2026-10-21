/* packet-continuity-rdlink.c — the Rapport companion and remote-display link.
 *
 * Copyright (C) 2026  Henri Jäger
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * ---------------------------------------------------------------------------
 *
 * The frame:
 *
 *     type(1) || length(3, big-endian) || body
 *
 * and the four types observed on the wire. None of this needs key material:
 * type, direction, length and timing are all in the clear, and a capture with
 * no keys still answers what was said to whom and when, just not what was in
 * it.
 *
 * Attached as a heuristic on the transport rather than by port, because the
 * ports are assigned per session. A static table would find nothing, and an
 * observed listener port was shared by two transports in the same capture,
 * so it would also find the wrong thing.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <wsutil/wsgcrypt.h>
#include "packet-tcp.h"

#include "packet-continuity.h"

static int proto_rdlink = -1;

static int hf_rdlink_type = -1;
static int hf_rdlink_length = -1;
static int hf_rdlink_direction = -1;
static int hf_rdlink_body = -1;
static int hf_rdlink_ephemeral_key = -1;
static int hf_rdlink_protected = -1;
static int hf_rdlink_read = -1;
static int hf_rdlink_unavailable_reason = -1;
static int hf_rdlink_key_label = -1;
static int hf_rdlink_key_binding = -1;
static int hf_rdlink_counter = -1;
static int hf_rdlink_counter_skipped = -1;
static int hf_rdlink_decrypted = -1;
static int hf_rdlink_tlv = -1;
static int hf_rdlink_tlv_tag = -1;
static int hf_rdlink_tlv_length = -1;
static int hf_rdlink_tlv_value = -1;

static int ett_rdlink = -1;
static int ett_rdlink_tlv = -1;

static expert_field ei_rdlink_tlv_truncated;
static expert_field ei_rdlink_frames_missing;

/* The frame header is four bytes, always. */
#define RDLINK_HEADER_LEN 4

/* Frame types, as observed. The body of 0x08 is the protected one; the rest
 * are the handshake and its continuation, which are in the clear. */
#define RDLINK_PUB_KEY        0x05
#define RDLINK_CONTINUE       0x06
#define RDLINK_ENCRYPTED_DATA 0x08

static const value_string rdlink_types[] = {
    { RDLINK_PUB_KEY,        "PubKey (PairVerify)" },
    { RDLINK_CONTINUE,       "Continue" },
    { RDLINK_ENCRYPTED_DATA, "EncryptedData" },
    { 0, NULL },
};

/* Which end spoke.
 *
 * Not `pinfo->p2p_dir`: that is unset for TCP over Ethernet and reports as
 * 0xffffffff, which renders as a direction and is not one. Not the port
 * numbers either -- they are assigned per session and say nothing about which
 * end is which. What does say it is which address opened the conversation,
 * which is recorded on the first frame of it and compared against thereafter.
 */
#define RDLINK_DIR_INITIATOR 0
#define RDLINK_DIR_RESPONDER 1

static const value_string rdlink_directions[] = {
    { RDLINK_DIR_INITIATOR, "initiator to responder" },
    { RDLINK_DIR_RESPONDER, "responder to initiator" },
    { 0, NULL },
};

/* Per-conversation: who opened it, and how many protected frames each end has
 * sent so far.
 *
 * The counter is conversation state rather than frame state because it is not
 * in any frame: the nonce is a count of protected frames in that direction,
 * so it can only be known by having seen the ones before. It is advanced on
 * the first pass over the capture and remembered per frame, because Wireshark
 * dissects a frame more than once and out of order, and a counter that
 * advanced on every visit would give a different nonce each time.
 */
typedef struct {
    address initiator;
    uint32_t initiator_port;
    uint64_t next_counter[2];
    /* A key this connection was found to open under by trial, when the key
     * log did not name it. Kept for the connection rather than tried again on
     * every frame: once one secret has authenticated a frame of it, that is
     * its key. */
    const continuity_session_keys *bound_keys;
} rdlink_conversation;

/* What was worked out about one protected frame, kept so that every later
 * visit to it reports what the first visit found. */
typedef struct {
    uint64_t counter;
    uint64_t skipped;      /* protected frames missing from the capture before it */
    bool read;
    const char *label;     /* which direction key read it */
    const char *binding;   /* how the key was found: named, or by trial */
    const char *reason;    /* why not, when it was not read */
    uint8_t *plaintext;
    unsigned plaintext_len;
} rdlink_frame;

static uint32_t rdlink_direction(packet_info *pinfo)
{
    conversation_t *conversation = find_or_create_conversation(pinfo);
    if (conversation == NULL) {
        return RDLINK_DIR_INITIATOR;
    }
    rdlink_conversation *state =
        (rdlink_conversation *)conversation_get_proto_data(conversation, proto_rdlink);
    if (state == NULL) {
        state = wmem_new0(wmem_file_scope(), rdlink_conversation);
        copy_address_wmem(wmem_file_scope(), &state->initiator, &pinfo->src);
        state->initiator_port = pinfo->srcport;
        conversation_add_proto_data(conversation, proto_rdlink, state);
    }
    return (addresses_equal(&state->initiator, &pinfo->src) &&
            state->initiator_port == pinfo->srcport)
               ? RDLINK_DIR_INITIATOR
               : RDLINK_DIR_RESPONDER;
}

/* A body longer than this in a first frame is not a handshake; the observed
 * ones are 47 bytes and the protected ones a few hundred. The bound exists so
 * that a heuristic looking at arbitrary TCP does not claim a stream on the
 * strength of three bytes that happen to be small. */
#define RDLINK_HEUR_MAX_BODY 4096

/* The handshake's first message, byte for byte as observed:
 *
 *   05 00 00 2f  e1 43 5f 70 64 91 28  06 01 01  03 20 <32 bytes>  19 01 01
 *   |            |                     |         |                |
 *   header       OPACK dict, one key   State=1   PublicKey (32)    Flags=1
 *                "_pd", 0x28 bytes
 *
 * The OPACK prefix is what makes the heuristic safe: `e1 43 5f 70 64` is a
 * one-entry dictionary keyed "_pd", which is specific enough not to fire on
 * unrelated traffic.
 */
static const uint8_t rdlink_pairverify_prefix[] = { 0xe1, 0x43, 0x5f, 0x70, 0x64 };

/* TLV8 tags inside the PairVerify body, as observed on the wire:
 *
 *     06 01 01               State = 1
 *     03 20 <32 bytes>       PublicKey, Curve25519
 *     19 01 01               Flags = 1
 *     05 <len> <bytes>       EncryptedData, in M2 and M3
 *
 * The values are what the handshake sends; their meanings are the thesis'
 * and were confirmed against a completed handshake in this repository.
 */
#define PV_TLV_STATE          0x06
#define PV_TLV_PUBLIC_KEY     0x03
#define PV_TLV_FLAGS          0x19
#define PV_TLV_ENCRYPTED_DATA 0x05
#define PV_PUBLIC_KEY_LEN     32

static const value_string pv_tlv_tags[] = {
    { PV_TLV_STATE,          "State" },
    { PV_TLV_PUBLIC_KEY,     "Public key" },
    { PV_TLV_FLAGS,          "Flags" },
    { PV_TLV_ENCRYPTED_DATA, "Encrypted data" },
    { 0, NULL },
};

/* Walk the TLV8 run, reporting each element and returning where the ephemeral
 * public key is, if it carries one.
 *
 * A walk rather than a fixed offset. The offset works for M1, whose shape is
 * constant, and is wrong for anything that puts its elements in another order
 * -- and being wrong would mean reporting 32 bytes of something else as the
 * value that names the session, which every later record would then carry.
 */
static bool pairverify_tlvs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                            int length, int *key_offset)
{
    int end = offset + length;
    bool found = false;
    while (offset + 2 <= end) {
        uint8_t tag = tvb_get_uint8(tvb, offset);
        uint8_t len = tvb_get_uint8(tvb, offset + 1);
        if (offset + 2 + len > end) {
            /* Reported where it stopped rather than silently ending: a run
             * that disagrees with its own lengths is worth seeing. */
            proto_tree_add_expert_format(tree, pinfo, &ei_rdlink_tlv_truncated, tvb, offset,
                                         end - offset,
                                         "a TLV8 element declares %u byte(s) with %d "
                                         "remaining", len, end - offset - 2);
            return found;
        }
        proto_item *item = proto_tree_add_item(tree, hf_rdlink_tlv, tvb, offset, 2 + len,
                                               ENC_NA);
        proto_item_set_text(item, "%s (0x%02x), %u byte(s)",
                            val_to_str(tag, pv_tlv_tags, "Unknown"), tag, len);
        proto_tree *tlv_tree = proto_item_add_subtree(item, ett_rdlink_tlv);
        proto_tree_add_item(tlv_tree, hf_rdlink_tlv_tag, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tlv_tree, hf_rdlink_tlv_length, tvb, offset + 1, 1,
                            ENC_BIG_ENDIAN);
        if (len > 0) {
            proto_tree_add_item(tlv_tree, hf_rdlink_tlv_value, tvb, offset + 2, len, ENC_NA);
        }

        if (tag == PV_TLV_PUBLIC_KEY && len == PV_PUBLIC_KEY_LEN && !found) {
            *key_offset = offset + 2;
            found = true;
        }
        offset += 2 + len;
    }
    return found;
}

/* ---------------------------------------------------------------------------
 * Reading a protected body.
 *
 * ChaCha20-Poly1305, with the nonce a count of protected frames sent in that
 * direction and the associated data the frame's own four-byte header. All of
 * it established by decrypting frames off the air, including one the *phone*
 * encrypted -- which matters, because a construction verified only against
 * frames this toolkit encrypted itself would be verified against nothing.
 */

#define RDLINK_TAG_LEN   16
#define RDLINK_NONCE_LEN 12

/* How far ahead to look for the counter when a frame does not authenticate.
 *
 * A capture that dropped a protected frame leaves every later frame in that
 * direction off by one, and without this the whole rest of the session reads
 * as unreadable -- which looks exactly like a wrong key and would send an
 * operator hunting for the wrong problem. Poly1305 is what makes the search
 * safe: a wrong counter does not authenticate, so a hit is the counter, not a
 * guess that happened to fit. The jump is reported rather than hidden, since
 * it is also the evidence that frames are missing.
 */
#define RDLINK_COUNTER_LOOKAHEAD 16

static bool rdlink_open_body(const uint8_t *key, uint64_t counter, const uint8_t *header,
                             const uint8_t *ciphertext, unsigned ciphertext_len,
                             const uint8_t *tag, uint8_t *out)
{
    gcry_cipher_hd_t cipher;
    if (gcry_cipher_open(&cipher, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_POLY1305, 0) != 0) {
        return false;
    }

    /* The counter is little-endian in a 12-byte nonce, so the high four bytes
     * are always zero -- a session would need 2^64 frames to reach them. */
    uint8_t nonce[RDLINK_NONCE_LEN] = { 0 };
    for (unsigned i = 0; i < 8; i++) {
        nonce[i] = (uint8_t)((counter >> (8 * i)) & 0xff);
    }

    bool opened = gcry_cipher_setkey(cipher, key, CONTINUITY_KEY_LEN) == 0 &&
                  gcry_cipher_setiv(cipher, nonce, sizeof nonce) == 0 &&
                  gcry_cipher_authenticate(cipher, header, RDLINK_HEADER_LEN) == 0 &&
                  gcry_cipher_decrypt(cipher, out, ciphertext_len, ciphertext, ciphertext_len) == 0 &&
                  gcry_cipher_checktag(cipher, tag, RDLINK_TAG_LEN) == 0;

    gcry_cipher_close(cipher);
    return opened;
}

/* Try one key set on this frame: the direction's own key first, then the
 * other one, each at the expected counter and a few past it. Fills in the
 * frame and advances the counter on success; leaves both alone otherwise. */
static bool rdlink_try_keys(const continuity_session_keys *keys, uint32_t direction,
                            rdlink_conversation *state, rdlink_frame *frame,
                            const uint8_t *header, const uint8_t *ciphertext,
                            unsigned ciphertext_len, const uint8_t *tag, uint8_t *plaintext)
{
    /* The initiator of the connection is the client of the protocol, so its
     * frames are the ones the client key reads. That mapping is asserted by
     * the tests rather than assumed here: if it were the other way round, the
     * fallback below would quietly paper over it, so the tests check which
     * label actually read each direction. */
    bool initiator = direction == RDLINK_DIR_INITIATOR;
    const uint8_t *primary = initiator ? keys->client_enc : keys->server_enc;
    const uint8_t *secondary = initiator ? keys->server_enc : keys->client_enc;
    bool have_primary = initiator ? keys->has_client : keys->has_server;
    bool have_secondary = initiator ? keys->has_server : keys->has_client;
    const char *primary_label = initiator ? "client" : "server";
    const char *secondary_label = initiator ? "server" : "client";

    for (uint64_t ahead = 0; ahead <= RDLINK_COUNTER_LOOKAHEAD; ahead++) {
        uint64_t counter = frame->counter + ahead;
        if (have_primary &&
            rdlink_open_body(primary, counter, header, ciphertext, ciphertext_len, tag, plaintext)) {
            frame->label = primary_label;
        } else if (have_secondary && rdlink_open_body(secondary, counter, header, ciphertext,
                                                      ciphertext_len, tag, plaintext)) {
            frame->label = secondary_label;
        } else {
            continue;
        }
        frame->read = true;
        frame->skipped = ahead;
        frame->counter = counter;
        frame->plaintext = plaintext;
        frame->plaintext_len = ciphertext_len;
        state->next_counter[direction] = counter + 1;
        return true;
    }
    return false;
}

/* Work out what this protected frame is, once, on the first pass over it. */
static rdlink_frame *rdlink_read_body(tvbuff_t *tvb, packet_info *pinfo, uint32_t length,
                                      uint32_t direction)
{
    rdlink_frame *frame = wmem_new0(wmem_file_scope(), rdlink_frame);

    conversation_t *conversation = find_or_create_conversation(pinfo);
    rdlink_conversation *state =
        conversation == NULL
            ? NULL
            : (rdlink_conversation *)conversation_get_proto_data(conversation, proto_rdlink);
    if (state == NULL) {
        frame->reason = "the conversation's state was not established";
        return frame;
    }

    frame->counter = state->next_counter[direction];

    if (length <= RDLINK_TAG_LEN) {
        frame->reason = "the body is too short to carry an authentication tag";
        state->next_counter[direction]++;
        return frame;
    }

    unsigned ciphertext_len = length - RDLINK_TAG_LEN;
    const uint8_t *header = tvb_get_ptr(tvb, 0, RDLINK_HEADER_LEN);
    const uint8_t *ciphertext = tvb_get_ptr(tvb, RDLINK_HEADER_LEN, (int)ciphertext_len);
    const uint8_t *tag = tvb_get_ptr(tvb, RDLINK_HEADER_LEN + (int)ciphertext_len, RDLINK_TAG_LEN);
    uint8_t *plaintext = (uint8_t *)wmem_alloc(wmem_file_scope(), ciphertext_len);

    /* A key found earlier for this connection, by trial. */
    if (state->bound_keys != NULL) {
        if (rdlink_try_keys(state->bound_keys, direction, state, frame, header, ciphertext,
                            ciphertext_len, tag, plaintext)) {
            frame->binding = "found by trial against the unbound secrets";
            return frame;
        }
        frame->reason = "no key for this session authenticated this frame";
        state->next_counter[direction]++;
        return frame;
    }

    /* A key the key log names, by the session's handshake. */
    const char *session = continuity_session_get(pinfo);
    const continuity_session_keys *keys = session == NULL ? NULL : continuity_keys_lookup(session);
    if (keys != NULL && (keys->has_client || keys->has_server)) {
        if (rdlink_try_keys(keys, direction, state, frame, header, ciphertext, ciphertext_len,
                            tag, plaintext)) {
            frame->binding = "named in the key log";
            return frame;
        }
        frame->reason = "no key for this session authenticated this frame";
        state->next_counter[direction]++;
        return frame;
    }

    /* Neither: try the secrets recorded without a session.
     *
     * Only while the counter is still near where a connection starts. The
     * nonce is a count of the frames before this one, so on a connection that
     * began before the capture it is unknown and no key could open a frame
     * anyway; and that bound is what keeps this cheap -- a handful of attempts
     * per direction of each keyless connection, not per frame of every one.
     *
     * A connection without a handshake is tried as well. That is not only a
     * capture that started late: a stream sub-connection opened inside a
     * session is keyed from a value exchanged on the control channel and
     * never performs a handshake of its own, so this is the only way it is
     * ever read. */
    unsigned candidates = continuity_keys_unbound_count();
    bool tried = candidates > 0 && frame->counter <= RDLINK_COUNTER_LOOKAHEAD;
    if (tried) {
        for (unsigned i = 0; i < candidates; i++) {
            const continuity_session_keys *candidate = continuity_keys_unbound_at(i);
            if (rdlink_try_keys(candidate, direction, state, frame, header, ciphertext,
                                ciphertext_len, tag, plaintext)) {
                state->bound_keys = candidate;
                frame->binding = "found by trial against the unbound secrets";
                return frame;
            }
        }
    }

    if (session == NULL) {
        /* The ordinary cause is a capture that starts after the handshake.
         * Said plainly, because it is also the one case an operator can fix
         * by capturing earlier. */
        frame->reason = tried ? "the session's handshake is not in this capture, and no "
                                "unbound secret opens this connection"
                              : "the session's handshake is not in this capture";
    } else if (keys != NULL) {
        frame->reason = "no key material for this session";
    } else {
        frame->reason = !continuity_keys_any_loaded()
                            ? "no key material was supplied"
                            : tried ? "no key material for this session, and no unbound "
                                      "secret authenticated this frame"
                                    : "no key material for this session";
    }
    state->next_counter[direction]++;
    return frame;
}

static unsigned rdlink_pdu_length(packet_info *pinfo _U_, tvbuff_t *tvb,
                                  int offset, void *data _U_)
{
    return RDLINK_HEADER_LEN + tvb_get_uint24(tvb, offset + 1, ENC_BIG_ENDIAN);
}

/* ---------------------------------------------------------------------------
 * The record's one-line summary.
 *
 * What the Info column says is what a record's line says in every timeline
 * output -- the toolkit takes the column as the record's message. So it is
 * built here, once the body has been read or declined and walked, from what
 * the companion and object decodes found, rather than appended to by each
 * sub-decode: appended pieces would read in call order, and a refactor would
 * silently scramble the line.
 *
 *   read:       <Type> <event> <k1>=<v1> <k2>=<v2> ... [dir]
 *   unread:     <Type> not read: <reason> [dir]
 *   handshake:  <Type> <step> [dir]
 *
 * Keys appear as the wire spells them: an investigator searches for what the
 * protocol says, not for a prettier name for it.
 */

/* Bounded, because a line is for a terminal and the fields are for the rest.
 * Long enough for a stream negotiation's line. */
#define RDLINK_SUMMARY_MAX 240

/* The identifying keys of known events, in the order they are shown. Any other
 * event shows its first scalar members in wire order. A short table on
 * purpose: an entry earns its place by being what an investigator looks for. */
static const struct {
    const char *event;
    const char *keys[4];
} rdlink_summary_keys[] = {
    { "_streamStart",  { "_streamID", "_streamAddr", "_streamPort", NULL } },
    { "_systemInfo",   { "model", "name", NULL } },
    { "_camCapUpdate", { "InUseState", NULL } },
};

/* The envelope's own entries, which say how the message travels rather than
 * what it is about. Never shown as members. */
static bool rdlink_envelope_key(const char *key)
{
    return strcmp(key, "_i") == 0 || strcmp(key, "_x") == 0 || strcmp(key, "_t") == 0 ||
           strcmp(key, "_c") == 0;
}

/* Never placed in a line, whatever its value's encoding. Key material on this
 * link is bytes, which the object decode never offers as a member; this is
 * the second guard, for a key whose value arrives some other way. */
static bool rdlink_secret_key(const char *key)
{
    return g_strrstr(key, "Key") != NULL || g_strrstr(key, "key") != NULL ||
           g_ascii_strcasecmp(key, "_pk") == 0 || g_ascii_strcasecmp(key, "_sk") == 0 ||
           g_ascii_strcasecmp(key, "_psk") == 0 || g_ascii_strcasecmp(key, "_pd") == 0;
}

static void rdlink_append_member(wmem_strbuf_t *line, const char *key, const char *value)
{
    if (rdlink_secret_key(key)) {
        return;
    }
    /* Quoted only where a bare value would not read as one value. */
    bool quote = value[0] == '\0' || strchr(value, ' ') != NULL;
    wmem_strbuf_append_printf(line, quote ? " %s=\"%s\"" : " %s=%s", key, value);
}

/* The members a read message's line shows: the table's keys for a known
 * event, found anywhere inside `_c`, else `_c`'s own scalars and then the
 * envelope's other scalars, in wire order. */
static void rdlink_append_members(wmem_strbuf_t *line, const continuity_envelope *envelope,
                                  const char *event)
{
    for (unsigned i = 0; event != NULL && i < array_length(rdlink_summary_keys); i++) {
        if (strcmp(event, rdlink_summary_keys[i].event) != 0) {
            continue;
        }
        bool any = false;
        for (unsigned k = 0; rdlink_summary_keys[i].keys[k] != NULL; k++) {
            const char *wanted = rdlink_summary_keys[i].keys[k];
            for (unsigned m = 0; m < envelope->member_count; m++) {
                if (strcmp(envelope->members[m].key, wanted) == 0) {
                    rdlink_append_member(line, wanted, envelope->members[m].value);
                    any = true;
                    break;
                }
            }
        }
        if (any) {
            return;
        }
        break; /* a known event without its keys: fall back rather than say nothing */
    }

    for (int pass = 0; pass < 2; pass++) {
        bool content = pass == 0;
        for (unsigned m = 0; m < envelope->member_count; m++) {
            if (envelope->members[m].in_content != content || envelope->members[m].nested) {
                continue;
            }
            if (!content && rdlink_envelope_key(envelope->members[m].key)) {
                continue;
            }
            rdlink_append_member(line, envelope->members[m].key, envelope->members[m].value);
            if (wmem_strbuf_get_len(line) > RDLINK_SUMMARY_MAX) {
                return; /* the bound cuts it; nothing after this would show */
            }
        }
    }
}

/* The handshake step, from the PairVerify state in the clear body:
 * `{_pd: <TLV8>}` with State as tag 0x06. 0 when it cannot be found. Read
 * without touching the tree, so the step costs no field the decode did not
 * already report. */
static unsigned rdlink_pairverify_step(tvbuff_t *tvb, uint32_t length)
{
    int offset = RDLINK_HEADER_LEN;
    int end = RDLINK_HEADER_LEN + (int)length;
    if (tvb_captured_length(tvb) < (unsigned)end || length < sizeof rdlink_pairverify_prefix + 1 ||
        tvb_memeql(tvb, offset, rdlink_pairverify_prefix, sizeof rdlink_pairverify_prefix) != 0) {
        return 0;
    }
    offset += (int)sizeof rdlink_pairverify_prefix;

    /* The value of `_pd`: a byte string, its length inline or in one byte. */
    uint8_t marker = tvb_get_uint8(tvb, offset++);
    int data_len;
    if (marker >= 0x70 && marker <= 0x90) {
        data_len = marker - 0x70;
    } else if (marker == 0x91 && offset < end) {
        data_len = tvb_get_uint8(tvb, offset++);
    } else {
        return 0;
    }
    int data_end = offset + data_len < end ? offset + data_len : end;

    while (offset + 2 <= data_end) {
        uint8_t tag = tvb_get_uint8(tvb, offset);
        uint8_t len = tvb_get_uint8(tvb, offset + 1);
        if (tag == PV_TLV_STATE && len == 1 && offset + 3 <= data_end) {
            return tvb_get_uint8(tvb, offset + 2);
        }
        offset += 2 + len;
    }
    return 0;
}

static const char *rdlink_direction_tag(uint32_t direction)
{
    return direction == RDLINK_DIR_INITIATOR ? "[init→resp]" : "[resp→init]";
}

/* Put the summary in the Info column, bounded. A frame can carry several
 * PDUs; each one's summary follows the previous one's rather than replacing
 * it, so no record is reduced to the last thing its frame carried.
 *
 * The bound is on the whole line, not on each PDU's part: the line is the
 * record's, and a frame of three unread PDUs otherwise made one of 354
 * characters out of three that were each within it. */
static void rdlink_set_summary(packet_info *pinfo, bool first, wmem_strbuf_t *line)
{
    const char *text = wmem_strbuf_get_str(line);
    if (!first) {
        const char *so_far = col_get_text(pinfo->cinfo, COL_INFO);
        if (so_far != NULL) {
            if (g_str_has_suffix(so_far, "…")) {
                return; /* already full: nothing more would show */
            }
            text = wmem_strdup_printf(pinfo->pool, "%s | %s", so_far, text);
        }
    }
    if (g_utf8_strlen(text, -1) > RDLINK_SUMMARY_MAX) {
        const char *cut = g_utf8_offset_to_pointer(text, RDLINK_SUMMARY_MAX - 1);
        text = wmem_strdup_printf(pinfo->pool, "%.*s…", (int)(cut - text), text);
    }
    col_add_str(pinfo->cinfo, COL_INFO, text);
}

/* Whether this is the first RDLink PDU of the frame in this pass over it. */
static bool rdlink_first_pdu(packet_info *pinfo)
{
    if (p_get_proto_data(pinfo->pool, pinfo, proto_rdlink, 0) != NULL) {
        return false;
    }
    p_add_proto_data(pinfo->pool, pinfo, proto_rdlink, 0, GUINT_TO_POINTER(1));
    return true;
}

static int dissect_rdlink_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                              void *data _U_)
{
    uint8_t type = tvb_get_uint8(tvb, 0);
    uint32_t length = tvb_get_uint24(tvb, 1, ENC_BIG_ENDIAN);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RDLink");

    /* Provisional, for a decode that does not reach the summary below. Only
     * the frame's first PDU sets it: a later one must not erase what the
     * earlier ones said. */
    bool first = rdlink_first_pdu(pinfo);
    const char *type_name = val_to_str(type, rdlink_types, "Type 0x%02x");
    if (first) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s, %u byte body", type_name, length);
    }
    wmem_strbuf_t *summary = wmem_strbuf_new(pinfo->pool, type_name);

    proto_item *item = proto_tree_add_item(tree, proto_rdlink, tvb, 0, -1, ENC_NA);
    proto_tree *rdlink_tree = proto_item_add_subtree(item, ett_rdlink);

    /* The umbrella first, before this decode contributes anything of its own.
     * The service is not known from the framing alone -- the companion link
     * carries several -- so it is left unsaid rather than guessed. */
    continuity_mark(pinfo, rdlink_tree, tvb, NULL);

    proto_tree_add_item(rdlink_tree, hf_rdlink_type, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(rdlink_tree, hf_rdlink_length, tvb, 1, 3, ENC_BIG_ENDIAN);

    uint32_t dir = rdlink_direction(pinfo);
    proto_item *direction = proto_tree_add_uint(rdlink_tree, hf_rdlink_direction, tvb, 0, 0, dir);
    proto_item_set_generated(direction);

    if (length == 0) {
        wmem_strbuf_append_printf(summary, " empty %s", rdlink_direction_tag(dir));
        rdlink_set_summary(pinfo, first, summary);
        return tvb_captured_length(tvb);
    }

    if (type == RDLINK_PUB_KEY || type == RDLINK_CONTINUE) {
        unsigned step = rdlink_pairverify_step(tvb, length);
        if (step != 0) {
            /* The PubKey type's own name already says PairVerify. */
            wmem_strbuf_append_printf(summary, type == RDLINK_PUB_KEY ? " M%u" : " PairVerify M%u",
                                      step);
        } else {
            wmem_strbuf_append(summary, " (step not recognised)");
        }
        wmem_strbuf_append_printf(summary, " %s", rdlink_direction_tag(dir));
    }

    if (type == RDLINK_PUB_KEY || type == RDLINK_CONTINUE) {
        /* The handshake frames are in the clear. Their bodies are the same
         * object encoding the protected bodies carry, so they are walked by
         * the same decode -- which is what makes the encoding's correctness
         * testable against captures nobody holds a key for. */
        continuity_opack_dissect(tvb, pinfo, rdlink_tree, RDLINK_HEADER_LEN, (int)length);
    }

    if (type == RDLINK_PUB_KEY) {
        /* The handshake is in the clear, and carries the value that names
         * this session for everything that follows it.
         *
         * The TLV8 run sits inside the object encoding's one value, which
         * the walk above has already reported: this finds where that value
         * is by walking from the body, which is what makes it independent of
         * the handshake message's exact shape.
         */
        int key_offset = 0;
        int body_start = RDLINK_HEADER_LEN + (int)sizeof rdlink_pairverify_prefix + 2;
        int available = tvb_captured_length_remaining(tvb, body_start);
        if (available > 0 &&
            pairverify_tlvs(tvb, pinfo, rdlink_tree, body_start, available, &key_offset)) {
            proto_item *key = proto_tree_add_item(rdlink_tree, hf_rdlink_ephemeral_key, tvb,
                                                  key_offset, PV_PUBLIC_KEY_LEN, ENC_NA);
            proto_item_set_generated(key);
            continuity_session_set(pinfo,
                                   tvb_get_ptr(tvb, key_offset, PV_PUBLIC_KEY_LEN),
                                   PV_PUBLIC_KEY_LEN);
        }
        proto_tree_add_item(rdlink_tree, hf_rdlink_body, tvb, RDLINK_HEADER_LEN,
                            (int)length, ENC_NA);
        rdlink_set_summary(pinfo, first, summary);
        return tvb_captured_length(tvb);
    }

    if (type == RDLINK_ENCRYPTED_DATA) {
        /* Reported as protected, and reported read or unread, rather than
         * omitted. A frame whose body could not be read is still evidence
         * that the frame happened, how big it was and which way it went --
         * and an operator has to be able to select exactly the ones that
         * were read and exactly the ones that were not. */
        proto_item *protected_item =
            proto_tree_add_boolean(rdlink_tree, hf_rdlink_protected, tvb, 0, 0, true);
        proto_item_set_generated(protected_item);

        /* Worked out once, on the first pass, and kept: the nonce is a count
         * of the frames before this one, so it cannot be recomputed by a
         * visit that arrives out of order. Keyed on where this PDU starts in
         * the frame, because one frame can carry several. */
        rdlink_frame *frame =
            (rdlink_frame *)p_get_proto_data(wmem_file_scope(), pinfo, proto_rdlink,
                                             (uint32_t)tvb_raw_offset(tvb));
        if (frame == NULL) {
            frame = rdlink_read_body(tvb, pinfo, length, rdlink_direction(pinfo));
            p_add_proto_data(wmem_file_scope(), pinfo, proto_rdlink,
                             (uint32_t)tvb_raw_offset(tvb), frame);
        }

        proto_item *read_item =
            proto_tree_add_boolean(rdlink_tree, hf_rdlink_read, tvb, 0, 0, frame->read);
        proto_item_set_generated(read_item);

        if (frame->read) {
            proto_item *label = proto_tree_add_string(rdlink_tree, hf_rdlink_key_label, tvb, 0, 0,
                                                      frame->label);
            proto_item_set_generated(label);
            if (frame->binding != NULL) {
                proto_item *binding = proto_tree_add_string(rdlink_tree, hf_rdlink_key_binding,
                                                            tvb, 0, 0, frame->binding);
                proto_item_set_generated(binding);
            }
            proto_item *counter =
                proto_tree_add_uint64(rdlink_tree, hf_rdlink_counter, tvb, 0, 0, frame->counter);
            proto_item_set_generated(counter);
            if (frame->skipped > 0) {
                /* The capture is missing frames, and this is where that
                 * becomes visible. Worth saying out loud: the alternative is
                 * a session that silently stops being readable partway. */
                proto_item *skipped = proto_tree_add_uint64(rdlink_tree, hf_rdlink_counter_skipped,
                                                            tvb, 0, 0, frame->skipped);
                proto_item_set_generated(skipped);
                expert_add_info(pinfo, skipped, &ei_rdlink_frames_missing);
            }

            /* A data source of its own, so the bytes an operator sees under
             * the decoded fields are the plaintext those fields came from,
             * and the frame's own bytes stay what came off the wire. */
            tvbuff_t *plain = tvb_new_child_real_data(tvb, frame->plaintext,
                                                      frame->plaintext_len, frame->plaintext_len);
            add_new_data_source(pinfo, plain, "Decrypted RDLink body");
            proto_tree_add_item(rdlink_tree, hf_rdlink_decrypted, plain, 0,
                                (int)frame->plaintext_len, ENC_NA);

            /* The same object encoding the cleartext handshake carries, read
             * by the same decode -- which is what makes that decode testable
             * against captures nobody holds a key for. */
            continuity_envelope envelope = { 0 };
            continuity_opack_dissect_envelope(plain, pinfo, rdlink_tree, 0,
                                              (int)frame->plaintext_len, &envelope);
            const char *name = continuity_companion_report(plain, pinfo, rdlink_tree, &envelope);

            /* What was said. A response is named by the request it answers,
             * and looked up in the key table under that request's event. */
            wmem_strbuf_append_printf(summary, " %s", name != NULL ? name : "(no event)");
            const char *event = envelope.has_event ? envelope.event : NULL;
            if (event == NULL && name != NULL && g_str_has_suffix(name, " response")) {
                event = wmem_strndup(pinfo->pool, name, strlen(name) - strlen(" response"));
            }
            rdlink_append_members(summary, &envelope, event);
            wmem_strbuf_append_printf(summary, " %s", rdlink_direction_tag(dir));
        } else {
            proto_item *reason = proto_tree_add_string(rdlink_tree, hf_rdlink_unavailable_reason,
                                                       tvb, 0, 0, frame->reason);
            proto_item_set_generated(reason);
            /* Never the wording a read frame uses: "not read" is what an
             * investigator filters on to find what still needs a key. */
            wmem_strbuf_append_printf(summary, " not read: %s %s", frame->reason,
                                      rdlink_direction_tag(dir));
        }
    } else if (type != RDLINK_CONTINUE) {
        /* A type this decode does not know: the provisional line was all it
         * can say. */
        wmem_strbuf_append_printf(summary, ", %u byte body %s", length, rdlink_direction_tag(dir));
    }

    proto_tree_add_item(rdlink_tree, hf_rdlink_body, tvb, RDLINK_HEADER_LEN,
                        (int)length, ENC_NA);
    rdlink_set_summary(pinfo, first, summary);
    return tvb_captured_length(tvb);
}

static int dissect_rdlink(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, true, RDLINK_HEADER_LEN, rdlink_pdu_length,
                     dissect_rdlink_pdu, data);
    return tvb_captured_length(tvb);
}

/* Does this stream open with a PairVerify M1?
 *
 * Deliberately narrow. A looser test -- "the first byte is a known type and
 * the length is plausible" -- matches a great deal of ordinary traffic, and a
 * heuristic that claims a stream it does not understand is worse than one
 * that misses: the stream then gets *this* component's wrong decode instead
 * of whatever was right.
 */
static bool opens_with_pairverify(tvbuff_t *tvb)
{
    if (tvb_captured_length(tvb) < RDLINK_HEADER_LEN + (int)sizeof rdlink_pairverify_prefix) {
        return false;
    }
    if (tvb_get_uint8(tvb, 0) != RDLINK_PUB_KEY) {
        return false;
    }
    uint32_t length = tvb_get_uint24(tvb, 1, ENC_BIG_ENDIAN);
    if (length == 0 || length > RDLINK_HEUR_MAX_BODY) {
        return false;
    }
    return tvb_memeql(tvb, RDLINK_HEADER_LEN, rdlink_pairverify_prefix,
                      sizeof rdlink_pairverify_prefix) == 0;
}

/* The other way in: a segment that is exactly tiled by well-formed frames.
 *
 * A capture that began after the handshake carries no PairVerify to
 * recognise -- one of the reference captures is exactly that, a single
 * segment holding one EncryptedData frame -- and a component that decoded
 * nothing there would be refusing the ordinary case of joining a session
 * already in progress.
 *
 * "Exactly tiled" is doing the work. Every frame's type must be one this
 * decode knows, every declared length must fit, and the last frame must end
 * precisely at the end of the segment. Arbitrary binary traffic does not
 * usually satisfy a 3-byte big-endian length chain that lands exactly on the
 * boundary, and requiring the exact landing is what separates this from the
 * "first byte is plausible" test that would claim half the captures on a
 * machine.
 */
static bool tiles_exactly(tvbuff_t *tvb)
{
    int length = (int)tvb_captured_length(tvb);
    if (length != (int)tvb_reported_length(tvb) || length < RDLINK_HEADER_LEN) {
        /* A segment that was cut short cannot be checked for exact tiling,
         * and guessing from a prefix is the loose test this avoids. */
        return false;
    }

    int offset = 0;
    unsigned frames = 0;
    while (offset + RDLINK_HEADER_LEN <= length) {
        uint8_t type = tvb_get_uint8(tvb, offset);
        if (try_val_to_str(type, rdlink_types) == NULL) {
            return false;
        }
        uint32_t body = tvb_get_uint24(tvb, offset + 1, ENC_BIG_ENDIAN);
        if (body == 0 || body > RDLINK_HEUR_MAX_BODY * 64) {
            return false;
        }
        offset += RDLINK_HEADER_LEN + (int)body;
        frames++;
    }
    return frames > 0 && offset == length;
}

static bool dissect_rdlink_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                void *data)
{
    if (!opens_with_pairverify(tvb) && !tiles_exactly(tvb)) {
        return false;
    }

    /* Claimed for the whole conversation: the frames after the handshake
     * carry no marker of their own, so a per-frame heuristic would decode the
     * first frame of a session and nothing else. */
    conversation_t *conversation = find_or_create_conversation(pinfo);
    conversation_set_dissector(conversation, find_dissector("continuity.rdlink"));
    dissect_rdlink(tvb, pinfo, tree, data);
    return true;
}

void proto_register_continuity_rdlink(void)
{
    static hf_register_info hf[] = {
        { &hf_rdlink_type,
          { "Type", "continuity.rdlink.type", FT_UINT8, BASE_HEX, VALS(rdlink_types), 0x0,
            NULL, HFILL } },
        { &hf_rdlink_length,
          { "Body length", "continuity.rdlink.length", FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL } },
        { &hf_rdlink_direction,
          { "Direction", "continuity.rdlink.direction", FT_UINT8, BASE_DEC,
            VALS(rdlink_directions), 0x0, NULL, HFILL } },
        { &hf_rdlink_body,
          { "Body", "continuity.rdlink.body", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_rdlink_ephemeral_key,
          { "Ephemeral public key", "continuity.rdlink.ephemeral_key", FT_BYTES, BASE_NONE,
            NULL, 0x0,
            "The handshake's cleartext Curve25519 public key, which identifies "
            "the session", HFILL } },
        { &hf_rdlink_protected,
          { "Protected", "continuity.rdlink.protected", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "The body is encrypted on the wire", HFILL } },
        { &hf_rdlink_read,
          { "Read", "continuity.rdlink.read", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "The protected content was recovered", HFILL } },
        { &hf_rdlink_unavailable_reason,
          { "Unavailable", "continuity.rdlink.unavailable", FT_STRING, BASE_NONE, NULL, 0x0,
            "Why the protected content was not recovered", HFILL } },
        { &hf_rdlink_key_label,
          { "Read with", "continuity.rdlink.key_label", FT_STRING, BASE_NONE, NULL, 0x0,
            "Which direction's key read this body: the client key for the frames the "
            "connection's initiator sent, the server key for the other end's", HFILL } },
        { &hf_rdlink_key_binding,
          { "Key found", "continuity.rdlink.key_binding", FT_STRING, BASE_NONE, NULL, 0x0,
            "How this connection's key was found: named in the key log by the session's "
            "handshake, or found by trying the secrets recorded without a session until one "
            "authenticated", HFILL } },
        { &hf_rdlink_counter,
          { "Frame counter", "continuity.rdlink.counter", FT_UINT64, BASE_DEC, NULL, 0x0,
            "This frame's position in the protected frames sent in its direction, which "
            "is what the nonce is. Not carried in the frame: known only by having seen "
            "the ones before it", HFILL } },
        { &hf_rdlink_counter_skipped,
          { "Protected frames missing before this one", "continuity.rdlink.counter_skipped",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "How far the counter had to advance past the expected value before this body "
            "authenticated, which is how many protected frames of this direction the "
            "capture does not contain", HFILL } },
        { &hf_rdlink_decrypted,
          { "Decrypted body", "continuity.rdlink.decrypted", FT_BYTES, BASE_NONE, NULL, 0x0,
            "The protected body, recovered. Reported as its own data source so that the "
            "frame's own bytes stay what came off the wire", HFILL } },
        { &hf_rdlink_tlv,
          { "TLV8 element", "continuity.rdlink.tlv", FT_NONE, BASE_NONE, NULL, 0x0, NULL,
            HFILL } },
        { &hf_rdlink_tlv_tag,
          { "Tag", "continuity.rdlink.tlv.tag", FT_UINT8, BASE_HEX, VALS(pv_tlv_tags), 0x0,
            NULL, HFILL } },
        { &hf_rdlink_tlv_length,
          { "Length", "continuity.rdlink.tlv.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL,
            HFILL } },
        { &hf_rdlink_tlv_value,
          { "Value", "continuity.rdlink.tlv.value", FT_BYTES, BASE_NONE, NULL, 0x0, NULL,
            HFILL } },
    };

    static int *ett[] = { &ett_rdlink, &ett_rdlink_tlv };

    static ei_register_info ei[] = {
        { &ei_rdlink_tlv_truncated,
          { "continuity.rdlink.tlv.truncated", PI_MALFORMED, PI_WARN,
            "A TLV8 element runs past the end of the body", EXPFILL } },
        { &ei_rdlink_frames_missing,
          { "continuity.rdlink.frames_missing", PI_SEQUENCE, PI_NOTE,
            "Protected frames of this direction are missing from the capture", EXPFILL } },
    };

    proto_rdlink = proto_register_protocol("Rapport Remote-Display Link", "RDLink",
                                           "continuity.rdlink");
    proto_register_field_array(proto_rdlink, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_module_t *expert = expert_register_protocol(proto_rdlink);
    expert_register_field_array(expert, ei, array_length(ei));

    register_dissector("continuity.rdlink", dissect_rdlink, proto_rdlink);
}

void proto_reg_handoff_continuity_rdlink(void)
{
    heur_dissector_add("tcp", dissect_rdlink_heur, "Continuity over TCP", "continuity_tcp",
                       proto_rdlink, HEURISTIC_ENABLE);
}
