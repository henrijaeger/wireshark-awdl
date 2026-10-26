/* packet-continuity.h — the umbrella every part of this component contributes to.
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
 * An operator investigating what two devices said to each other should have
 * one thing to filter on, not four. The advertisement is inside a Bluetooth
 * event, the control frame is inside TCP, the media is inside UDP, and they
 * share no byte, no transport and no capture file — so the only thing that can
 * join them is a name every part of this component puts on every record it
 * touches.
 *
 * That is `continuity`. It is contributed through continuity_mark() below,
 * which every sub-decode calls before contributing anything of its own.
 *
 * It is a function rather than a convention because the failure is silent: a
 * sub-decode that forgets still produces correct records of its own, and the
 * single filter goes on appearing to work because the other layers still
 * match. What is missing is one layer, and it is missing quietly, for as long
 * as nobody counts.
 */

#ifndef __PACKET_CONTINUITY_H__
#define __PACKET_CONTINUITY_H__

#include <epan/packet.h>
#include <epan/prefs.h>

/* The umbrella protocol. Registered once, referenced by every sub-decode. */
extern int proto_continuity;

/* The Continuity service a record belongs to, as an attribute rather than a
 * container: a camera session is control on one transport and media on
 * another, and nesting the service above the transport would force the same
 * service to appear under each. Registered in the service table (see
 * continuity_service_register) so a further service attaches to the shared
 * transport decoding instead of duplicating it.
 */
/* How a service reads its own payload, when it has one this component
 * decodes. `offset` and `length` bound the payload within `tvb` -- the
 * transport has already reported the framing around it. */
typedef void (*continuity_service_dissect)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                           int offset, int length);

/* How a service reads a companion-link message's content, given what the
 * object decode found in it: the envelope says where `_c` is within `tvb`,
 * whether the body was walked whole, and what shape `_c` has. */
struct continuity_envelope;
typedef void (*continuity_content_dissect)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                           const struct continuity_envelope *envelope);

typedef struct {
    const char *id;    /* what `continuity.service` holds, e.g. "camera" */
    const char *name;  /* what a reader sees, e.g. "Continuity Camera" */

    /* Optional. A service with no decode here still gets its records
     * attributed to it, with its payload reported as bytes -- which is the
     * honest state for a service whose payload has not been worked out, and
     * is most of them. */
    continuity_service_dissect dissect;

    /* Optional. A companion-link service's reading of a message's content,
     * used in place of `dissect` there. */
    continuity_content_dissect dissect_content;
} continuity_service;

/* Put the umbrella on this record, and say which service it belongs to.
 *
 * `service` may be NULL, which is the honest answer for a transport record
 * whose service is not yet known — the companion link carries several, and
 * which one a frame belongs to is often only decidable once its body has been
 * read.
 *
 * Returns the tree to hang the sub-decode's own fields under, which is the
 * caller's tree: the umbrella is an attribute of the record, not a layer above
 * it.
 */
proto_tree *continuity_mark(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb,
                            const continuity_service *service);

/* Bind a session to this conversation, and report it on every record of it
 * from this frame on. The first call for a conversation wins; callers bind
 * only a handshake message they have validated, so a malformed one neither
 * names nor replaces a session.
 *
 * The session is identified by the handshake's cleartext ephemeral public key:
 * visible in the capture, unique per session, and present before any protected
 * frame. That is what lets a reader holding only the capture and the keys bind
 * one to the other, and isolate one session in a capture containing several.
 *
 * Keying on the address and port tuple was tried and is wrong: ports are
 * reused across sessions, and one observed listener port was shared by two
 * transports.
 */
void continuity_session_set(packet_info *pinfo, const uint8_t *ephemeral_key, unsigned len);
void continuity_session_report(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb);

/* This conversation's session, as the lowercase hex of the ephemeral public
 * key, or NULL if its handshake was not in the capture or comes after this
 * frame. A capture cut after the handshake is the ordinary reason for NULL,
 * and it is why a frame says which of "no keys at all" and "no key for this
 * session" applies. */
const char *continuity_session_get(packet_info *pinfo);

/* Services, in a table so that supporting another one is a registration.
 * `continuity_service_lookup` returns NULL for an id nothing registered.
 */
void continuity_service_register(const continuity_service *service);
const continuity_service *continuity_service_lookup(const char *id);

/* Say which service one part of a record belongs to.
 *
 * Separate from continuity_mark() because a record is not always all one
 * service: a single advertisement carries several Continuity messages, and
 * they can be messages of different services. Attributing the whole record to
 * whichever happened to be first would be a wrong answer that looks like a
 * right one, so the attribution goes where the evidence is -- on the message.
 */
void continuity_service_report(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb,
                               const continuity_service *service);

/* Field handles the umbrella owns; sub-decodes use them rather than declaring
 * their own spelling of the same thing. */
extern int hf_continuity_service;
extern int hf_continuity_session;

void proto_register_continuity(void);
void proto_reg_handoff_continuity(void);

void proto_register_continuity_ble(void);
void proto_reg_handoff_continuity_ble(void);

void proto_register_continuity_rdlink(void);
void proto_reg_handoff_continuity_rdlink(void);

void proto_register_continuity_media(void);
void proto_reg_handoff_continuity_media(void);

/* One end of a media stream's negotiation: the UDP port it named, the address
 * it announced in `_streamAddr` (text, may be NULL), and the address of its
 * end of the control connection. */
typedef struct {
    uint32_t port;
    const char *announced;
    const address *control;
} continuity_media_end;

/* A media stream's negotiation completed on this frame: a `_streamStart` of
 * type 3 (UDP media), requested by one end and answered by the other. A UDP
 * packet after this frame between those two ends' ports, at addresses each end
 * announced or controls from, is then that stream. First pass only; later
 * calls are ignored. */
void continuity_media_negotiated(packet_info *pinfo, const char *stream_id,
                                 const continuity_media_end *request,
                                 const continuity_media_end *answer);

void proto_register_continuity_opack(void);
void proto_reg_handoff_continuity_opack(void);

/* The key store, registered by the umbrella rather than as a dissector of
 * its own: its preference belongs to the umbrella's protocol, and a
 * preference registered before that protocol exists aborts at startup. */
void continuity_keys_register(module_t *module);

/* The media decode's preference, which also has to hang off the umbrella's
 * module: a preference on a module named "continuity.media" cannot be set by
 * name, because "continuity" is found first and the rest is then looked up in
 * it. */
void continuity_media_register_prefs(module_t *module);
void continuity_keys_handoff(void);

/* The handshake's cleartext ephemeral public key, which names a session, and
 * the direction keys derived from that session's shared secret. Both are
 * Curve25519/ChaCha20 sized and both are 32 bytes; they are named separately
 * because they are different things that happen to be the same length. */
#define CONTINUITY_SESSION_LEN 32
#define CONTINUITY_KEY_LEN     32

/* One session's key material, as far as it is known.
 *
 * Either direction may be absent: a keylog written while only one end was
 * observed carries one key, and the honest result for the other direction is
 * that its frames are reported unread rather than guessed at.
 */
typedef struct {
    bool has_client;
    bool has_server;
    uint8_t client_enc[CONTINUITY_KEY_LEN];
    uint8_t server_enc[CONTINUITY_KEY_LEN];
} continuity_session_keys;

/* Key material for the session named by this ephemeral public key, or NULL if
 * none was supplied. Never blocks and never reads the network: the inputs are
 * a preference-named file and the capture's own secrets blocks. */
const continuity_session_keys *continuity_keys_lookup(const char *session_hex);

/* Whether any key material at all was supplied, which is what separates "no
 * keys were given" from "keys were given and none of them is this session's".
 * An operator needs to be told which of those happened. */
bool continuity_keys_any_loaded(void);

/* What went wrong reading key material, or NULL: an unreadable key log file,
 * or lines that named a key of this format but could not be used (a session
 * or key of the wrong length, hex that is not hex). Said on the frames that
 * cannot be read, because otherwise they report no key at all. */
const char *continuity_keys_problem(void);

/* Secrets recorded without the session they belong to (keyed on the all-zero
 * session in a keylog). A connection with no key of its own is tried against
 * each, and the one that authenticates is its key. */
unsigned continuity_keys_unbound_count(void);
const continuity_session_keys *continuity_keys_unbound_at(unsigned index);

void proto_register_continuity_companion(void);
void proto_reg_handoff_continuity_companion(void);

void proto_register_continuity_sidecar(void);
void proto_reg_handoff_continuity_sidecar(void);

/* The three-key envelope every companion-link message sits in, as far as a
 * body carried it. `_c` (the content) is not here: it is reported by the
 * object decode in place, and copying it would be a second name for bytes
 * that already have one. */
/* How many scalar members an envelope keeps for the summary. Far more than a
 * line can show; the bound exists because the count comes from the packet. */
#define CONTINUITY_ENVELOPE_MEMBERS 48

typedef struct continuity_envelope {
    bool has_xid;
    bool has_type;
    uint64_t xid;
    int64_t type;

    bool has_event;

    /* `_i`, the event identifier: what the message is, named by the sender.
     * Some values are a service in reverse-DNS form and some name a message
     * of the link itself, so this is reported as the event identifier it is
     * and only separately resolved to a service. */
    const char *event;

    /* Where `_c`, the content, sits in the body -- so a service can be handed
     * its own payload without the transport knowing anything about it.
     * `content_length` is 0 when the message carried no content. */
    int content_offset;
    int content_length;

    /* A top-level `_pd` byte string, as the handshake carries its TLV8 run:
     * where its bytes are, taken from the walk rather than from a fixed
     * offset, so every length encoding of it lands on the same bytes. */
    bool has_pd;
    int pd_offset;
    int pd_length;
    /* How many top-level `_pd` entries the body carried, of any type. */
    unsigned pd_count;

    /* `_c` as {0: <bytes>}: where the byte string is, for a service whose
     * payload is a second object nested in it. */
    bool has_content_bytes;
    int content_bytes_offset;
    int content_bytes_length;
    /* `_c` as {0: <bytes>, 1: <bytes>}: the second nested object. */
    bool has_content_body;
    int content_body_offset;
    int content_body_length;

    /* Whether the body was walked to its end without a stop, a container
     * shorter than it declared, or bytes after it; `problem` says why not.
     * Nothing taken from an incomplete body should be acted on as if the body
     * were whole. */
    bool complete;
    const char *problem;

    /* Set when the envelope's own entries conflict: one of _x, _t, _i or _c
     * sent more than once, or of the wrong type. The message is shown, but
     * pairing it or negotiating from it would rest on a value chosen
     * arbitrarily. */
    const char *conflict;

    /* The scalar members the object decode found -- the envelope's own and
     * those inside `_c`, at any depth -- in wire order, as text. They are what a
     * record's one-line summary is made from, so the summary says what the
     * fields say without a second decode of the body.
     *
     * Scalars only: strings, integers, booleans. A byte string is never one,
     * which is what keeps key material -- always bytes on this link -- out of
     * the line by construction rather than by a list of names to remember. */
    unsigned member_count;
    bool members_truncated;
    struct {
        const char *key;
        const char *value;
        /* The value was an integer, not a string or a boolean: a member a
         * number is taken from must have been sent as one. */
        bool is_int;
        bool in_content;
        /* Inside a container within `_c`, not directly in it. An identifying
         * key can sit there -- `_camCapUpdate` carries InUseState in
         * `_c._cCap` -- but a generic summary takes only `_c`'s own. */
        bool nested;
    } members[CONTINUITY_ENVELOPE_MEMBERS];
} continuity_envelope;

/* Whether a message may have effects that outlive its own frame -- pairing
 * an exchange, recording a negotiation, naming a session: its object was
 * walked whole and its envelope entries do not conflict. A message that is
 * not usable is still shown, with why. */
static inline bool continuity_envelope_usable(const continuity_envelope *envelope)
{
    return envelope->complete && envelope->conflict == NULL;
}

static inline const char *continuity_envelope_unusable_reason(const continuity_envelope *envelope)
{
    return !envelope->complete
               ? (envelope->problem != NULL ? envelope->problem : "the object is incomplete")
               : envelope->conflict;
}

/* Report the envelope, and pair this message with the other half of its
 * exchange. Called by the transport decode, on a cleartext or a decrypted
 * body -- the envelope is the same either way.
 *
 * `message_key` names this message among the others its frame carries, and
 * must be the same on every pass over the frame: per-message state is kept
 * under it. A frame may carry several messages, and a decrypted body is a data
 * source of its own whose offsets all start at zero, so neither the frame nor
 * the body's offset can name one. */
const char *continuity_companion_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                        const continuity_envelope *envelope,
                                        uint32_t message_key);

/* Walk the object encoding at `offset` for `length` bytes, reporting its
 * contents as fields. Returns the offset just past what it consumed.
 *
 * Used for a cleartext body and, where key material recovered one, for a
 * decrypted body: the encoding is the same either way, which is the point of
 * decoding it in one place.
 */
int continuity_opack_dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                             int length);

/* The same walk, additionally reporting the envelope its outermost dictionary
 * carried, if it carried one. */
int continuity_opack_dissect_envelope(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                      int offset, int length, continuity_envelope *envelope);

#endif /* __PACKET_CONTINUITY_H__ */
