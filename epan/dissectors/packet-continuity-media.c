/* packet-continuity-media.c — the media transport, marked and handed on.
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
 * A Continuity Camera session's media is RTP and RTCP on the low-latency
 * link. The RTP dissection already reports sequence, timestamps, marker bits
 * and loss, and restating any of that under a name of this component's own
 * would be two names for one byte.
 *
 * So this decode contributes the umbrella, the session, and which negotiated
 * stream a flow is, and hands the frame to the dissection that already exists.
 * RTCP multiplexed on the same port (RFC 5761) is separated by the RTP
 * dissection itself.
 *
 * WHICH FLOWS. A flow is identified from its negotiation, not from its
 * packets. The control channel's `_streamStart` exchange for a stream of type
 * 3 (UDP media) carries a port in the request and one in the response, and a
 * UDP flow between exactly those two ports is that stream. Ports rather than
 * addresses, because the sender was observed sending from per-stream addresses
 * other than the one it announced. This needs the control channel decrypted;
 * without it no flow is identified, which is the honest result -- RTP with
 * payload type 100 alone is any application's dynamic type 100. A preference
 * restores the old guess for captures without keys, off by default.
 *
 * WHAT IS BOUND. Per stream, from what was observed in Continuity Camera
 * sessions (iOS 16.1.2 to macOS 15.7.9, and a live session on macOS 15.7.9):
 * the two video streams send payload type 100 at a 24 kHz RTP clock, and the
 * microphone stream payload type 101 at 48 kHz. Those types are negotiated,
 * not fixed, so this is what the observed sessions chose. A stream of any
 * other identifier -- including any of another service -- gets no binding:
 * no assumption is carried over from the camera to it.
 *
 * WHAT IS NOT DECODED. The payload is SRTP (7.83 bits of entropy per byte,
 * measured); its keys are negotiated in the same `_streamStart` exchange, and
 * recovering the media is out of scope. A bound payload type is given a name
 * no decode is registered for, so the RTP dissection reports the header and
 * leaves the payload as data -- without it, type 100 and 101 fall to
 * telephone events (RFC 2833) and a camera stream reads as keypad tones.
 * Decoding the RTP header is not decrypting the media.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/prefs.h>

#include "packet-rtp.h"

#include "packet-continuity.h"

static int proto_continuity_media = -1;

static int hf_media_session_unknown = -1;
static int hf_media_opaque = -1;
static int hf_media_stream_id = -1;
static int hf_media_negotiated_in = -1;
static int hf_media_guessed = -1;

static int ett_continuity_media = -1;

static dissector_handle_t media_handle;
static dissector_handle_t rtp_handle;

static bool pref_guess_pt100 = false;

#define CONTINUITY_MEDIA_PT_GUESS 100

#define CONTINUITY_MEDIA_OPAQUE_NAME "Continuity media (opaque payload)"

#define RTP_VERSION_2 2

/* What the observed sessions bound, by the stream identifier's suffix (the
 * identifier is "<session tag>:<name>"). */
static const struct {
    const char *suffix;
    int payload_type;
    int clock_rate;
} media_bindings[] = {
    { ":ContinuityCaptureMediaIdentifierDefaultVideo", 100, 24000 },
    { ":ContinuityCaptureMediaIdentifierDeskcamVideo", 100, 24000 },
    { ":ContinuityCaptureMediaMicrophone",             101, 48000 },
};

/* One negotiated flow. */
typedef struct {
    uint32_t port_low;
    uint32_t port_high;
    const char *stream_id;
    const char *session;
    uint32_t negotiated_in;
} media_flow;

/* Negotiated flows, keyed on the port pair, lowest first. */
static wmem_map_t *flows;

static unsigned flow_hash(const void *key)
{
    const media_flow *f = (const media_flow *)key;
    return g_direct_hash(GUINT_TO_POINTER((f->port_low << 16) ^ f->port_high));
}

static gboolean flow_equal(const void *a, const void *b)
{
    const media_flow *x = (const media_flow *)a;
    const media_flow *y = (const media_flow *)b;
    return x->port_low == y->port_low && x->port_high == y->port_high;
}

static void media_init(void)
{
    flows = wmem_map_new(wmem_file_scope(), flow_hash, flow_equal);
}

void continuity_media_negotiated(packet_info *pinfo, const char *stream_id, uint32_t port_a,
                                 uint32_t port_b)
{
    if (flows == NULL || PINFO_FD_VISITED(pinfo) || port_a == 0 || port_b == 0 ||
        port_a > 65535 || port_b > 65535) {
        return;
    }
    media_flow *flow = wmem_new0(wmem_file_scope(), media_flow);
    flow->port_low = port_a < port_b ? port_a : port_b;
    flow->port_high = port_a < port_b ? port_b : port_a;
    flow->stream_id = stream_id != NULL ? wmem_strdup(wmem_file_scope(), stream_id) : NULL;
    const char *session = continuity_session_get(pinfo);
    flow->session = session != NULL ? wmem_strdup(wmem_file_scope(), session) : NULL;
    flow->negotiated_in = pinfo->num;
    wmem_map_insert(flows, flow, flow);
}

static const media_flow *flow_for(packet_info *pinfo)
{
    if (flows == NULL) {
        return NULL;
    }
    media_flow key = {
        .port_low = pinfo->srcport < pinfo->destport ? pinfo->srcport : pinfo->destport,
        .port_high = pinfo->srcport < pinfo->destport ? pinfo->destport : pinfo->srcport,
    };
    return (const media_flow *)wmem_map_lookup(flows, &key);
}

static bool looks_like_rtp(tvbuff_t *tvb)
{
    return tvb_captured_length(tvb) >= 12 && (tvb_get_uint8(tvb, 0) >> 6) == RTP_VERSION_2;
}

static int dissect_continuity_media(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                    void *data)
{
    proto_item *item = proto_tree_add_item(tree, proto_continuity_media, tvb, 0, 0, ENC_NA);
    proto_item_set_generated(item);
    proto_tree *media_tree = proto_item_add_subtree(item, ett_continuity_media);

    /* The umbrella, so that one selection reaches the media of a session as
     * well as its control channel and its advertisements. */
    continuity_mark(pinfo, media_tree, tvb, NULL);

    const media_flow *flow = flow_for(pinfo);
    if (flow != NULL) {
        if (flow->stream_id != NULL) {
            proto_item *id = proto_tree_add_string(media_tree, hf_media_stream_id, tvb, 0, 0,
                                                   flow->stream_id);
            proto_item_set_generated(id);
        }
        proto_item *in = proto_tree_add_uint(media_tree, hf_media_negotiated_in, tvb, 0, 0,
                                             flow->negotiated_in);
        proto_item_set_generated(in);
        if (flow->session != NULL) {
            proto_item *session = proto_tree_add_string(media_tree, hf_continuity_session, tvb,
                                                        0, 0, flow->session);
            proto_item_set_generated(session);
        }
    } else {
        proto_item *guessed = proto_tree_add_string(
            media_tree, hf_media_guessed, tvb, 0, 0,
            "identified by payload type 100 alone (preference continuity.media_guess_pt100): "
            "no negotiation was seen, so this may be any application's RTP");
        proto_item_set_generated(guessed);
    }
    if (flow == NULL || flow->session == NULL) {
        proto_item *unknown = proto_tree_add_string(
            media_tree, hf_media_session_unknown, tvb, 0, 0,
            "the negotiation of this flow was not read, so the capture does not say which "
            "session it belongs to");
        proto_item_set_generated(unknown);
    }

    proto_item *opaque = proto_tree_add_string(
        media_tree, hf_media_opaque, tvb, 0, 0,
        "SRTP: the payload is encrypted and is not decoded; only the RTP header is");
    proto_item_set_generated(opaque);

    if (rtp_handle != NULL) {
        call_dissector_with_data(rtp_handle, tvb, pinfo, tree, data);
    }
    return tvb_captured_length(tvb);
}

static bool dissect_continuity_media_heur(tvbuff_t *tvb, packet_info *pinfo,
                                          proto_tree *tree, void *data)
{
    if (!looks_like_rtp(tvb)) {
        return false;
    }
    const media_flow *flow = flow_for(pinfo);
    if (flow == NULL &&
        !(pref_guess_pt100 && (tvb_get_uint8(tvb, 1) & 0x7f) == CONTINUITY_MEDIA_PT_GUESS)) {
        return false;
    }

    /* Before the conversation is claimed: setting the flow up with RTP
     * points a conversation at the RTP dissection, and it must not be this
     * one, or the next frame would skip this component. Done once, on the
     * first pass; RTP keeps what it needs per frame for later passes. */
    if (!PINFO_FD_VISITED(pinfo)) {
        rtp_dyn_payload_t *payloads = rtp_dyn_payload_new();
        bool bound = false;
        for (unsigned i = 0; i < array_length(media_bindings); i++) {
            if (flow == NULL ? media_bindings[i].payload_type == CONTINUITY_MEDIA_PT_GUESS
                             : flow->stream_id != NULL &&
                                   g_str_has_suffix(flow->stream_id, media_bindings[i].suffix)) {
                rtp_dyn_payload_insert(payloads, media_bindings[i].payload_type,
                                       CONTINUITY_MEDIA_OPAQUE_NAME,
                                       media_bindings[i].clock_rate, 1);
                bound = true;
                break;
            }
        }
        if (bound) {
            rtp_add_address(pinfo, PT_UDP, &pinfo->net_dst, pinfo->destport, pinfo->srcport,
                            "Continuity", pinfo->num, 0, payloads);
        }
        rtp_dyn_payload_free(payloads); /* RTP holds its own reference */
    }

    conversation_t *conversation = find_or_create_conversation(pinfo);
    conversation_set_dissector(conversation, media_handle);
    dissect_continuity_media(tvb, pinfo, tree, data);
    return true;
}

void proto_register_continuity_media(void)
{
    static hf_register_info hf[] = {
        { &hf_media_session_unknown,
          { "Session not established", "continuity.media.session_unknown", FT_STRING,
            BASE_NONE, NULL, 0x0,
            "Why this media flow could not be bound to a session", HFILL } },
        { &hf_media_opaque,
          { "Opaque payload", "continuity.media.opaque", FT_STRING, BASE_NONE, NULL, 0x0,
            "Why this media payload is reported as data rather than decoded", HFILL } },
        { &hf_media_stream_id,
          { "Stream", "continuity.media.stream_id", FT_STRING, BASE_NONE, NULL, 0x0,
            "The stream identifier this flow was negotiated under (`_streamID`)", HFILL } },
        { &hf_media_negotiated_in,
          { "Negotiated in", "continuity.media.negotiated_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "The frame whose `_streamStart` response completed this flow's negotiation",
            HFILL } },
        { &hf_media_guessed,
          { "Guessed", "continuity.media.guessed", FT_STRING, BASE_NONE, NULL, 0x0,
            "This flow was taken for Continuity media without its negotiation", HFILL } },
    };

    static int *ett[] = { &ett_continuity_media };

    proto_continuity_media = proto_register_protocol("Apple Continuity Media",
                                                     "Continuity Media", "continuity.media");
    proto_register_field_array(proto_continuity_media, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    media_handle = register_dissector("continuity.media", dissect_continuity_media,
                                      proto_continuity_media);

    register_init_routine(media_init);
}

void continuity_media_register_prefs(module_t *module)
{
    prefs_register_bool_preference(
        module, "media_guess_pt100", "Take RTP payload type 100 for Continuity media",
        "Without keys the negotiation of a media flow cannot be read. With this set, any "
        "UDP flow of RTP version 2 and payload type 100 is taken for a Continuity Camera "
        "video stream -- which any other application using dynamic type 100 also matches.",
        &pref_guess_pt100);
}

void proto_reg_handoff_continuity_media(void)
{
    rtp_handle = find_dissector("rtp");
    heur_dissector_add("udp", dissect_continuity_media_heur, "Continuity media over UDP",
                       "continuity_media_udp", proto_continuity_media, HEURISTIC_ENABLE);
}
