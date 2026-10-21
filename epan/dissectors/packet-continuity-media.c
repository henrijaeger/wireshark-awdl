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
 * So this decode contributes exactly two things -- the umbrella, and the
 * session where it is known -- and hands the frame to the dissection that
 * already exists.
 *
 * The payload is SRTP (7.83 bits of entropy per byte, measured), and its keys
 * are negotiated inside the control channel this component decrypts one layer
 * above. Recovering the media itself is out of scope, and the headers are in
 * scope regardless.
 *
 * Handing on is not quite enough on its own, though. Payload type 100 is
 * dynamic, and with nothing to say what it means the RTP dissection falls back
 * to whatever claims the number -- telephone events (RFC 2833), whose default
 * range is 100-101 -- and reports a camera stream as keypad tones. So the flow
 * this component identifies is set up with RTP the way a session description
 * would set it up, with type 100 bound to a name no decode is registered for.
 * The RTP dissection then reports the header and leaves the payload as data.
 *
 * Not H.265, although the stream is HEVC video: what H.265's RTP decode reads
 * is the NAL unit header at the start of the payload, and that header is
 * inside the encryption. Over the whole flow of the reference capture the
 * payload's first two bytes are what random bytes give (forbidden bit set in
 * 565 of 1,164 frames, all 64 unit types present, 9 of 28 "fragmentation
 * units" both starting and ending), so naming the format would turn a wrong
 * label into a wrong decode.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/conversation.h>

#include "packet-rtp.h"

#include "packet-continuity.h"

static int proto_continuity_media = -1;

static int hf_media_session_unknown = -1;
static int hf_media_opaque = -1;

static int ett_continuity_media = -1;

static dissector_handle_t media_handle;
static dissector_handle_t rtp_handle;
static dissector_handle_t rtcp_handle;

/* The dynamic payload type observed carrying HEVC on this link: the one RTP
 * flow of the Continuity Camera session in continuity-camera.pcapng (iPhone to
 * Mac over the low-latency link, 1,164 frames, one SSRC). Used as one of the
 * heuristic's conditions, not as a claim about what type 100 means: another
 * link that uses it differently is not identified, and the binding below is
 * made per identified flow, never for type 100 in general. */
#define CONTINUITY_MEDIA_PT_HEVC 100

/* What type 100 is bound to on an identified flow. No decode is registered
 * under this name, which is the point: RTP reports the payload as data. */
#define CONTINUITY_MEDIA_OPAQUE_NAME "Continuity media (opaque payload)"

/* The flow's RTP clock, measured: the timestamp advances by 800 per video
 * frame at 30 frames a second. Not the 90 000 Hz usual for video, and RTP's
 * stream analysis computes jitter from it. */
#define CONTINUITY_MEDIA_CLOCK_RATE 24000

#define RTP_VERSION_2 2

static bool looks_like_rtp(tvbuff_t *tvb)
{
    if (tvb_captured_length(tvb) < 12) {
        return false;
    }
    uint8_t first = tvb_get_uint8(tvb, 0);
    if ((first >> 6) != RTP_VERSION_2) {
        return false;
    }
    uint8_t second = tvb_get_uint8(tvb, 1);
    uint8_t payload_type = second & 0x7f;
    return payload_type == CONTINUITY_MEDIA_PT_HEVC;
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

    /* The session, when it is known. A media flow is a different five-tuple
     * from the control channel that negotiated it, and which session it
     * belongs to is stated inside that channel's protected bodies. Until
     * those are read, the honest answer is that the capture does not say --
     * and not the address pair, which is right only while there is one
     * session between two devices and silently wrong the moment there are
     * two.
     */
    conversation_t *conversation = find_conversation_pinfo(pinfo, 0);
    if (conversation == NULL ||
        conversation_get_proto_data(conversation, proto_continuity) == NULL) {
        proto_item *unknown = proto_tree_add_string(
            media_tree, hf_media_session_unknown, tvb, 0, 0,
            "the control channel that negotiated this flow is protected, so the "
            "capture does not say which session it belongs to");
        proto_item_set_generated(unknown);
    }

    /* Why the RTP dissection shows this payload as data and under no format's
     * name: the format is known, but nothing of it is visible. */
    if ((tvb_get_uint8(tvb, 1) & 0x7f) == CONTINUITY_MEDIA_PT_HEVC) {
        proto_item *opaque = proto_tree_add_string(
            media_tree, hf_media_opaque, tvb, 0, 0,
            "HEVC video under SRTP: the packetisation is inside the encryption, "
            "so no decode applies to it");
        proto_item_set_generated(opaque);
    }

    /* Handed on rather than restated. */
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

    /* Before the conversation is claimed: setting the flow up with RTP
     * points a conversation at the RTP dissection, and it must not be this
     * one, or the next frame would skip this component. Done once, on the
     * first pass; RTP keeps what it needs per frame for later passes. */
    if (!PINFO_FD_VISITED(pinfo)) {
        rtp_dyn_payload_t *payloads = rtp_dyn_payload_new();
        rtp_dyn_payload_insert(payloads, CONTINUITY_MEDIA_PT_HEVC, CONTINUITY_MEDIA_OPAQUE_NAME,
                               CONTINUITY_MEDIA_CLOCK_RATE, 1);
        rtp_add_address(pinfo, PT_UDP, &pinfo->net_dst, pinfo->destport, pinfo->srcport,
                        "Continuity", pinfo->num, 0, payloads);
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
    };

    static int *ett[] = { &ett_continuity_media };

    proto_continuity_media = proto_register_protocol("Apple Continuity Media",
                                                     "Continuity Media", "continuity.media");
    proto_register_field_array(proto_continuity_media, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    media_handle = register_dissector("continuity.media", dissect_continuity_media,
                                      proto_continuity_media);
}

void proto_reg_handoff_continuity_media(void)
{
    rtp_handle = find_dissector("rtp");
    rtcp_handle = find_dissector("rtcp");
    heur_dissector_add("udp", dissect_continuity_media_heur, "Continuity media over UDP",
                       "continuity_media_udp", proto_continuity_media, HEURISTIC_ENABLE);
}
