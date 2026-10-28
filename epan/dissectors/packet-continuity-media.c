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
 * 3 (UDP media) carries a port from each end, and optionally an address
 * (`_streamAddr`). A UDP packet belongs to that stream when it was captured
 * after the negotiation and runs between the two ends' ports, each end at an
 * address it announced or at its end of the control connection: in a keyed
 * Camera session the media used the announced per-stream addresses on both
 * ends, while the message spec records media sent to the control connection's
 * address instead. The interface is not compared -- on a Mac the control
 * connection and the media travel on different interfaces (awdl0 or en0, and
 * llw0) -- and nothing that ends a flow has been observed, so none is assumed:
 * when two negotiations fit a packet equally it is reported as ambiguous and
 * given to neither. Each packet's association is worked out once, on the first
 * pass, so a revisit reports the same and a later negotiation never claims an
 * earlier packet.
 *
 * This needs the control channel decrypted; without it no flow is identified,
 * which is the honest result -- RTP with payload type 100 alone is any
 * application's dynamic type 100. A preference restores the old guess for
 * captures without keys, off by default.
 *
 * WHAT IS BOUND. Only what real sessions showed: Continuity Camera's two
 * video streams (DefaultVideo, DeskcamVideo) send payload type 100, and their
 * RTP timestamps advance at 24 kHz -- 24,004 to 24,225 ticks a second,
 * measured over six streams of two capture sessions, macOS 15.7.9 -- and so
 * does Sidecar Display's video (AVCVideoStream, see the table below).
 * Payload types are negotiated, not fixed, so this is what those sessions
 * chose. Every other stream -- the microphone included, whose payload type a
 * real Mac's answer chooses and no real-Mac capture has shown -- is read with
 * its observed payload type marked opaque and its clock rate unknown, rather
 * than with a rate carried over from elsewhere.
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
#include <epan/proto_data.h>
#include <epan/to_str.h>
#include <wsutil/inet_addr.h>

#include <string.h>

#include "packet-rtp.h"

#include "packet-continuity.h"

static int proto_continuity_media = -1;

static int hf_media_session_unknown = -1;
static int hf_media_opaque = -1;
static int hf_media_stream_id = -1;
static int hf_media_negotiated_in = -1;
static int hf_media_guessed = -1;
static int hf_media_ambiguous = -1;
static int hf_media_payload_binding = -1;

static int ett_continuity_media = -1;

static dissector_handle_t media_handle;
static dissector_handle_t rtp_handle;

static bool pref_guess_pt100 = false;

#define CONTINUITY_MEDIA_PT_GUESS 100

#define CONTINUITY_MEDIA_OPAQUE_NAME "Continuity media (opaque payload)"

#define RTP_VERSION_2 2

/* What the observed sessions bound, by the stream's name. A Sidecar session
 * names a stream "<session tag>:<name>"; the Rapport Continuity Camera
 * transport an iPhone on iOS 27 is driven through names it by <name> alone
 * (ContinuityCaptureMediaIdentifierDefaultVideo), at the same payload type and
 * clock rate (iPhone18,3 to a Mac on macOS 15.7.9, 2026-10-27).
 * AVCVideoStream is Sidecar Display's video, Mac to iPad, sent as four tiles
 * of consecutive SSRCs: payload type 100, and 24,005 to 24,136 ticks a second
 * over every tile of the three sessions that ran longer than 3 s (iPad on
 * iPadOS 18.3.1 to a Mac on macOS 15.7.9, 2026-10-26). */
static const struct {
    const char *name;
    int payload_type;
    int clock_rate;
} media_bindings[] = {
    { "ContinuityCaptureMediaIdentifierDefaultVideo", 100, 24000 },
    { "ContinuityCaptureMediaIdentifierDeskcamVideo", 100, 24000 },
    { "AVCVideoStream", 100, 24000 },
};

/* What an unbound stream's payload type is given: a name no decode is
 * registered for, and clock rate 0, which RTP's analysis takes as unknown. */
#define CONTINUITY_MEDIA_UNKNOWN_NAME "Continuity media (opaque payload, clock rate unknown)"

/* One end of a negotiated flow: the port it named, and the addresses media of
 * that end has been seen to use -- the one it announced in `_streamAddr`, and
 * the address of its control connection. Both are needed: in a keyed Camera
 * session the media ran between the announced per-stream addresses on both
 * ends, and the message spec records media sent to the control connection's
 * address instead. */
#define MEDIA_SIDE_ADDRS 2

typedef struct {
    uint32_t port;
    address addrs[MEDIA_SIDE_ADDRS];
    unsigned addr_count;
} media_side;

/* One negotiated flow: the requesting end and the answering end. */
typedef struct {
    media_side side[2];
    const char *stream_id;
    const char *session;
    uint32_t negotiated_in;
} media_flow;

/* What one packet was found to be, on the first pass, kept for every later
 * visit: the flow, or the first two of several that fit it equally. */
typedef struct {
    media_flow *flow;
    uint32_t direction;      /* which side of the flow sent it */
    unsigned candidates;     /* flows that fitted; more than one is ambiguous */
    uint32_t first_in;
    uint32_t second_in;
    /* The binding the packet is read with: the flow's, or, for an ambiguous
     * packet, the one every flow that fitted would use -- the same payload type
     * at the same clock rate. -1 when there is none, including when the flows
     * that fitted disagree (binding_conflict), so that the payload stays
     * opaque and its clock rate unknown rather than taking either's. */
    int binding;
    bool binding_conflict;
    bool guessed;
} media_match;

/* RTP is told how to read a flow per transport conversation, as
 * rtp_add_address() keys it: the destination address and port and the
 * source port, in one direction. One negotiation allows more than one such
 * conversation (an announced and a control address on each end), so this is
 * what records whether one has been set up, and with which binding. */
typedef struct {
    rtp_dyn_payload_t *payloads; /* this file's own reference; RTP holds another */
    int binding;
    uint32_t set_up_in;
} media_rtp_setup;

static wmem_map_t *rtp_setups;

/* Negotiated flows, listed per port pair (lowest first) in negotiation order. */
static wmem_map_t *flows;

static void media_init(void)
{
    flows = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
    rtp_setups = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
}

static void release_rtp_setup(void *key _U_, void *value, void *user_data _U_)
{
    rtp_dyn_payload_free(((media_rtp_setup *)value)->payloads);
}

static void media_cleanup(void)
{
    if (rtp_setups != NULL) {
        wmem_map_foreach(rtp_setups, release_rtp_setup, NULL);
        rtp_setups = NULL;
    }
    flows = NULL;
}

static void *port_pair_key(uint32_t a, uint32_t b)
{
    uint32_t low = a < b ? a : b;
    uint32_t high = a < b ? b : a;
    return GUINT_TO_POINTER((low << 16) | high);
}

static void side_add_address(media_side *side, const address *addr)
{
    if (addr == NULL || addr->type == AT_NONE || side->addr_count >= MEDIA_SIDE_ADDRS) {
        return;
    }
    for (unsigned i = 0; i < side->addr_count; i++) {
        if (addresses_equal(&side->addrs[i], addr)) {
            return;
        }
    }
    copy_address_wmem(wmem_file_scope(), &side->addrs[side->addr_count++], addr);
}

/* An announced `_streamAddr`, as an address, or AT_NONE when it is not one. */
static void announced_address(const char *text, address *out, uint8_t *storage)
{
    clear_address(out);
    if (text == NULL) {
        return;
    }
    if (ws_inet_pton6(text, (ws_in6_addr *)storage)) {
        set_address(out, AT_IPv6, 16, storage);
    } else if (ws_inet_pton4(text, (ws_in4_addr *)storage)) {
        set_address(out, AT_IPv4, 4, storage);
    }
}

void continuity_media_negotiated(packet_info *pinfo, const char *stream_id,
                                 const continuity_media_end *request,
                                 const continuity_media_end *answer)
{
    if (flows == NULL || PINFO_FD_VISITED(pinfo) || request->port == 0 || answer->port == 0 ||
        request->port > 65535 || answer->port > 65535) {
        return;
    }
    media_flow *flow = wmem_new0(wmem_file_scope(), media_flow);
    const continuity_media_end *ends[2] = { request, answer };
    for (unsigned s = 0; s < 2; s++) {
        uint8_t storage[16];
        address announced;
        announced_address(ends[s]->announced, &announced, storage);
        flow->side[s].port = ends[s]->port;
        side_add_address(&flow->side[s], &announced);
        side_add_address(&flow->side[s], ends[s]->control);
    }
    flow->stream_id = stream_id != NULL ? wmem_strdup(wmem_file_scope(), stream_id) : NULL;
    const char *session = continuity_session_get(pinfo);
    flow->session = session != NULL ? wmem_strdup(wmem_file_scope(), session) : NULL;
    flow->negotiated_in = pinfo->num;

    void *key = port_pair_key(request->port, answer->port);
    wmem_list_t *list = (wmem_list_t *)wmem_map_lookup(flows, key);
    if (list == NULL) {
        list = wmem_list_new(wmem_file_scope());
        wmem_map_insert(flows, key, list);
    }
    wmem_list_append(list, flow);

    /* A UDP conversation for each pairing of the two ends' addresses, starting
     * at this frame. Conversation dissectors are tried before heuristic ones,
     * so the flow's first packet is offered here whatever it is -- RTCP before
     * any RTP included -- and nothing before this frame can belong to one. */
    for (unsigned a = 0; a < flow->side[0].addr_count; a++) {
        for (unsigned b = 0; b < flow->side[1].addr_count; b++) {
            conversation_t *conversation =
                conversation_new(pinfo->num, &flow->side[0].addrs[a], &flow->side[1].addrs[b],
                                 CONVERSATION_UDP, flow->side[0].port, flow->side[1].port, 0);
            conversation_set_dissector_from_frame_number(conversation, pinfo->num, media_handle);
        }
    }
}

static bool side_has(const media_side *side, uint32_t port, const address *addr)
{
    if (side->port != port) {
        return false;
    }
    for (unsigned i = 0; i < side->addr_count; i++) {
        if (addresses_equal(&side->addrs[i], addr)) {
            return true;
        }
    }
    return false;
}

static int binding_for(const char *stream_id);
static bool same_binding(int a, int b);

/* Which negotiated flow this packet belongs to: one negotiated before it,
 * whose two ends' ports and addresses are this packet's source and
 * destination, in either direction. Nothing about a flow ending has been
 * observed, so a flow is not ended by anything; when two flows fit one packet
 * equally, the packet is reported as ambiguous rather than given to either. */
static media_match *match_packet(packet_info *pinfo)
{
    media_match *match = wmem_new0(pinfo->pool, media_match);
    match->binding = -1;
    if (flows == NULL) {
        return match;
    }
    wmem_list_t *list =
        (wmem_list_t *)wmem_map_lookup(flows, port_pair_key(pinfo->srcport, pinfo->destport));
    if (list == NULL) {
        return match;
    }
    for (wmem_list_frame_t *f = wmem_list_head(list); f != NULL; f = wmem_list_frame_next(f)) {
        media_flow *flow = (media_flow *)wmem_list_frame_data(f);
        if (flow->negotiated_in >= pinfo->num) {
            continue;
        }
        for (uint32_t from = 0; from < 2; from++) {
            if (side_has(&flow->side[from], pinfo->srcport, &pinfo->src) &&
                side_has(&flow->side[1 - from], pinfo->destport, &pinfo->dst)) {
                int binding = binding_for(flow->stream_id);
                if (match->candidates == 0) {
                    match->flow = flow;
                    match->direction = from;
                    match->first_in = flow->negotiated_in;
                    match->binding = binding;
                } else {
                    if (match->candidates == 1) {
                        match->second_in = flow->negotiated_in;
                    }
                    if (!same_binding(binding, match->binding)) {
                        match->binding_conflict = true;
                    }
                }
                match->candidates++;
                break;
            }
        }
    }
    if (match->candidates > 1) {
        match->flow = NULL;
    }
    if (match->binding_conflict) {
        match->binding = -1;
    }
    return match;
}

/* The binding the observed sessions used for a stream, or -1. */
static int binding_for(const char *stream_id)
{
    for (unsigned i = 0; stream_id != NULL && i < array_length(media_bindings); i++) {
        const char *name = media_bindings[i].name;
        size_t id_length = strlen(stream_id);
        size_t name_length = strlen(name);
        /* <name> itself, or <session tag>:<name> -- never a longer name that
         * merely ends in this one. */
        if (id_length >= name_length && strcmp(stream_id + id_length - name_length, name) == 0 &&
            (id_length == name_length || stream_id[id_length - name_length - 1] == ':')) {
            return (int)i;
        }
    }
    return -1;
}

/* Whether two bindings read a payload the same way: the same payload type at
 * the same clock rate (different stream names can share one), or both none. */
static bool same_binding(int a, int b)
{
    if (a < 0 || b < 0) {
        return a == b;
    }
    return media_bindings[a].payload_type == media_bindings[b].payload_type &&
           media_bindings[a].clock_rate == media_bindings[b].clock_rate;
}

/* RTP or, multiplexed with it (RFC 5761), RTCP: version 2, and long enough
 * for an RTP header or, with an RTCP packet type, for an RTCP one. */
#define RTCP_PT_MIN 192
#define RTCP_PT_MAX 223

static bool looks_like_rtp(tvbuff_t *tvb)
{
    unsigned length = tvb_captured_length(tvb);
    if (length < 8 || (tvb_get_uint8(tvb, 0) >> 6) != RTP_VERSION_2) {
        return false;
    }
    uint8_t type = tvb_get_uint8(tvb, 1);
    return length >= 12 || (type >= RTCP_PT_MIN && type <= RTCP_PT_MAX);
}

/* This packet's association, worked out once on the first pass. Only a packet
 * that has one keeps a record; no record on a later pass means none. */
static media_match *packet_match(tvbuff_t *tvb, packet_info *pinfo)
{
    media_match *match =
        (media_match *)p_get_proto_data(wmem_file_scope(), pinfo, proto_continuity_media, 0);
    if (match == NULL && !PINFO_FD_VISITED(pinfo)) {
        match = match_packet(pinfo);
        if (match->candidates == 0 && pref_guess_pt100 && looks_like_rtp(tvb) &&
            (tvb_get_uint8(tvb, 1) & 0x7f) == CONTINUITY_MEDIA_PT_GUESS) {
            match->guessed = true;
            match->binding = binding_for(":ContinuityCaptureMediaIdentifierDefaultVideo");
        }
        if (match->candidates > 0 || match->guessed) {
            match = (media_match *)wmem_memdup(wmem_file_scope(), match, sizeof *match);
            p_add_proto_data(wmem_file_scope(), pinfo, proto_continuity_media, 0, match);
        }
    }
    return match;
}

/* Give RTP the payload types and clock rate this packet's transport
 * conversation is read with, on the first pass -- once per conversation, not
 * per packet, so RTP's analysis of the flow runs on uninterrupted.
 *
 * A conversation is set up again only when the binding it must be read with
 * changes: a second negotiation that makes the packet ambiguous with a
 * different binding turns it opaque from that frame on, and the earlier frames
 * keep theirs. A payload type that has not been seen on the conversation is
 * added to the table RTP already holds, marked opaque with its clock rate
 * unknown -- without that, RTP reads dynamic types 100 and 101 as telephone
 * events. An RTCP packet names no payload type, so it sets the conversation up
 * with what is known and adds nothing. */
static void set_up_rtp(tvbuff_t *tvb, packet_info *pinfo, const media_match *match)
{
    if (PINFO_FD_VISITED(pinfo) || rtp_setups == NULL) {
        return;
    }
    uint8_t second = tvb_get_uint8(tvb, 1);
    bool rtcp = second >= RTCP_PT_MIN && second <= RTCP_PT_MAX;
    unsigned type = second & 0x7f;
    int binding = match->binding;

    char *key = wmem_strdup_printf(pinfo->pool, "%s/%u/%u",
                                   address_to_str(pinfo->pool, &pinfo->net_dst), pinfo->destport,
                                   pinfo->srcport);
    media_rtp_setup *setup = (media_rtp_setup *)wmem_map_lookup(rtp_setups, key);
    if (setup != NULL && setup->binding == binding) {
        if (!rtcp && rtp_dyn_payload_get_name(setup->payloads, type) == NULL) {
            rtp_dyn_payload_insert(setup->payloads, type, CONTINUITY_MEDIA_UNKNOWN_NAME, 0, 1);
        }
        return;
    }

    rtp_dyn_payload_t *payloads = rtp_dyn_payload_new();
    if (binding >= 0) {
        rtp_dyn_payload_insert(payloads, media_bindings[binding].payload_type,
                               CONTINUITY_MEDIA_OPAQUE_NAME, media_bindings[binding].clock_rate,
                               1);
    }
    if (!rtcp && rtp_dyn_payload_get_name(payloads, type) == NULL) {
        rtp_dyn_payload_insert(payloads, type, CONTINUITY_MEDIA_UNKNOWN_NAME, 0, 1);
    }
    rtp_add_address(pinfo, PT_UDP, &pinfo->net_dst, pinfo->destport, pinfo->srcport,
                    "Continuity", pinfo->num, 0, payloads);
    if (setup == NULL) {
        setup = wmem_new0(wmem_file_scope(), media_rtp_setup);
        wmem_map_insert(rtp_setups, wmem_strdup(wmem_file_scope(), key), setup);
    } else {
        rtp_dyn_payload_free(setup->payloads); /* RTP keeps its own reference */
    }
    setup->payloads = payloads;
    setup->binding = binding;
    setup->set_up_in = pinfo->num;
}

static int dissect_media(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    media_match *match = packet_match(tvb, pinfo);
    if (match == NULL || (match->candidates == 0 && !match->guessed) || !looks_like_rtp(tvb)) {
        return 0;
    }
    set_up_rtp(tvb, pinfo, match);

    proto_item *item = proto_tree_add_item(tree, proto_continuity_media, tvb, 0, 0, ENC_NA);
    proto_item_set_generated(item);
    proto_tree *media_tree = proto_item_add_subtree(item, ett_continuity_media);

    /* The umbrella, so that one selection reaches the media of a session as
     * well as its control channel and its advertisements. */
    continuity_mark(pinfo, media_tree, tvb, NULL);

    const media_flow *flow = match->flow;
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
        int binding = binding_for(flow->stream_id);
        proto_item *bound = proto_tree_add_string(
            media_tree, hf_media_payload_binding, tvb, 0, 0,
            binding < 0 ? "none: no real session of this stream has shown its payload type "
                          "and clock rate, so its payload is marked opaque and its clock "
                          "rate unknown"
                        : wmem_strdup_printf(pinfo->pool, "payload type %d at %d Hz",
                                             media_bindings[binding].payload_type,
                                             media_bindings[binding].clock_rate));
        proto_item_set_generated(bound);
    } else if (match->candidates > 1) {
        proto_item *ambiguous = proto_tree_add_string(
            media_tree, hf_media_ambiguous, tvb, 0, 0,
            wmem_strdup_printf(pinfo->pool,
                               "%u negotiations fit this packet's addresses and ports, in "
                               "frames %u and %u%s; nothing observed ends a flow, so which "
                               "one it belongs to is not known",
                               match->candidates, match->first_in, match->second_in,
                               match->candidates > 2 ? " and later" : ""));
        proto_item_set_generated(ambiguous);
        proto_item *bound = proto_tree_add_string(
            media_tree, hf_media_payload_binding, tvb, 0, 0,
            match->binding >= 0
                ? wmem_strdup_printf(pinfo->pool,
                                     "payload type %d at %d Hz, as every negotiation that fits "
                                     "binds it",
                                     media_bindings[match->binding].payload_type,
                                     media_bindings[match->binding].clock_rate)
            : match->binding_conflict
                ? "none: the negotiations that fit bind it differently, so its payload is "
                  "marked opaque and its clock rate unknown"
                : "none: no negotiation that fits has an observed binding, so its payload is "
                  "marked opaque and its clock rate unknown");
        proto_item_set_generated(bound);
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
            flow == NULL ? "no single negotiation of this flow was read, so the capture does "
                           "not say which session it belongs to"
                         : "the flow's negotiation was read, but not its session's handshake");
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

static int dissect_continuity_media(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                    void *data)
{
    return dissect_media(tvb, pinfo, tree, data);
}

static bool dissect_continuity_media_heur(tvbuff_t *tvb, packet_info *pinfo,
                                          proto_tree *tree, void *data)
{
    if (!looks_like_rtp(tvb)) {
        return false;
    }
    media_match *match = packet_match(tvb, pinfo);
    if (match == NULL || (match->candidates == 0 && !match->guessed)) {
        return false;
    }

    /* From this frame on, not before it: a packet of this address and port
     * pair that came before the negotiation is not this flow's. */
    conversation_t *conversation = find_or_create_conversation(pinfo);
    conversation_set_dissector_from_frame_number(conversation, pinfo->num, media_handle);
    return dissect_media(tvb, pinfo, tree, data) > 0;
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
            "The frame whose `_streamStart` response completed this flow's negotiation; only "
            "a negotiation before a packet is considered for it",
            HFILL } },
        { &hf_media_guessed,
          { "Guessed", "continuity.media.guessed", FT_STRING, BASE_NONE, NULL, 0x0,
            "This flow was taken for Continuity media without its negotiation", HFILL } },
        { &hf_media_ambiguous,
          { "Ambiguous", "continuity.media.ambiguous", FT_STRING, BASE_NONE, NULL, 0x0,
            "More than one negotiation fits this packet, so it is given to none of them",
            HFILL } },
        { &hf_media_payload_binding,
          { "Payload binding", "continuity.media.payload_binding", FT_STRING, BASE_NONE, NULL,
            0x0, "The payload type and RTP clock rate this stream is read with, or why none is",
            HFILL } },
    };

    static int *ett[] = { &ett_continuity_media };

    proto_continuity_media = proto_register_protocol("Apple Continuity Media",
                                                     "Continuity Media", "continuity.media");
    proto_register_field_array(proto_continuity_media, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    media_handle = register_dissector("continuity.media", dissect_continuity_media,
                                      proto_continuity_media);

    register_init_routine(media_init);
    register_cleanup_routine(media_cleanup);
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
