/* packet-continuity-companion.c — the companion link's request/response framing.
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
 * Every message the companion link carries sits in the same three-key
 * envelope, whatever service sent it:
 *
 *     { "_c": <the content>, "_t": <kind>, "_x": <exchange id> }
 *
 * Read off the wire, from a request and its reply in one recorded session:
 *
 *     frame 40, initiator -> responder   _t = 2   _x = 0xdbe687a7
 *     frame 42, responder -> initiator   _t = 3   _x = 0xdbe687a7
 *
 * The exchange id is the same on both halves. That is what this decode is for:
 * it is the only thing that says which reply answers which request, on a link
 * that multiplexes several services and does not deliver replies in order. The
 * host's own log prints the same value -- `XID 0x6B000C8E` on a send and on the
 * matching receive -- so a record decoded here and a log line can be put beside
 * each other on a value both of them carry.
 *
 * What is deliberately *not* claimed: that `_t` 2 means request and 3 means
 * response. That is what one observed exchange is consistent with, and one
 * exchange is not enough to name a field after. So the kind is reported as the
 * number it is, and the request/response relationship is reported separately,
 * derived from the exchange id: the first frame of an exchange and the one
 * that answers it are identified by *pairing*, which is structural, rather
 * than by trusting a number whose meaning was inferred once.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/proto_data.h>

#include "packet-continuity.h"

static int proto_companion = -1;

static int hf_companion_xid = -1;
static int hf_companion_event = -1;
static int hf_companion_kind = -1;
static int hf_companion_answered_in = -1;
static int hf_companion_answers = -1;
static int hf_companion_elapsed = -1;

static int ett_companion = -1;

/* One exchange, while the capture is being read. */
typedef struct {
    uint32_t request_frame;
    uint32_t response_frame;
    nstime_t request_time;
    /* The request's event, so the response -- which carries none -- can be
     * summarised by what it answers. */
    const char *request_event;
} companion_exchange;

/* Per-frame, so that a second visit reports what the first worked out. */
typedef struct {
    uint32_t answered_in;
    uint32_t answers;
    nstime_t elapsed;
    bool has_elapsed;
    const char *answers_event; /* the answered request's event, if it had one */
} companion_frame;

/* Exchanges are per-conversation: the id is unique within a link, and two
 * links may both be running one. */
typedef struct {
    wmem_map_t *exchanges;
} companion_conversation;

static companion_conversation *conversation_state(packet_info *pinfo)
{
    conversation_t *conversation = find_or_create_conversation(pinfo);
    if (conversation == NULL) {
        return NULL;
    }
    companion_conversation *state =
        (companion_conversation *)conversation_get_proto_data(conversation, proto_companion);
    if (state == NULL) {
        state = wmem_new0(wmem_file_scope(), companion_conversation);
        state->exchanges = wmem_map_new(wmem_file_scope(), g_int64_hash, g_int64_equal);
        conversation_add_proto_data(conversation, proto_companion, state);
    }
    return state;
}

/* Pair this frame with the other half of its exchange, once, on the first
 * pass. Everything after that reads what this recorded. */
static companion_frame *pair_exchange(packet_info *pinfo, uint64_t xid, const char *event)
{
    companion_frame *frame = wmem_new0(wmem_file_scope(), companion_frame);
    companion_conversation *state = conversation_state(pinfo);
    if (state == NULL) {
        return frame;
    }

    uint64_t *key = wmem_new(wmem_file_scope(), uint64_t);
    *key = xid;
    companion_exchange *exchange = (companion_exchange *)wmem_map_lookup(state->exchanges, key);

    if (exchange == NULL) {
        exchange = wmem_new0(wmem_file_scope(), companion_exchange);
        exchange->request_frame = pinfo->num;
        exchange->request_time = pinfo->abs_ts;
        exchange->request_event = event == NULL ? NULL : wmem_strdup(wmem_file_scope(), event);
        wmem_map_insert(state->exchanges, key, exchange);
        return frame;
    }

    /* The second frame of an exchange answers the first. A third would be
     * neither, and is left unpaired rather than overwriting the pairing --
     * an id reused later in a long session is the likely cause, and a wrong
     * pairing reads as a real one. */
    if (exchange->response_frame == 0 && exchange->request_frame != pinfo->num) {
        exchange->response_frame = pinfo->num;
        frame->answers = exchange->request_frame;
        frame->answers_event = exchange->request_event;
        nstime_delta(&frame->elapsed, &pinfo->abs_ts, &exchange->request_time);
        frame->has_elapsed = true;
    }
    return frame;
}

const char *continuity_companion_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                        const continuity_envelope *envelope)
{
    if (envelope == NULL || !envelope->has_xid) {
        return envelope != NULL && envelope->has_event ? envelope->event : NULL;
    }

    proto_item *item = proto_tree_add_item(tree, proto_companion, tvb, 0, 0, ENC_NA);
    proto_item_set_generated(item);
    proto_tree *companion_tree = proto_item_add_subtree(item, ett_companion);

    /* The umbrella first, before this decode contributes anything of its own. */
    continuity_mark(pinfo, companion_tree, tvb, NULL);

    proto_item *xid =
        proto_tree_add_uint64(companion_tree, hf_companion_xid, tvb, 0, 0, envelope->xid);
    proto_item_set_generated(xid);

    /* What the sender called this message. Reported as the event identifier
     * it is rather than as a service: some values are a service in reverse-DNS
     * form (`com.apple.sidecar`) and some name a message of the link itself
     * (`_systemInfo`, `_streamStart`), and calling the second kind a service
     * would invent one.
     */
    const continuity_service *service = NULL;
    if (envelope->has_event && envelope->event != NULL) {
        proto_item *event =
            proto_tree_add_string(companion_tree, hf_companion_event, tvb, 0, 0, envelope->event);
        proto_item_set_generated(event);

        /* Resolved through the table, so a further service is a registration
         * rather than a change here. An event nothing registered stays an
         * event and gains no service. */
        service = continuity_service_lookup(envelope->event);
        continuity_service_report(pinfo, companion_tree, tvb, service);
    }

    /* The service reads its own payload. The transport hands over the bounds
     * of `_c` and knows nothing about what is in it, which is what keeps a
     * second service from needing a change to this file. */
    if (service != NULL && service->dissect != NULL && envelope->content_length > 0) {
        service->dissect(tvb, pinfo, companion_tree, envelope->content_offset,
                         envelope->content_length);
    }

    if (envelope->has_type) {
        proto_item *kind =
            proto_tree_add_int64(companion_tree, hf_companion_kind, tvb, 0, 0, envelope->type);
        proto_item_set_generated(kind);
    }

    companion_frame *frame =
        (companion_frame *)p_get_proto_data(wmem_file_scope(), pinfo, proto_companion, 0);
    if (frame == NULL) {
        frame = pair_exchange(pinfo, envelope->xid, envelope->has_event ? envelope->event : NULL);
        p_add_proto_data(wmem_file_scope(), pinfo, proto_companion, 0, frame);
    }

    if (frame->answers != 0) {
        proto_item *answers = proto_tree_add_uint(companion_tree, hf_companion_answers, tvb, 0, 0,
                                                  frame->answers);
        proto_item_set_generated(answers);
        if (frame->has_elapsed) {
            proto_item *elapsed = proto_tree_add_time(companion_tree, hf_companion_elapsed, tvb, 0,
                                                      0, &frame->elapsed);
            proto_item_set_generated(elapsed);
        }
    }

    /* The forward reference is filled in on the frame that was answered, which
     * is only knowable once the answer has been seen -- so it is looked up
     * here rather than recorded there. */
    companion_conversation *state = conversation_state(pinfo);
    if (state != NULL) {
        uint64_t key_value = envelope->xid;
        companion_exchange *exchange =
            (companion_exchange *)wmem_map_lookup(state->exchanges, &key_value);
        if (exchange != NULL && exchange->request_frame == pinfo->num &&
            exchange->response_frame != 0) {
            proto_item *answered = proto_tree_add_uint(companion_tree, hf_companion_answered_in,
                                                       tvb, 0, 0, exchange->response_frame);
            proto_item_set_generated(answered);
        }
    }

    /* What a one-line summary should call this message. A response carries
     * no event of its own, so it is named by the request it answers -- which
     * is what an investigator searching for an event wants to find too. */
    if (envelope->has_event && envelope->event != NULL) {
        return envelope->event;
    }
    if (frame->answers_event != NULL) {
        return wmem_strdup_printf(pinfo->pool, "%s response", frame->answers_event);
    }
    return NULL;
}

void proto_register_continuity_companion(void)
{
    static hf_register_info hf[] = {
        { &hf_companion_xid,
          { "Exchange", "continuity.companion.xid", FT_UINT64, BASE_HEX, NULL, 0x0,
            "The value both halves of one exchange carry, and the only thing that says "
            "which reply answers which request on a link carrying several services at "
            "once. The host's own log prints the same value", HFILL } },
        { &hf_companion_event,
          { "Event", "continuity.companion.event", FT_STRING, BASE_NONE, NULL, 0x0,
            "What the sender called this message, from the envelope's `_i`. Some values "
            "name a service and some name a message of the link itself, so this is the "
            "identifier as sent; `continuity.service` says which of them resolved to a "
            "service this component knows", HFILL } },
        { &hf_companion_kind,
          { "Kind", "continuity.companion.kind", FT_INT64, BASE_DEC, NULL, 0x0,
            "The envelope's `_t`, reported as the number it is. One observed exchange "
            "sent 2 and was answered with 3, which is not enough to name the values -- "
            "the request and reply relationship is reported separately, from the "
            "exchange id, which is structural", HFILL } },
        { &hf_companion_answered_in,
          { "Answered in", "continuity.companion.answered_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "The frame carrying the other half of this exchange", HFILL } },
        { &hf_companion_answers,
          { "Answers", "continuity.companion.answers", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "The frame this one answers, paired on the exchange id", HFILL } },
        { &hf_companion_elapsed,
          { "Time since request", "continuity.companion.elapsed", FT_RELATIVE_TIME, BASE_NONE,
            NULL, 0x0, "How long the other end took to answer", HFILL } },
    };

    static int *ett[] = { &ett_companion };

    proto_companion = proto_register_protocol("Rapport Companion Link", "CompanionLink",
                                              "continuity.companion");
    proto_register_field_array(proto_companion, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_continuity_companion(void)
{
    /* Attaches to nothing on its own: the envelope is inside a body that only
     * the transport decode can produce, cleartext or decrypted, so the
     * transport calls this rather than a dissector table finding it. */
}
