/* packet-continuity.c — the umbrella, the service table, the session binding.
 *
 * Copyright (C) 2026  Henri Jäger
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/proto_data.h>

#include "packet-continuity.h"

int proto_continuity = -1;

int hf_continuity_service = -1;
int hf_continuity_session = -1;
static int hf_continuity_service_name = -1;

static int ett_continuity = -1;

/* The service table. Small and fixed at registration time, so a linear walk
 * costs nothing and a hash would be machinery for its own sake. Growing it is
 * a registration from a sub-decode, which is the property that makes a second
 * service cheap. */
#define CONTINUITY_SERVICES_MAX 32
static const continuity_service *services[CONTINUITY_SERVICES_MAX];
static unsigned service_count;

void continuity_service_register(const continuity_service *service)
{
    if (service == NULL || service_count >= CONTINUITY_SERVICES_MAX) {
        return;
    }
    services[service_count++] = service;
}

const continuity_service *continuity_service_lookup(const char *id)
{
    if (id == NULL) {
        return NULL;
    }
    for (unsigned i = 0; i < service_count; i++) {
        if (strcmp(services[i]->id, id) == 0) {
            return services[i];
        }
    }
    return NULL;
}

/* What is remembered per conversation: the session's cleartext ephemeral
 * public key, as hex. Stored as a string because that is what the field holds
 * and what an operator pastes into a filter; the bytes are in the capture. */
typedef struct {
    char *session;
} continuity_conversation;

static continuity_conversation *conversation_state(packet_info *pinfo, bool create)
{
    conversation_t *conversation = find_or_create_conversation(pinfo);
    if (conversation == NULL) {
        return NULL;
    }
    continuity_conversation *state =
        (continuity_conversation *)conversation_get_proto_data(conversation, proto_continuity);
    if (state == NULL && create) {
        state = wmem_new0(wmem_file_scope(), continuity_conversation);
        conversation_add_proto_data(conversation, proto_continuity, state);
    }
    return state;
}

const char *continuity_session_get(packet_info *pinfo)
{
    const continuity_conversation *state = conversation_state(pinfo, false);
    return state != NULL ? state->session : NULL;
}

void continuity_session_set(packet_info *pinfo, const uint8_t *ephemeral_key, unsigned len)
{
    if (ephemeral_key == NULL || len == 0) {
        return;
    }
    continuity_conversation *state = conversation_state(pinfo, true);
    if (state == NULL || state->session != NULL) {
        /* The first handshake message of a conversation names the session.
         * A later one carrying a different key is the peer's half of the same
         * exchange, not a second session, so the first is kept. */
        return;
    }
    state->session = (char *)wmem_alloc(wmem_file_scope(), len * 2 + 1);
    for (unsigned i = 0; i < len; i++) {
        snprintf(state->session + i * 2, 3, "%02x", ephemeral_key[i]);
    }
}

void continuity_session_report(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb)
{
    continuity_conversation *state = conversation_state(pinfo, false);
    if (state == NULL || state->session == NULL || tree == NULL) {
        return;
    }
    proto_item *item =
        proto_tree_add_string(tree, hf_continuity_session, tvb, 0, 0, state->session);
    /* Generated: the value is in this conversation's handshake, not in this
     * frame. Saying otherwise would point an operator at bytes that are not
     * there. */
    proto_item_set_generated(item);
}

proto_tree *continuity_mark(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb,
                           const continuity_service *service)
{
    if (tree == NULL) {
        return tree;
    }

    /* A zero-length item of the umbrella protocol. Its presence is what
     * `continuity` matches on, which is why selection works across records
     * that share no byte: it is a property of the record, not a position in
     * it. */
    proto_item *item = proto_tree_add_item(tree, proto_continuity, tvb, 0, 0, ENC_NA);
    proto_item_set_generated(item);
    proto_tree *subtree = proto_item_add_subtree(item, ett_continuity);

    continuity_service_report(pinfo, subtree, tvb, service);
    continuity_session_report(pinfo, subtree, tvb);
    return tree;
}

void continuity_service_report(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb,
                               const continuity_service *service)
{
    if (tree == NULL || service == NULL) {
        /* No service is the honest report for a transport record whose
         * service is not yet known -- the companion link carries several, and
         * which one a frame belongs to is often only decidable once its body
         * has been read. An absent attribute says that; a guessed one does
         * not. */
        return;
    }
    proto_item *item = proto_tree_add_string(tree, hf_continuity_service, tvb, 0, 0, service->id);
    proto_item_set_generated(item);
    item = proto_tree_add_string(tree, hf_continuity_service_name, tvb, 0, 0, service->name);
    proto_item_set_generated(item);
}

void proto_register_continuity(void)
{
    static hf_register_info hf[] = {
        { &hf_continuity_service,
          { "Service", "continuity.service", FT_STRING, BASE_NONE, NULL, 0x0,
            "The Continuity service this record belongs to, selectable across "
            "every transport that service uses", HFILL } },
        { &hf_continuity_service_name,
          { "Service name", "continuity.service_name", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL } },
        { &hf_continuity_session,
          { "Session", "continuity.session", FT_STRING, BASE_NONE, NULL, 0x0,
            "The handshake's cleartext ephemeral public key, which identifies "
            "this session in the capture itself", HFILL } },
    };

    static int *ett[] = { &ett_continuity };

    proto_continuity = proto_register_protocol("Apple Continuity", "Continuity", "continuity");
    proto_register_field_array(proto_continuity, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* The key store's preference hangs off this protocol, so it is registered
     * from here rather than as a dissector of its own.
     *
     * Not a stylistic choice. Registration routines do not run in an order
     * the code can rely on -- when this was a loadable module, registering
     * the key store separately put its preference registration before this
     * line, and a preference on a protocol that does not exist yet aborts the
     * program at startup. Calling it here makes the order a fact of the code
     * rather than an assumption about whatever generates the registration
     * list.
     */
    continuity_keys_register(proto_continuity);
}

void proto_reg_handoff_continuity(void)
{
    /* The umbrella attaches to nothing on its own. It is contributed by the
     * sub-decodes, which is what lets one name span layers that have no
     * dissector in common. */
    continuity_keys_handoff();
}
