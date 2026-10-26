/* packet-continuity-sidecar.c — the first service to read its own payload.
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
 * The transport hands a service the bounds of `_c` and knows nothing about
 * what is in it. This is what one service does with that.
 *
 * From a live Desk View session between an iPhone and a Mac, decrypted:
 *
 *     { "_i": "com.apple.sidecar", "_x": 2436866620, "_t": 1,
 *       "_c": { 0: <46 bytes> } }
 *
 * and those 46 bytes are themselves the object encoding, one level down:
 *
 *     e5                          dict, 5 entries
 *     0d 59 "com.apple.sidecar.capture"
 *     0e 33 47 90 72 e9 11 00 00 00
 *     0a 0b   0b 09   0c 32 cf 0e 3c 12
 *
 * It parses with nothing left over, and the last value -- 0x123c0ecf -- is the
 * same identifier that prefixes every stream name negotiated later in the same
 * session (`123C0ECF:ContinuityCaptureControl`, and five more). Two independent
 * readings agreeing on one number is what makes this a decode rather than a
 * plausible walk.
 *
 * Why it is nested at all is not established, and this does not guess: it
 * reports the inner object as what it is, an object encoding inside a byte
 * string, and leaves the reason to whoever finds it.
 */

#include "config.h"

#include <epan/packet.h>

#include <string.h>

#include "packet-continuity.h"

static int proto_sidecar = -1;

static int hf_sidecar_nested = -1;
static int hf_sidecar_inner = -1;
static int hf_sidecar_undecoded = -1;
static int hf_sidecar_version = -1;
static int hf_sidecar_body = -1;
static int hf_sidecar_body_uninterpreted = -1;

static int ett_sidecar = -1;
static int ett_sidecar_body = -1;

/* A member of the nested object's top level, by its integer key, when it is a
 * string. */
static const char *member_string(const continuity_envelope *inner, const char *key)
{
    for (unsigned m = 0; m < inner->member_count; m++) {
        if (!inner->members[m].in_content && strcmp(inner->members[m].key, key) == 0) {
            return inner->members[m].value;
        }
    }
    return NULL;
}

/* Whether this names a Sidecar sub-service: "com.apple.sidecar." followed by a
 * non-empty run of letters, digits, '.', '-' and '_' that neither starts nor
 * ends with '.'. */
static bool sub_service_name(const char *name)
{
    static const char prefix[] = "com.apple.sidecar.";
    if (name == NULL || !g_str_has_prefix(name, prefix)) {
        return false;
    }
    const char *rest = name + sizeof prefix - 1;
    size_t length = strlen(rest);
    if (length == 0 || rest[0] == '.' || rest[length - 1] == '.') {
        return false;
    }
    for (const char *c = rest; *c != '\0'; c++) {
        if (!g_ascii_isalnum(*c) && *c != '.' && *c != '-' && *c != '_') {
            return false;
        }
    }
    return true;
}

/* The nested object's keys, as every observed Sidecar message used them: the
 * sub-service under 5 (`com.apple.sidecar.capture`, once per session, in the
 * message opening it) and a Sidecar version under 10 ("279", "342.4.4", in the
 * time-sync inquiry and its answer). Other keys are reported as the object
 * decode reads them, without a meaning. */
#define SIDECAR_KEY_SERVICE "5"
#define SIDECAR_KEY_VERSION "10"

/* The second nested object, under key 1 of the content, which Sidecar
 * Display's messages carry after the first: in the sessions examined (iPad on
 * iPadOS 18.3.1 to a Mac on macOS 15.7.9) it holds the message's own names --
 * "ddisp", "init", "config", "start", and "vdisp" once per change of the
 * display's mode, mirrored or extended. Walked like the first, and not
 * interpreted. */
static void dissect_sidecar_body(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                 const continuity_envelope *envelope)
{
    int start = envelope->content_body_offset;
    int size = envelope->content_body_length;
    proto_item *body = proto_tree_add_item(tree, hf_sidecar_body, tvb, start, size, ENC_NA);
    proto_tree *body_tree = proto_item_add_subtree(body, ett_sidecar_body);
    continuity_envelope second = { 0 };
    continuity_opack_dissect_envelope(tvb, pinfo, body_tree, start, size, &second);
    proto_item *note = proto_tree_add_string(
        body_tree, hf_sidecar_body_uninterpreted, tvb, start, size,
        "the second nested object is shown as encoded; what its entries mean is not "
        "interpreted");
    proto_item_set_generated(note);
}

static void dissect_sidecar(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                            const continuity_envelope *envelope)
{
    if (!envelope->has_content_bytes) {
        /* Reported by not reporting: content of another shape keeps the bytes
         * the object decode already gave it, and gains nothing made up here. */
        return;
    }
    int start = envelope->content_bytes_offset;
    int size = envelope->content_bytes_length;

    proto_item *item = proto_tree_add_item(tree, proto_sidecar, tvb, start, size, ENC_NA);
    proto_tree *sidecar_tree = proto_item_add_subtree(item, ett_sidecar);

    /* The umbrella, before this decode contributes anything of its own. */
    continuity_mark(pinfo, sidecar_tree, tvb, NULL);

    proto_item *nested = proto_tree_add_item(sidecar_tree, hf_sidecar_nested, tvb, start, size,
                                             ENC_NA);
    proto_item_set_generated(nested);

    /* The same object decode, one level down: the encoding does not change
     * because it is nested, so neither does the code that reads it -- and
     * only an object it walked whole is read for names. */
    continuity_envelope inner = { 0 };
    continuity_opack_dissect_envelope(tvb, pinfo, sidecar_tree, start, size, &inner);
    if (envelope->has_content_body) {
        dissect_sidecar_body(tvb, pinfo, sidecar_tree, envelope);
    }
    if (!inner.complete) {
        return;
    }

    const char *version = member_string(&inner, SIDECAR_KEY_VERSION);
    if (version != NULL) {
        proto_item *v = proto_tree_add_string(sidecar_tree, hf_sidecar_version, tvb, start, size,
                                              version);
        proto_item_set_generated(v);
    }

    const char *name = member_string(&inner, SIDECAR_KEY_SERVICE);
    if (!sub_service_name(name)) {
        return;
    }
    proto_item *named = proto_tree_add_string(sidecar_tree, hf_sidecar_inner, tvb, start, size,
                                              name);
    proto_item_set_generated(named);

    const continuity_service *service = continuity_service_lookup(name);
    if (service != NULL) {
        continuity_service_report(pinfo, sidecar_tree, tvb, service);
        if (service->dissect_content != NULL) {
            service->dissect_content(tvb, pinfo, sidecar_tree, &inner);
        }
    } else {
        /* A Sidecar sub-service this decode does not interpret, such as the
         * display or annotation ones. Named, and its object walked like any
         * other, but nothing about what it means is claimed. */
        proto_item *undecoded = proto_tree_add_string(
            sidecar_tree, hf_sidecar_undecoded, tvb, start, size,
            "this sub-service's objects are not interpreted; its object is shown as encoded");
        proto_item_set_generated(undecoded);
    }
}

/* The services this file registers.
 *
 * `com.apple.sidecar` is what the envelope carries. `com.apple.sidecar.capture`
 * is named inside its payload, and is only visible *because* the decode above
 * exists -- which is the point: adding it took a registration and no change to
 * any transport field.
 */
static const continuity_service sidecar_services[] = {
    { "com.apple.sidecar",         "Sidecar",                 NULL, dissect_sidecar },
    { "com.apple.sidecar.capture", "Sidecar (camera capture)", NULL, NULL },
};

void proto_register_continuity_sidecar(void)
{
    static hf_register_info hf[] = {
        { &hf_sidecar_nested,
          { "Nested object", "continuity.sidecar.nested", FT_BYTES, BASE_NONE, NULL, 0x0,
            "The object encoding carried inside a byte string of this service's content",
            HFILL } },
        { &hf_sidecar_inner,
          { "Sub-service", "continuity.sidecar.service", FT_STRING, BASE_NONE, NULL, 0x0,
            "The sub-service the nested object names under key 5, e.g. com.apple.sidecar.capture",
            HFILL } },
        { &hf_sidecar_version,
          { "Sidecar version", "continuity.sidecar.version", FT_STRING, BASE_NONE, NULL, 0x0,
            "The version string the nested object carries under key 10", HFILL } },
        { &hf_sidecar_body,
          { "Second nested object", "continuity.sidecar.body", FT_BYTES, BASE_NONE, NULL, 0x0,
            "The object encoding carried under key 1 of this service's content", HFILL } },
        { &hf_sidecar_body_uninterpreted,
          { "Not interpreted", "continuity.sidecar.body_uninterpreted", FT_STRING, BASE_NONE,
            NULL, 0x0, "Why the second nested object is shown without interpretation", HFILL } },
        { &hf_sidecar_undecoded,
          { "Not interpreted", "continuity.sidecar.uninterpreted", FT_STRING, BASE_NONE, NULL,
            0x0, "Why this sub-service's object is shown without interpretation", HFILL } },
    };

    static int *ett[] = { &ett_sidecar, &ett_sidecar_body };

    proto_sidecar = proto_register_protocol("Apple Sidecar", "Sidecar", "continuity.sidecar");
    proto_register_field_array(proto_sidecar, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_continuity_sidecar(void)
{
    for (unsigned i = 0; i < array_length(sidecar_services); i++) {
        continuity_service_register(&sidecar_services[i]);
    }
}
