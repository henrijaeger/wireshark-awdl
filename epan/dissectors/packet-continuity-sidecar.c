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

#include "packet-continuity.h"

static int proto_sidecar = -1;

static int hf_sidecar_nested = -1;
static int hf_sidecar_inner = -1;
static int hf_sidecar_undecoded = -1;

static int ett_sidecar = -1;

/* Only the markers this decode needs, rather than the whole table: it is
 * looking for one shape it has seen, not walking arbitrary content. The walk
 * itself is the object decode's job and is called for that. */
#define OPACK_SMALL_INT_MIN 0x08
#define OPACK_SMALL_INT_MAX 0x2f
#define OPACK_STRING_MIN    0x40
#define OPACK_STRING_MAX    0x60
#define OPACK_BYTES_MIN     0x70
#define OPACK_BYTES_MAX     0x90
#define OPACK_BYTES_LEN1    0x91 /* one length byte follows, then the bytes */
#define OPACK_BYTES_LEN4    0x94
#define OPACK_DICT_MIN      0xe0
#define OPACK_DICT_MAX      0xef

/* The first string in an object, which for the inner one is the identifier of
 * the sub-service the message belongs to. Returns NULL when there is none --
 * a message whose payload is shaped differently is left alone rather than
 * having a service invented for it. */
static const char *first_string(tvbuff_t *tvb, packet_info *pinfo, int offset, int end)
{
    while (offset < end) {
        uint8_t marker = tvb_get_uint8(tvb, offset);
        if (marker >= OPACK_STRING_MIN && marker <= OPACK_STRING_MAX) {
            int length = marker - OPACK_STRING_MIN;
            if (length == 0 || offset + 1 + length > end) {
                return NULL;
            }
            return (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset + 1, length,
                                                    ENC_UTF_8);
        }
        if (marker >= OPACK_SMALL_INT_MIN && marker <= OPACK_SMALL_INT_MAX) {
            offset += 1;
            continue;
        }
        if (marker >= OPACK_DICT_MIN && marker <= OPACK_DICT_MAX) {
            offset += 1;
            continue;
        }
        /* Anything else and the shape is not the one this recognises. */
        return NULL;
    }
    return NULL;
}

/* Find the byte string inside the content, if the content is the one-entry
 * dictionary holding one. */
static bool nested_bounds(tvbuff_t *tvb, int offset, int end, int *start, int *length)
{
    if (offset >= end || tvb_get_uint8(tvb, offset) < OPACK_DICT_MIN) {
        return false;
    }
    offset += 1;

    while (offset < end) {
        uint8_t marker = tvb_get_uint8(tvb, offset);
        if (marker >= OPACK_SMALL_INT_MIN && marker <= OPACK_SMALL_INT_MAX) {
            offset += 1; /* the key */
            continue;
        }
        if (marker >= OPACK_BYTES_MIN && marker <= OPACK_BYTES_MAX) {
            int size = marker - OPACK_BYTES_MIN;
            if (size == 0 || offset + 1 + size > end) {
                return false;
            }
            *start = offset + 1;
            *length = size;
            return true;
        }
        if (marker >= OPACK_BYTES_LEN1 && marker <= OPACK_BYTES_LEN4) {
            /* A byte string too long to say its length in the marker says it
             * in the bytes that follow. Handling only the inline form read
             * the short payloads and silently skipped the long ones -- which
             * were the interesting ones, since the first message of a session
             * is the largest. */
            int width = marker - OPACK_BYTES_LEN1 + 1;
            if (offset + 1 + width > end) {
                return false;
            }
            uint64_t size = 0;
            for (int i = 0; i < width; i++) {
                size |= (uint64_t)tvb_get_uint8(tvb, offset + 1 + i) << (8 * i);
            }
            if (size == 0 || (uint64_t)(end - offset - 1 - width) < size) {
                return false;
            }
            *start = offset + 1 + width;
            *length = (int)size;
            return true;
        }
        return false;
    }
    return false;
}

static void dissect_sidecar(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                            int length)
{
    int start = 0;
    int size = 0;
    if (!nested_bounds(tvb, offset, offset + length, &start, &size)) {
        /* Reported by not reporting: a payload this decode does not recognise
         * keeps the bytes the object decode already gave it, and gains
         * nothing made up here. */
        return;
    }

    proto_item *item = proto_tree_add_item(tree, proto_sidecar, tvb, start, size, ENC_NA);
    proto_tree *sidecar_tree = proto_item_add_subtree(item, ett_sidecar);

    /* The umbrella, before this decode contributes anything of its own. */
    continuity_mark(pinfo, sidecar_tree, tvb, NULL);

    proto_item *nested = proto_tree_add_item(sidecar_tree, hf_sidecar_nested, tvb, start, size,
                                             ENC_NA);
    proto_item_set_generated(nested);

    /* The same object decode, one level down. The encoding does not change
     * because it is nested, so neither does the code that reads it. */
    continuity_opack_dissect(tvb, pinfo, sidecar_tree, start, size);

    /* The inner object names a more specific service than the envelope did.
     * Resolved through the same table: a service that learns to read its own
     * payload, or a further one underneath it, is a registration and not a
     * change to this function.
     */
    /* Only a string of the sub-service form names one. Other nested messages
     * begin with a different first string -- the time-sync inquiry and its
     * answer carry a Sidecar version such as "279" there. */
    const char *inner = first_string(tvb, pinfo, start, start + size);
    if (inner != NULL && !g_str_has_prefix(inner, "com.apple.sidecar.")) {
        inner = NULL;
    }
    if (inner != NULL) {
        proto_item *named = proto_tree_add_string(sidecar_tree, hf_sidecar_inner, tvb, start,
                                                  size, inner);
        proto_item_set_generated(named);
    }
    const continuity_service *service = continuity_service_lookup(inner);
    if (service != NULL) {
        continuity_service_report(pinfo, sidecar_tree, tvb, service);
        if (service->dissect != NULL) {
            service->dissect(tvb, pinfo, sidecar_tree, start, size);
        }
    } else if (inner != NULL) {
        /* A Sidecar sub-service this decode has not seen, such as the display
         * or annotation ones. Named, and its object walked like any other,
         * but nothing about what it means is claimed. */
        proto_item *undecoded = proto_tree_add_string(
            sidecar_tree, hf_sidecar_undecoded, tvb, start, size,
            "no observed session of this sub-service has been examined; its object is shown "
            "as encoded, without interpretation");
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
    { "com.apple.sidecar",         "Sidecar",                 dissect_sidecar },
    { "com.apple.sidecar.capture", "Sidecar (camera capture)", NULL },
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
            "The identifier the nested object names first, e.g. com.apple.sidecar.capture",
            HFILL } },
        { &hf_sidecar_undecoded,
          { "Not interpreted", "continuity.sidecar.uninterpreted", FT_STRING, BASE_NONE, NULL,
            0x0, "Why this sub-service's object is shown without interpretation", HFILL } },
    };

    static int *ett[] = { &ett_sidecar };

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
