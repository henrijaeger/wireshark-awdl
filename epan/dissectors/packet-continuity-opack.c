/* packet-continuity-opack.c — the object encoding the control channel carries.
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
 * Apple's OPACK: a self-describing container of dictionaries, arrays,
 * strings, integers and byte strings, in which every value begins with one
 * marker byte that says what it is and how long it is.
 *
 * The markers decoded here were read off captures of real sessions rather
 * than taken from a specification:
 *
 *     e1 43 5f 70 64 91 28 ...   dict(1), string(3) "_pd", data(0x28)
 *     e1 43 5f 70 64 73 06 01 04 dict(1), string(3) "_pd", data(3)
 *     ... 42 5f 69 61 24 ...     string(2), then string(1-byte length 0x24)
 *
 * so the four forms above -- inline-length dicts, inline-length strings,
 * inline-length byte strings, and a byte string or string with a following
 * length -- are the ones seen on the air. The rest of the table follows the
 * same shape and is decoded on the same terms, and anything whose marker is not in it stops the walk and is
 * reported as undecoded bytes rather than guessed at. A container decoder
 * that resynchronises after a marker it did not understand reports a
 * structure that was never sent.
 *
 * BACK-REFERENCES. A value the message already carried is usually sent again
 * as a reference to it. The rule was read from the platform itself --
 * CoreUtils 742.5.2 (macOS 14.7.5), by encoding known objects with its
 * OPACKEncoderCreateData and feeding hand-made bodies to its OPACKDecodeData:
 *
 *   - one table per message, shared by keys and values, in the order objects
 *     are transmitted in full -- every one, an equal earlier entry
 *     notwithstanding; a reference adds nothing to it;
 *   - strings, data, UUIDs, dates, floats and sized integers (0x30..0x33)
 *     enter it; booleans, null, inline integers and containers never do;
 *   - 0xa0..0xc0 refer to index marker - 0xa0 (0..32); 0xc1..0xc4 carry the
 *     index in the next 1..4 bytes, little-endian (the encoder uses 0xc1 from
 *     index 33, 0xc2 once one byte is not enough).
 *
 * It looks de-duplicated from captures, because the encoder never sends a
 * duplicate in full; the platform's decoder shows it is not. With this rule
 * every decrypted body of continuity-camera.pcapng (24),
 * continuity-handshake-decrypted.pcapng (88) and a view-switch session of
 * 2026-10-12 (108) decodes to its last byte, the _camCapUpdate and
 * _systemInfo bodies that used to stop included. A reference this rule cannot
 * resolve stops the walk with its index and the table size -- which is also
 * what the platform's own decoder does with one.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <wsutil/time_util.h>
#include <wsutil/to_str.h>

#include <inttypes.h>
#include <math.h>
#include <time.h>
#include <string.h>

#include "packet-continuity.h"

static int proto_opack = -1;

static int hf_opack_key = -1;
static int hf_opack_string = -1;
static int hf_opack_int = -1;
static int hf_opack_float = -1;
static int hf_opack_uuid = -1;
static int hf_opack_date = -1;
static int hf_opack_ref_index = -1;
static int hf_opack_bool = -1;
static int hf_opack_null = -1;
static int hf_opack_bytes = -1;
static int hf_opack_dict = -1;
static int hf_opack_array = -1;
static int hf_opack_undecoded = -1;
static int hf_opack_member = -1;

static int ett_opack = -1;
static int ett_opack_value = -1;

static expert_field ei_opack_undecoded;
static expert_field ei_opack_truncated;
static expert_field ei_opack_malformed;
static expert_field ei_opack_bad_date;
static expert_field ei_opack_envelope_type;

/* Markers, as observed. */
#define OPACK_TERMINATOR    0x03
#define OPACK_TRUE          0x01
#define OPACK_FALSE         0x02
#define OPACK_NULL          0x04
#define OPACK_UUID          0x05 /* 16 bytes */
#define OPACK_DATE          0x06 /* 8-byte little-endian double, seconds since 2001 */
/* Inline integers -1..39: the value is marker - OPACK_SMALL_INT_ZERO. The
 * platform's encoder writes -1 as 0x07, which is why the range starts there. */
#define OPACK_SMALL_INT_MIN  0x07
#define OPACK_SMALL_INT_ZERO 0x08
#define OPACK_SMALL_INT_MAX  0x2f
#define OPACK_INT8          0x30
#define OPACK_INT16         0x31
#define OPACK_INT32         0x32
#define OPACK_INT64         0x33
#define OPACK_FLOAT32       0x35 /* 4-byte little-endian IEEE 754 single */
#define OPACK_FLOAT64       0x36 /* 8-byte little-endian IEEE 754 double */
#define OPACK_REF_MIN       0xa0 /* back-reference to index marker - 0xa0 */
#define OPACK_REF_MAX       0xc0
#define OPACK_REF_LEN1      0xc1 /* back-reference, index in the next 1..4 bytes */
#define OPACK_REF_LEN4      0xc4
#define OPACK_STRING_MIN    0x40 /* 0x40 + n, n bytes of string */
#define OPACK_STRING_MAX    0x60
#define OPACK_STRING_LEN1   0x61 /* one length byte follows, then the string */
#define OPACK_STRING_LEN4   0x64
#define OPACK_BYTES_MIN     0x70 /* 0x70 + n, n bytes */
#define OPACK_BYTES_MAX     0x90
#define OPACK_BYTES_LEN1    0x91
#define OPACK_BYTES_LEN4    0x94
#define OPACK_ARRAY_MIN     0xd0 /* 0xd0 + n entries */
#define OPACK_ARRAY_ENDLESS 0xdf
#define OPACK_DICT_MIN      0xe0 /* 0xe0 + n entries */
#define OPACK_DICT_ENDLESS  0xef

/* How deep a container may nest before the walk gives up. Not a property of
 * the encoding: a bound on what a malformed or hostile body can make this do,
 * since the length fields come from the packet. */
#define OPACK_MAX_DEPTH 16

/* The longest member path, in bytes including the terminator. A longer one is
 * cut and ends in an ellipsis; its member is still reported. */
#define OPACK_PATH_MAX 256

/* How many objects one message's reference table holds. Far more than any
 * observed message carries; the bound exists because the count comes from the
 * packet. Exceeding it stops the walk. */
#define OPACK_TABLE_MAX 4096

/* How many bytes of string and byte-string values one message may put into
 * the tree, counting every back-reference at the size of what it names.
 *
 * A reference costs one or two bytes on the wire and names an object of any
 * size, so the table bound alone does not bound the output: 2 KiB of body
 * referring to one long byte string again and again expands to megabytes.
 * Decrypted Continuity Camera bodies stay far below this (the largest observed
 * message puts a few KiB of values into the tree). On reaching it the walk
 * stops, says why, and leaves the rest of the body visible as bytes. */
#define OPACK_EXPANSION_MAX (1024 * 1024)

/* How many values one message may hold -- every scalar, container and
 * dictionary key, each back-reference counted as one. Decoded Continuity
 * Camera messages hold at most 439 (the largest of 131 messages in a keyed
 * view-switch session); this leaves room for messages many times larger while
 * bounding what a body of empty values, which costs no expansion, can make the
 * walk do. */
#define OPACK_VALUES_MAX 16384

/* How many bytes of member text one message may generate, counting each
 * member's path, separator and value before it is formatted. The values are
 * bounded above, but a long path is repeated on every member beneath it, so a
 * short body of references under a long key generates text out of all
 * proportion to it. Observed messages generate at most 10,778 bytes.
 * OPACK_TEXT_RESERVE of it is kept back for the diagnostic that ends a walk. */
#define OPACK_TEXT_MAX (1024 * 1024)
#define OPACK_TEXT_RESERVE (OPACK_PATH_MAX + 64)

/* How many bytes of a byte string a member's text spells out. The bytes
 * themselves stay in the byte field; the member is for selecting by value, and
 * a hex rendering three times the size of a long value selects nothing better
 * than its start does. */
#define OPACK_MEMBER_BYTES_MAX 64

/* What the value just walked was. Set by every value as it finishes, so after
 * a container it names the container and not that container's last leaf. */
typedef enum {
    OPACK_KIND_NONE,
    OPACK_KIND_BOOL,
    OPACK_KIND_NULL,
    OPACK_KIND_INT,
    OPACK_KIND_FLOAT,
    OPACK_KIND_STRING,
    OPACK_KIND_BYTES,
    OPACK_KIND_UUID,
    OPACK_KIND_DATE,
    OPACK_KIND_ARRAY,
    OPACK_KIND_DICT,
} opack_kind;

static const char *const opack_kind_names[] = {
    "nothing", "a boolean", "null", "an integer", "a float", "a string", "a byte string",
    "a UUID", "a date", "an array", "a dictionary",
};

typedef struct {
    packet_info *pinfo;
    tvbuff_t *tvb;
    int end;
    bool stopped; /* a marker the walk does not know; nothing after it is read */

    /* What the value just walked was, and its value where it is a scalar a
     * caller may need rather than only a rendering of.
     *
     * Kept on the walk rather than returned, so that the recursive step keeps
     * its one job -- reporting fields -- and nothing above it has to thread a
     * result through every container. `last_string`, `last_int` and
     * `last_bool` are meaningful only while `kind` says the value was of
     * their type.
     */
    opack_kind kind;
    const char *last_string;
    int64_t last_int;
    bool last_bool;
    int last_bytes_offset;
    int last_bytes_length;

    /* String and byte-string bytes put into the tree so far; see
     * OPACK_EXPANSION_MAX. Values walked and member text generated so far; see
     * OPACK_VALUES_MAX and OPACK_TEXT_MAX. */
    size_t expanded;
    unsigned values;
    size_t text;

    /* Why the walk stopped or found the body malformed, when it did. */
    const char *problem;

    /* The envelope entries seen so far at the top level, one bit each for
     * _x, _t, _i and _c, so that a repeated one is noticed. */
    unsigned envelope_seen;

    /* Filled for the outermost dictionary's entries, when it looks like the
     * companion link's request/response envelope. */
    continuity_envelope *envelope;

    /* Where in the message the walk is: keys joined with '.', array elements
     * as [i]. What makes a member reportable as one value -- path and value
     * together -- so no generic flattening of the tree can separate a key
     * from its value again. Bounded: the depth and the keys come from the
     * packet. */
    char path[OPACK_PATH_MAX];
    size_t path_len;
    bool path_truncated;

    /* Set while a dictionary key is being read. A key is itself an encoded
     * value and is walked as one, but it is a name, not a member. */
    bool in_key;

    /* Every object transmitted in full that a back-reference can name, in
     * transmission order (see the header). */
    wmem_array_t *table;

    /* The depth at which the entries of `_c` are walked, while they are; 0
     * otherwise. Entries deeper than that are inside `_c` too, nested. */
    int content_depth;
} opack_walk;

typedef enum {
    OPACK_OBJECT_STRING,
    OPACK_OBJECT_BYTES,
    OPACK_OBJECT_INT,
    OPACK_OBJECT_FLOAT32,
    OPACK_OBJECT_FLOAT64,
    OPACK_OBJECT_UUID,
    OPACK_OBJECT_DATE,
} opack_object_kind;

/* One table entry: its kind, its value, and -- for bytes and UUIDs -- where it
 * was in the body, so a reference reports the bytes that were sent. */
typedef struct {
    opack_object_kind kind;
    const char *string;
    int64_t integer;
    double real;
    int offset;
    int length;
    /* The member text, rendered once on first use and reused by every
     * reference to this object. */
    const char *text;
} opack_object;

static int opack_value(opack_walk *walk, proto_tree *tree, int offset, int depth,
                       const char *key);

/* Record one dictionary entry's value for the summary, if it is a scalar.
 *
 * Read from what the walk says the entry's value was, which after a container
 * is the container -- never that container's last leaf, which is not this
 * entry's value. A back-reference is the object it names, so an `_i` or a
 * stream id sent as a reference belongs on the line as much as one sent in
 * full. A byte string is never recorded -- on this link key material is
 * always bytes -- and neither is a container. */
static void envelope_member(opack_walk *walk, const char *key, bool in_content, bool nested)
{
    continuity_envelope *envelope = walk->envelope;
    const char *value = NULL;
    if (walk->kind == OPACK_KIND_BOOL) {
        value = walk->last_bool ? "true" : "false";
    } else if (walk->kind == OPACK_KIND_INT) {
        value = wmem_strdup_printf(walk->pinfo->pool, "%" PRId64, walk->last_int);
    } else if (walk->kind == OPACK_KIND_STRING && walk->last_string != NULL) {
        value = walk->last_string;
    } else {
        return;
    }

    if (envelope->member_count >= CONTINUITY_ENVELOPE_MEMBERS) {
        envelope->members_truncated = true;
        return;
    }
    envelope->members[envelope->member_count].key = key;
    envelope->members[envelope->member_count].value = value;
    envelope->members[envelope->member_count].is_int = walk->kind == OPACK_KIND_INT;
    envelope->members[envelope->member_count].in_content = in_content;
    envelope->members[envelope->member_count].nested = nested;
    envelope->member_count++;
}

/* Read a little-endian length of `bytes` octets. OPACK's lengths are
 * little-endian where they are more than one byte, which is the opposite of
 * the frame header one layer up -- a difference worth stating because
 * assuming otherwise decodes a plausible wrong length. */
static uint64_t opack_length(tvbuff_t *tvb, int offset, int bytes)
{
    uint64_t value = 0;
    for (int i = 0; i < bytes; i++) {
        value |= (uint64_t)tvb_get_uint8(tvb, offset + i) << (8 * i);
    }
    return value;
}

/* ---------------------------------------------------------------------------
 * Members: one value per decoded scalar, stating where it is and what it is.
 *
 * The typed leaves above report every value, and in a tree view their nesting
 * shows which key a value belongs to. A generic flattening of the tree keeps
 * the leaves and loses the nesting -- a key and its value become two numbered
 * rows related only by position, and integers are numbered apart from
 * strings -- so "every _streamAddr in this session" could not be asked. Only
 * the walk knows the structure, so the walk states it.
 */

typedef struct {
    size_t len;
    bool truncated;
} opack_path_mark;

/* Append a piece to the path, cutting it with an ellipsis rather than growing
 * past the bound. Returns the mark to restore on the way out. */
static opack_path_mark path_push(opack_walk *walk, const char *piece)
{
    opack_path_mark mark = { walk->path_len, walk->path_truncated };
    if (walk->path_truncated) {
        return mark;
    }
    size_t length = strlen(piece);
    if (walk->path_len + length + 1 <= OPACK_PATH_MAX) {
        memcpy(walk->path + walk->path_len, piece, length + 1);
        walk->path_len += length;
        return mark;
    }
    static const char ellipsis[] = "…";
    size_t room = OPACK_PATH_MAX - 1 - (sizeof ellipsis - 1);
    size_t keep = room > walk->path_len ? room - walk->path_len : 0;
    if (keep > length) {
        keep = length;
    }
    /* Not inside a multi-byte character: back off its continuation bytes. */
    while (keep > 0 && ((uint8_t)piece[keep] & 0xC0) == 0x80) {
        keep--;
    }
    size_t at = walk->path_len < room ? walk->path_len : room;
    memcpy(walk->path + at, piece, keep);
    memcpy(walk->path + at + keep, ellipsis, sizeof ellipsis);
    walk->path_len = at + keep + (sizeof ellipsis - 1);
    walk->path_truncated = true;
    return mark;
}

static void path_pop(opack_walk *walk, opack_path_mark mark)
{
    walk->path_len = mark.len;
    walk->path[mark.len] = '\0';
    walk->path_truncated = mark.truncated;
}

/* The path as reported: the top of the message, before any key, is "(root)". */
static const char *path_text(const opack_walk *walk)
{
    return walk->path_len == 0 ? "(root)" : walk->path;
}

/* One member for the scalar just decoded at [start, start + length). Not for a
 * key, which names a member rather than being one. Its text is charged to the
 * message's budget before it is made; when the budget is spent the walk stops
 * here instead. */
static void opack_stop(opack_walk *walk, proto_tree *tree, int offset, const char *why);

static void opack_member(opack_walk *walk, proto_tree *tree, int start, int length,
                         const char *value)
{
    if (walk->in_key || walk->stopped) {
        return;
    }
    const char *path = path_text(walk);
    size_t needed = strlen(path) + 3 + strlen(value);
    if (needed > OPACK_TEXT_MAX - OPACK_TEXT_RESERVE - walk->text) {
        opack_stop(walk, tree, start,
                   wmem_strdup_printf(walk->pinfo->pool,
                                      "the message's generated text exceeds %u bytes",
                                      (unsigned)OPACK_TEXT_MAX));
        return;
    }
    walk->text += needed;
    proto_item *item = proto_tree_add_string(
        tree, hf_opack_member, walk->tvb, start, length,
        wmem_strdup_printf(walk->pinfo->pool, "%s = %s", path, value));
    proto_item_set_generated(item);
}

/* Bytes as Wireshark renders them elsewhere: lowercase hex, ':' between, cut
 * with an ellipsis past OPACK_MEMBER_BYTES_MAX. */
static const char *opack_hex(opack_walk *walk, int offset, int length)
{
    if (length <= 0) {
        return "";
    }
    return bytes_to_str_punct_maxlen(walk->pinfo->pool, tvb_get_ptr(walk->tvb, offset, length),
                                     (size_t)length, ':', OPACK_MEMBER_BYTES_MAX);
}

/* Admit an object to the table. False when the table is full, in which case
 * the walk has been stopped with the reason. */
static bool opack_admit(opack_walk *walk, proto_tree *tree, int next, opack_object object)
{
    if (wmem_array_get_count(walk->table) >= OPACK_TABLE_MAX) {
        opack_stop(walk, tree, next,
                   "the message holds more objects than the reference table's bound of 4096");
        return false;
    }
    wmem_array_append_one(walk->table, object);
    return true;
}

/* Count `size` bytes of value against the message's expansion bound. False,
 * with the walk stopped at `start` and the reason given, once it is spent. */
static bool opack_spend(opack_walk *walk, proto_tree *tree, int start, size_t size)
{
    if (size > OPACK_EXPANSION_MAX - walk->expanded) {
        opack_stop(walk, tree, start,
                   wmem_strdup_printf(walk->pinfo->pool,
                                      "the message's values, counting each back-reference at "
                                      "the size of what it names, exceed %u bytes",
                                      (unsigned)OPACK_EXPANSION_MAX));
        return false;
    }
    walk->expanded += size;
    return true;
}

/* A date: seconds since 2001-01-01. */
#define OPACK_DATE_EPOCH 978307200 /* 2001-01-01T00:00:00Z in seconds since 1970 */

/* The largest magnitude of seconds accepted: every integer up to it is exact
 * in a double, it is far beyond any date a device sends (about 285 million
 * years), and adding the epoch to it cannot overflow 64 bits. */
#define OPACK_DATE_LIMIT 9007199254740992.0 /* 2^53 */

/* Split a date into whole seconds since 1970 and a fraction rounded to
 * `units` per second (1000000 for the text, 1000000000 for the field). False
 * for a value no time can represent: NaN, an infinity, a magnitude beyond
 * OPACK_DATE_LIMIT, or one that does not fit this platform's time_t. A
 * fraction that rounds up to a whole second carries into the seconds rather
 * than printing as one more digit. */
static bool opack_date_split(double seconds, int64_t units, time_t *whole_out, int64_t *frac_out)
{
    if (!isfinite(seconds) || seconds < -OPACK_DATE_LIMIT || seconds > OPACK_DATE_LIMIT) {
        return false;
    }
    double whole = floor(seconds);
    int64_t secs = (int64_t)whole + OPACK_DATE_EPOCH;
    int64_t frac = (int64_t)llround((seconds - whole) * (double)units);
    if (frac >= units) {
        secs += 1;
        frac -= units;
    }
    time_t converted = (time_t)secs;
    if ((int64_t)converted != secs) {
        return false;
    }
    *whole_out = converted;
    *frac_out = frac;
    return true;
}

static const char *opack_date_text(opack_walk *walk, double seconds)
{
    time_t whole;
    int64_t micro;
    struct tm utc;
    if (!opack_date_split(seconds, 1000000, &whole, &micro)) {
        return wmem_strdup_printf(walk->pinfo->pool, "<unrepresentable date: %g s since 2001>",
                                  seconds);
    }
    if (ws_gmtime_r(&whole, &utc) == NULL) {
        return wmem_strdup_printf(walk->pinfo->pool, "%.6f s since 2001", seconds);
    }
    return wmem_strdup_printf(walk->pinfo->pool, "%04d-%02d-%02dT%02d:%02d:%02d.%06dZ",
                              utc.tm_year + 1900, utc.tm_mon + 1, utc.tm_mday, utc.tm_hour,
                              utc.tm_min, utc.tm_sec, (int)micro);
}

/* The member text of a table object, rendered once and kept on the object, so
 * that a value referred to many times is converted to text once. */
static const char *opack_object_text(opack_walk *walk, opack_object *object)
{
    if (object->text != NULL) {
        return object->text;
    }
    const char *text = "";
    switch (object->kind) {
    case OPACK_OBJECT_STRING:
        text = object->string;
        break;
    case OPACK_OBJECT_BYTES:
        text = opack_hex(walk, object->offset, object->length);
        break;
    case OPACK_OBJECT_INT:
        text = wmem_strdup_printf(walk->pinfo->pool, "%" PRId64, object->integer);
        break;
    case OPACK_OBJECT_FLOAT32:
    case OPACK_OBJECT_FLOAT64:
        text = wmem_strdup_printf(walk->pinfo->pool,
                                  object->kind == OPACK_OBJECT_FLOAT32 ? "%.9g" : "%.17g",
                                  object->real);
        break;
    case OPACK_OBJECT_UUID: {
        const uint8_t *u = tvb_get_ptr(walk->tvb, object->offset, 16);
        text = wmem_strdup_printf(walk->pinfo->pool,
                                  "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
                                  "%02x%02x%02x%02x%02x%02x",
                                  u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7], u[8], u[9],
                                  u[10], u[11], u[12], u[13], u[14], u[15]);
        break;
    }
    case OPACK_OBJECT_DATE:
        text = opack_date_text(walk, object->real);
        break;
    }
    object->text = text;
    return text;
}

/* Report a table object at [start, start + length) with its own type's field
 * and member, and leave it as the walk's last value -- so a key that arrived as
 * a reference names its member and its envelope entry like one sent in full.
 * False when the expansion bound stopped the walk instead. */
static bool opack_report_object(opack_walk *walk, proto_tree *tree, int start, int length,
                                opack_object *object)
{
    if ((object->kind == OPACK_OBJECT_STRING || object->kind == OPACK_OBJECT_BYTES) &&
        !opack_spend(walk, tree, start, (size_t)object->length)) {
        return false;
    }
    switch (object->kind) {
    case OPACK_OBJECT_STRING:
        proto_tree_add_string(tree, hf_opack_string, walk->tvb, start, length, object->string);
        walk->kind = OPACK_KIND_STRING;
        walk->last_string = object->string;
        break;
    case OPACK_OBJECT_BYTES:
        proto_tree_add_bytes_with_length(tree, hf_opack_bytes, walk->tvb, start, length,
                                         tvb_get_ptr(walk->tvb, object->offset, object->length),
                                         object->length);
        walk->kind = OPACK_KIND_BYTES;
        walk->last_bytes_offset = object->offset;
        walk->last_bytes_length = object->length;
        break;
    case OPACK_OBJECT_INT:
        proto_tree_add_int64(tree, hf_opack_int, walk->tvb, start, length, object->integer);
        walk->kind = OPACK_KIND_INT;
        walk->last_int = object->integer;
        break;
    case OPACK_OBJECT_FLOAT32:
    case OPACK_OBJECT_FLOAT64:
        proto_tree_add_double(tree, hf_opack_float, walk->tvb, start, length, object->real);
        walk->kind = OPACK_KIND_FLOAT;
        break;
    case OPACK_OBJECT_UUID: {
        e_guid_t guid;
        tvb_get_guid(walk->tvb, object->offset, &guid, ENC_BIG_ENDIAN);
        proto_tree_add_guid(tree, hf_opack_uuid, walk->tvb, start, length, &guid);
        walk->kind = OPACK_KIND_UUID;
        break;
    }
    case OPACK_OBJECT_DATE: {
        time_t whole;
        int64_t nanos;
        if (opack_date_split(object->real, 1000000000, &whole, &nanos)) {
            nstime_t when = { .secs = whole, .nsecs = (int)nanos };
            proto_tree_add_time(tree, hf_opack_date, walk->tvb, start, length, &when);
        } else {
            /* The value as sent, since no time can hold it. */
            proto_item *raw = proto_tree_add_double(tree, hf_opack_float, walk->tvb, start,
                                                    length, object->real);
            expert_add_info(walk->pinfo, raw, &ei_opack_bad_date);
        }
        walk->kind = OPACK_KIND_DATE;
        break;
    }
    }
    opack_member(walk, tree, start, length, opack_object_text(walk, object));
    return true;
}

static void opack_stop(opack_walk *walk, proto_tree *tree, int offset, const char *why)
{
    walk->stopped = true;
    if (walk->problem == NULL) {
        walk->problem = why;
    }
    int remaining = walk->end - offset;
    if (remaining <= 0) {
        return;
    }
    proto_item *item =
        proto_tree_add_item(tree, hf_opack_undecoded, walk->tvb, offset, remaining, ENC_NA);

    /* Where the gap is, as a member: at the path the walk had reached, which
     * says which part of the message is missing. Reported even while a key
     * was being read -- the gap is then in the dictionary the path names. */
    proto_item *gap = proto_tree_add_string(
        tree, hf_opack_member, walk->tvb, offset, remaining,
        wmem_strdup_printf(walk->pinfo->pool, "%s = <undecoded: %d bytes>", path_text(walk),
                           remaining));
    proto_item_set_generated(gap);
    expert_add_info_format(walk->pinfo, item, &ei_opack_undecoded,
                           "%s; the remaining %d byte(s) are reported undecoded rather "
                           "than walked past, because a container decoder that "
                           "resynchronises reports a structure that was never sent",
                           why, remaining);
}

/* A container that ends before the structure it declares: said on the
 * container, and the walk stops, so the containers around it do not each
 * report the same missing bytes again. */
static void opack_short(opack_walk *walk, proto_item *item, const char *why)
{
    walk->stopped = true;
    if (walk->problem == NULL) {
        walk->problem = why;
    }
    walk->kind = OPACK_KIND_NONE;
    expert_add_info_format(walk->pinfo, item, &ei_opack_malformed, "%s", why);
}

/* An envelope entry whose value is not of the type the envelope gives it. The
 * entry is then not taken as the envelope's: an `_i` that is an array names
 * no event, whatever is inside the array. */
static void opack_envelope_mismatch(opack_walk *walk, proto_tree *tree, int start, int end,
                                    const char *key, const char *expected)
{
    proto_tree_add_expert_format(tree, walk->pinfo, &ei_opack_envelope_type, walk->tvb, start,
                                 end - start,
                                 "the envelope's %s is %s, not %s, so it is not read as the "
                                 "envelope's", key, opack_kind_names[walk->kind], expected);
    if (walk->envelope->conflict == NULL) {
        walk->envelope->conflict =
            wmem_strdup_printf(walk->pinfo->pool, "the envelope's %s is %s, not %s", key,
                               opack_kind_names[walk->kind], expected);
    }
}

/* Whether this top-level envelope entry is the first of its name. A repeat
 * is reported, keeps the value already taken, and marks the envelope as
 * conflicting: which of two values the sender meant is not knowable, so the
 * message is shown but not acted on. */
static bool opack_envelope_first(opack_walk *walk, proto_tree *tree, int start, int end,
                                 const char *key, unsigned bit)
{
    if (!(walk->envelope_seen & bit)) {
        walk->envelope_seen |= bit;
        return true;
    }
    proto_tree_add_expert_format(tree, walk->pinfo, &ei_opack_envelope_type, walk->tvb, start,
                                 end - start,
                                 "the envelope carries %s more than once; the first is kept "
                                 "and the message is not acted on", key);
    if (walk->envelope->conflict == NULL) {
        walk->envelope->conflict = wmem_strdup_printf(
            walk->pinfo->pool, "the envelope carries %s more than once", key);
    }
    return false;
}

/* One value. Returns the offset just past it, or the end on a stop. */
static int opack_value(opack_walk *walk, proto_tree *tree, int offset, int depth,
                       const char *key)
{
    walk->kind = OPACK_KIND_NONE;
    if (offset >= walk->end) {
        return walk->end;
    }
    if (depth > OPACK_MAX_DEPTH) {
        opack_stop(walk, tree, offset, "the container nests deeper than this decode walks");
        return walk->end;
    }
    if (walk->values >= OPACK_VALUES_MAX) {
        opack_stop(walk, tree, offset,
                   wmem_strdup_printf(walk->pinfo->pool, "the message holds more than %u values",
                                      (unsigned)OPACK_VALUES_MAX));
        return walk->end;
    }
    walk->values++;

    uint8_t marker = tvb_get_uint8(walk->tvb, offset);
    int start = offset;
    offset += 1;

    /* The key, where this value is a dictionary entry's. Added before the
     * value so the two read in the order they were written. */
    if (key != NULL) {
        proto_item *key_item =
            proto_tree_add_string(tree, hf_opack_key, walk->tvb, start, 1, key);
        proto_item_set_generated(key_item);
    }

    if (marker == OPACK_TRUE || marker == OPACK_FALSE) {
        proto_tree_add_boolean(tree, hf_opack_bool, walk->tvb, start, 1,
                               marker == OPACK_TRUE);
        opack_member(walk, tree, start, 1, marker == OPACK_TRUE ? "true" : "false");
        walk->kind = OPACK_KIND_BOOL;
        walk->last_bool = marker == OPACK_TRUE;
        return offset;
    }
    if (marker == OPACK_NULL) {
        proto_tree_add_item(tree, hf_opack_null, walk->tvb, start, 1, ENC_NA);
        opack_member(walk, tree, start, 1, "null");
        walk->kind = OPACK_KIND_NULL;
        return offset;
    }
    if (marker >= OPACK_SMALL_INT_MIN && marker <= OPACK_SMALL_INT_MAX) {
        /* add_int64, not add_int: the field is FT_INT64, and the 32-bit
         * adder against a 64-bit field is a dissector bug that Wireshark
         * reports in place of the value. */
        proto_tree_add_int64(tree, hf_opack_int, walk->tvb, start, 1,
                             marker - OPACK_SMALL_INT_ZERO);
        walk->kind = OPACK_KIND_INT;
        walk->last_int = marker - OPACK_SMALL_INT_ZERO;
        opack_member(walk, tree, start, 1,
                     wmem_strdup_printf(walk->pinfo->pool, "%" PRId64, walk->last_int));
        return offset;
    }
    if (marker >= OPACK_INT8 && marker <= OPACK_INT64) {
        int width = 1 << (marker - OPACK_INT8);
        if (offset + width > walk->end) {
            opack_stop(walk, tree, start, "an integer runs past the end of the body");
            return walk->end;
        }
        /* Signedness as Apple's own parser reads it, measured against a peer:
         * the 4-byte form is a signed int32 -- an exchange id of 0xA56960BC
         * sent that way was taken as negative and matched no request, in
         * every one of four sessions, while ids below 2^31 matched -- and the
         * 1- and 2-byte forms are unsigned, a stream port of 49239 in the
         * 2-byte form having been dialled as that port. The 8-byte form is
         * the signed int64 it holds. */
        uint64_t raw = opack_length(walk->tvb, offset, width);
        int64_t value = marker == OPACK_INT32 ? (int64_t)(int32_t)(uint32_t)raw : (int64_t)raw;
        proto_tree_add_int64(tree, hf_opack_int, walk->tvb, start, 1 + width, value);
        walk->kind = OPACK_KIND_INT;
        walk->last_int = value;
        opack_member(walk, tree, start, 1 + width,
                     wmem_strdup_printf(walk->pinfo->pool, "%" PRId64, value));
        opack_object object = { .kind = OPACK_OBJECT_INT, .integer = value };
        return opack_admit(walk, tree, offset + width, object) ? offset + width : walk->end;
    }
    if (marker == OPACK_FLOAT32 || marker == OPACK_FLOAT64 || marker == OPACK_UUID ||
        marker == OPACK_DATE) {
        int width = marker == OPACK_FLOAT32 ? 4 : marker == OPACK_UUID ? 16 : 8;
        if (offset + width > walk->end) {
            opack_stop(walk, tree, start, "a value runs past the end of the body");
            return walk->end;
        }
        opack_object object = { .offset = offset, .length = width };
        if (marker == OPACK_FLOAT32) {
            object.kind = OPACK_OBJECT_FLOAT32;
            object.real = (double)tvb_get_letohieee_float(walk->tvb, offset);
        } else if (marker == OPACK_FLOAT64) {
            object.kind = OPACK_OBJECT_FLOAT64;
            object.real = tvb_get_letohieee_double(walk->tvb, offset);
        } else if (marker == OPACK_UUID) {
            object.kind = OPACK_OBJECT_UUID;
        } else {
            object.kind = OPACK_OBJECT_DATE;
            object.real = tvb_get_letohieee_double(walk->tvb, offset);
        }
        opack_report_object(walk, tree, start, 1 + width, &object);
        opack_kind kind = walk->kind;
        if (!opack_admit(walk, tree, offset + width, object)) {
            return walk->end;
        }
        walk->kind = kind;
        return offset + width;
    }
    if ((marker >= OPACK_REF_MIN && marker <= OPACK_REF_MAX) ||
        (marker >= OPACK_REF_LEN1 && marker <= OPACK_REF_LEN4)) {
        int width = marker <= OPACK_REF_MAX ? 0 : marker - OPACK_REF_LEN1 + 1;
        if (offset + width > walk->end) {
            opack_stop(walk, tree, start, "a reference's index runs past the end of the body");
            return walk->end;
        }
        uint64_t ref_at = width == 0 ? (uint64_t)(marker - OPACK_REF_MIN)
                                    : opack_length(walk->tvb, offset, width);
        unsigned size = wmem_array_get_count(walk->table);
        if (ref_at >= size) {
            /* Not guessed: no nearest entry, no fallback. The platform's own
             * decoder refuses such a body too. */
            opack_stop(walk, tree, start,
                       wmem_strdup_printf(walk->pinfo->pool,
                                          "unresolvable reference (index %" PRIu64
                                          ", table size %u)", ref_at, size));
            return walk->end;
        }
        opack_object *object = (opack_object *)wmem_array_index(walk->table, (unsigned)ref_at);
        if (!opack_report_object(walk, tree, start, 1 + width, object)) {
            return walk->end;
        }
        proto_item *ref = proto_tree_add_uint(tree, hf_opack_ref_index, walk->tvb, start,
                                              1 + width, (uint32_t)ref_at);
        proto_item_set_generated(ref);
        return offset + width;
    }

    bool is_string = (marker >= OPACK_STRING_MIN && marker <= OPACK_STRING_MAX);
    bool is_bytes = (marker >= OPACK_BYTES_MIN && marker <= OPACK_BYTES_MAX);
    bool string_with_length = (marker >= OPACK_STRING_LEN1 && marker <= OPACK_STRING_LEN4);
    bool bytes_with_length = (marker >= OPACK_BYTES_LEN1 && marker <= OPACK_BYTES_LEN4);
    if (is_string || is_bytes || string_with_length || bytes_with_length) {
        uint64_t length;
        if (is_string || is_bytes) {
            length = is_string ? (uint64_t)(marker - OPACK_STRING_MIN)
                               : (uint64_t)(marker - OPACK_BYTES_MIN);
        } else {
            int width = string_with_length ? (marker - OPACK_STRING_LEN1 + 1)
                                           : (marker - OPACK_BYTES_LEN1 + 1);
            if (offset + width > walk->end) {
                opack_stop(walk, tree, start, "a length runs past the end of the body");
                return walk->end;
            }
            length = opack_length(walk->tvb, offset, width);
            offset += width;
        }
        if (length > (uint64_t)(walk->end - offset)) {
            opack_stop(walk, tree, start, "a value runs past the end of the body");
            return walk->end;
        }
        if (!opack_spend(walk, tree, start, (size_t)length)) {
            return walk->end;
        }
        bool string = is_string || string_with_length;
        opack_object object = { .kind = string ? OPACK_OBJECT_STRING : OPACK_OBJECT_BYTES,
                                .offset = offset, .length = (int)length };
        if (string) {
            /* A value longer than 32 bytes is a value too -- a stream id such
             * as 123C0ECF:ContinuityCaptureMedia-Microphone is 41. */
            proto_tree_add_item(tree, hf_opack_string, walk->tvb, offset, (int)length,
                                ENC_UTF_8);
            object.string = (const char *)tvb_get_string_enc(
                walk->pinfo->pool, walk->tvb, offset, (int)length, ENC_UTF_8);
            object.text = object.string;
        } else {
            proto_tree_add_item(tree, hf_opack_bytes, walk->tvb, offset, (int)length, ENC_NA);
            object.text = opack_hex(walk, offset, (int)length);
        }
        opack_member(walk, tree, start, offset - start + (int)length, object.text);
        if (!opack_admit(walk, tree, offset + (int)length, object)) {
            return walk->end;
        }
        walk->kind = string ? OPACK_KIND_STRING : OPACK_KIND_BYTES;
        walk->last_string = object.string;
        walk->last_bytes_offset = object.offset;
        walk->last_bytes_length = object.length;
        return offset + (int)length;
    }

    if (marker >= OPACK_ARRAY_MIN && marker <= OPACK_ARRAY_ENDLESS) {
        bool endless = (marker == OPACK_ARRAY_ENDLESS);
        unsigned count = endless ? 0 : (unsigned)(marker - OPACK_ARRAY_MIN);
        proto_item *item = proto_tree_add_none_format(tree, hf_opack_array, walk->tvb, start,
                                                      1, "Array");
        proto_tree *subtree = proto_item_add_subtree(item, ett_opack_value);
        unsigned i = 0;
        bool terminated = false;
        while (!walk->stopped && (endless || i < count) && offset < walk->end) {
            if (endless && tvb_get_uint8(walk->tvb, offset) == OPACK_TERMINATOR) {
                offset += 1;
                terminated = true;
                break;
            }
            char element[24];
            snprintf(element, sizeof element, "[%u]", i);
            opack_path_mark mark = path_push(walk, element);
            offset = opack_value(walk, subtree, offset, depth + 1, NULL);
            path_pop(walk, mark);
            i++;
        }
        proto_item_set_len(item, offset - start);
        if (!walk->stopped) {
            if (!endless && i < count) {
                opack_short(walk, item,
                            wmem_strdup_printf(walk->pinfo->pool,
                                               "the array declares %u entries and the body "
                                               "ends after %u", count, i));
                return walk->end;
            }
            if (endless && !terminated) {
                opack_short(walk, item, "the array has no terminator before the body ends");
                return walk->end;
            }
        }
        walk->kind = walk->stopped ? OPACK_KIND_NONE : OPACK_KIND_ARRAY;
        return offset;
    }

    if (marker >= OPACK_DICT_MIN && marker <= OPACK_DICT_ENDLESS) {
        bool endless = (marker == OPACK_DICT_ENDLESS);
        unsigned count = endless ? 0 : (unsigned)(marker - OPACK_DICT_MIN);
        proto_item *item =
            proto_tree_add_none_format(tree, hf_opack_dict, walk->tvb, start, 1, "Dictionary");
        proto_tree *subtree = proto_item_add_subtree(item, ett_opack_value);
        unsigned i = 0;
        bool terminated = false;
        while (!walk->stopped && (endless || i < count) && offset < walk->end) {
            if (endless && tvb_get_uint8(walk->tvb, offset) == OPACK_TERMINATOR) {
                offset += 1;
                terminated = true;
                break;
            }
            /* A dictionary is a run of alternating keys and values, and the
             * key is itself an OPACK value -- usually a short string. It is
             * walked as one rather than assumed to be a string, because a
             * dictionary keyed on something else would otherwise decode as a
             * structure that was never sent. */
            int key_start = offset;
            bool was_in_key = walk->in_key;
            walk->in_key = true;
            offset = opack_value(walk, subtree, offset, depth + 1, NULL);
            walk->in_key = was_in_key;
            if (walk->stopped) {
                break;
            }

            /* The key, copied rather than pointed at: `last_string` is
             * overwritten by the very next value this walk reads. */
            const char *entry_key = NULL;
            if (walk->kind == OPACK_KIND_STRING && walk->last_string != NULL) {
                entry_key = wmem_strdup(walk->pinfo->pool, walk->last_string);
            }
            opack_kind key_kind = walk->kind;
            int64_t key_int = walk->last_int;

            /* The member's name in the path: the key as sent. A key that is
             * not a string is named by its integer, or by '?' when it is
             * neither -- the value is still reported under it. */
            const char *name = entry_key;
            if (name == NULL) {
                name = walk->kind == OPACK_KIND_INT
                           ? wmem_strdup_printf(walk->pinfo->pool, "%" PRId64, walk->last_int)
                           : "?";
            }

            if (offset >= walk->end) {
                proto_item_set_len(item, offset - start);
                opack_short(walk, item,
                            wmem_strdup_printf(walk->pinfo->pool,
                                               "the dictionary's key %s at offset %d has no "
                                               "value before the body ends", name,
                                               key_start));
                return walk->end;
            }

            opack_path_mark mark = path_push(
                walk, walk->path_len == 0 ? name
                                          : wmem_strdup_printf(walk->pinfo->pool, ".%s", name));

            int value_start = offset;
            bool entering_content = walk->envelope != NULL && depth == 0 &&
                                    entry_key != NULL && strcmp(entry_key, "_c") == 0;
            if (entering_content) {
                walk->content_depth = depth + 1;
            }
            offset = opack_value(walk, subtree, offset, depth + 1, NULL);
            path_pop(walk, mark);
            if (entering_content) {
                walk->content_depth = 0;
            }
            i++;
            if (walk->stopped) {
                break;
            }

            /* The summary's members: the envelope's own entries, and those
             * inside `_c` at any depth -- an identifying key need not be at
             * its top. At the top of the walked object an integer key names a
             * member too, which is how a nested object's entries are keyed. */
            const char *member_key = entry_key;
            if (member_key == NULL && depth == 0 && key_kind == OPACK_KIND_INT) {
                member_key = name;
            }
            if (walk->envelope != NULL && member_key != NULL &&
                (depth == 0 || (walk->content_depth != 0 && depth >= walk->content_depth))) {
                envelope_member(walk, member_key, depth != 0,
                                depth > walk->content_depth && walk->content_depth != 0);
            }

            /* `_c` as observed for a service that nests objects in byte
             * strings: {0: <bytes>}, and in Sidecar Display's messages
             * {0: <bytes>, 1: <bytes>}, each byte string a nested object. */
            if (walk->envelope != NULL && walk->content_depth != 0 &&
                depth == walk->content_depth && i == 1 && key_kind == OPACK_KIND_INT &&
                key_int == 0 && walk->kind == OPACK_KIND_BYTES) {
                walk->envelope->has_content_bytes = true;
                walk->envelope->content_bytes_offset = walk->last_bytes_offset;
                walk->envelope->content_bytes_length = walk->last_bytes_length;
            }
            if (walk->envelope != NULL && walk->envelope->has_content_bytes &&
                walk->content_depth != 0 && depth == walk->content_depth && i == 2 &&
                key_kind == OPACK_KIND_INT && key_int == 1 && walk->kind == OPACK_KIND_BYTES) {
                walk->envelope->has_content_body = true;
                walk->envelope->content_body_offset = walk->last_bytes_offset;
                walk->envelope->content_body_length = walk->last_bytes_length;
            }

            /* The envelope's own entries, which only the outermost dictionary
             * can carry: an entry named the same thing nested inside the
             * content would otherwise be mistaken for the envelope's. Each is
             * taken only when its value is of the envelope's type for it. */
            if (walk->envelope != NULL && depth == 0 && entry_key != NULL) {
                if (strcmp(entry_key, "_x") == 0) {
                    if (!opack_envelope_first(walk, subtree, value_start, offset, "_x", 1)) {
                        /* reported */
                    } else if (walk->kind == OPACK_KIND_INT) {
                        walk->envelope->xid = (uint64_t)walk->last_int;
                        walk->envelope->has_xid = true;
                    } else {
                        opack_envelope_mismatch(walk, subtree, value_start, offset, "_x",
                                                "an integer");
                    }
                } else if (strcmp(entry_key, "_t") == 0) {
                    if (!opack_envelope_first(walk, subtree, value_start, offset, "_t", 2)) {
                        /* reported */
                    } else if (walk->kind == OPACK_KIND_INT) {
                        walk->envelope->type = walk->last_int;
                        walk->envelope->has_type = true;
                    } else {
                        opack_envelope_mismatch(walk, subtree, value_start, offset, "_t",
                                                "an integer");
                    }
                } else if (strcmp(entry_key, "_i") == 0) {
                    if (!opack_envelope_first(walk, subtree, value_start, offset, "_i", 4)) {
                        /* reported */
                    } else if (walk->kind == OPACK_KIND_STRING && walk->last_string != NULL) {
                        walk->envelope->event = wmem_strdup(walk->pinfo->pool, walk->last_string);
                        walk->envelope->has_event = true;
                    } else {
                        opack_envelope_mismatch(walk, subtree, value_start, offset, "_i",
                                                "a string");
                    }
                } else if (strcmp(entry_key, "_pd") == 0) {
                    walk->envelope->pd_count++;
                    if (walk->kind == OPACK_KIND_BYTES && !walk->envelope->has_pd) {
                        walk->envelope->has_pd = true;
                        walk->envelope->pd_offset = walk->last_bytes_offset;
                        walk->envelope->pd_length = walk->last_bytes_length;
                    }
                } else if (strcmp(entry_key, "_c") == 0) {
                    /* The bounds of the content, not its contents: what is in
                     * there is the service's to say, and the transport should
                     * not need to know. */
                    if (opack_envelope_first(walk, subtree, value_start, offset, "_c", 8)) {
                        walk->envelope->content_offset = value_start;
                        walk->envelope->content_length = offset - value_start;
                    }
                }
            }
        }
        proto_item_set_len(item, offset - start);
        if (!walk->stopped) {
            if (!endless && i < count) {
                opack_short(walk, item,
                            wmem_strdup_printf(walk->pinfo->pool,
                                               "the dictionary declares %u entries and the "
                                               "body ends after %u", count, i));
                return walk->end;
            }
            if (endless && !terminated) {
                opack_short(walk, item, "the dictionary has no terminator before the body ends");
                return walk->end;
            }
        }
        walk->kind = walk->stopped ? OPACK_KIND_NONE : OPACK_KIND_DICT;
        return offset;
    }

    opack_stop(walk, tree, start, "an unrecognised marker");
    return walk->end;
}

int continuity_opack_dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                             int length)
{
    return continuity_opack_dissect_envelope(tvb, pinfo, tree, offset, length, NULL);
}

int continuity_opack_dissect_envelope(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                      int offset, int length, continuity_envelope *envelope)
{
    if (length <= 0) {
        return offset;
    }
    proto_item *item = proto_tree_add_item(tree, proto_opack, tvb, offset, length, ENC_NA);
    proto_tree *opack_tree = proto_item_add_subtree(item, ett_opack);

    opack_walk walk = {
        .pinfo = pinfo,
        .tvb = tvb,
        .end = offset + length,
        .stopped = false,
        .envelope = envelope,
        .table = wmem_array_new(pinfo->pool, sizeof(opack_object)),
    };
    int consumed = opack_value(&walk, opack_tree, offset, 0, NULL);

    /* Trailing bytes are reported, not ignored. A body whose container ended
     * early is carrying something this decode did not account for, and that
     * is worth seeing rather than trimming. */
    if (!walk.stopped && consumed < walk.end) {
        proto_item *trailing = proto_tree_add_item(opack_tree, hf_opack_undecoded, tvb,
                                                   consumed, walk.end - consumed, ENC_NA);
        expert_add_info_format(pinfo, trailing, &ei_opack_truncated,
                               "%d byte(s) follow the container and were not decoded",
                               walk.end - consumed);
        if (walk.problem == NULL) {
            walk.problem = "bytes follow the object";
        }
    }

    /* Whether everything the caller takes from the envelope came from a body
     * that was walked to its end without a stop, a short container or a
     * trailing byte. A caller that acts on a value -- naming a session, say --
     * needs that, not just the value. */
    if (envelope != NULL) {
        envelope->complete = walk.problem == NULL;
        envelope->problem = walk.problem;
    }
    return consumed;
}

void proto_register_continuity_opack(void)
{
    static hf_register_info hf[] = {
        { &hf_opack_key,
          { "Key", "continuity.opack.key", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_opack_string,
          { "String", "continuity.opack.string", FT_STRING, BASE_NONE, NULL, 0x0, NULL,
            HFILL } },
        { &hf_opack_int,
          { "Integer", "continuity.opack.int", FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_opack_bool,
          { "Boolean", "continuity.opack.bool", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL,
            HFILL } },
        { &hf_opack_null,
          { "Null", "continuity.opack.null", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_opack_bytes,
          { "Bytes", "continuity.opack.bytes", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_opack_dict,
          { "Dictionary", "continuity.opack.dict", FT_NONE, BASE_NONE, NULL, 0x0, NULL,
            HFILL } },
        { &hf_opack_array,
          { "Array", "continuity.opack.array", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_opack_float,
          { "Float", "continuity.opack.float", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_opack_uuid,
          { "UUID", "continuity.opack.uuid", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_opack_date,
          { "Date", "continuity.opack.date", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
            "Sent as seconds since 2001-01-01", HFILL } },
        { &hf_opack_ref_index,
          { "Reference index", "continuity.opack.ref_index", FT_UINT32, BASE_DEC, NULL, 0x0,
            "This value was transmitted as a back-reference to the earlier object at this "
            "index of the message's object table; the value shown is that object", HFILL } },
        { &hf_opack_member,
          { "Member", "continuity.opack.member", FT_STRING, BASE_NONE, NULL, 0x0,
            "One decoded value with where it is: \"<path> = <value>\", the path being the "
            "keys from the top of the message joined with '.', array elements as [i]. "
            "Selectable by path, e.g. value LIKE '_c._streamAddr = %'", HFILL } },
        { &hf_opack_undecoded,
          { "Undecoded", "continuity.opack.undecoded", FT_BYTES, BASE_NONE, NULL, 0x0,
            "Bytes this decode did not account for, retained rather than walked past",
            HFILL } },
    };

    static int *ett[] = { &ett_opack, &ett_opack_value };

    static ei_register_info ei[] = {
        { &ei_opack_undecoded,
          { "continuity.opack.undecoded.expert", PI_UNDECODED, PI_NOTE,
            "The object encoding could not be walked further", EXPFILL } },
        { &ei_opack_truncated,
          { "continuity.opack.trailing", PI_UNDECODED, PI_NOTE,
            "Bytes follow the container", EXPFILL } },
        { &ei_opack_malformed,
          { "continuity.opack.malformed", PI_MALFORMED, PI_WARN,
            "The body ends before the structure it declares", EXPFILL } },
        { &ei_opack_bad_date,
          { "continuity.opack.date.invalid", PI_MALFORMED, PI_WARN,
            "The date is not a representable time (NaN, infinite or out of range); its raw "
            "value is shown instead", EXPFILL } },
        { &ei_opack_envelope_type,
          { "continuity.opack.envelope_type", PI_PROTOCOL, PI_WARN,
            "An envelope entry's value is not of the envelope's type for it", EXPFILL } },
    };

    proto_opack = proto_register_protocol("Apple OPACK", "OPACK", "continuity.opack");
    proto_register_field_array(proto_opack, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_module_t *expert = expert_register_protocol(proto_opack);
    expert_register_field_array(expert, ei, array_length(ei));
}

void proto_reg_handoff_continuity_opack(void)
{
    /* Reached from the frames that carry it, not from a table of its own. */
}
