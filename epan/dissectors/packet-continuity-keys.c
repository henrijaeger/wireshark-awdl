/* packet-continuity-keys.c — where session key material comes from.
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
 *
 * ---------------------------------------------------------------------------
 *
 * Two inputs, one format, one table.
 *
 * Key material arrives either from a file the operator points a preference at,
 * or from the capture's own decryption-secrets block -- and both carry the
 * same text, so both are parsed here by the same code. That is not tidiness
 * for its own sake: it means the keys that rode in with a capture and the keys
 * someone kept beside it cannot diverge in how they are read, which is the
 * kind of difference that shows up as "it decrypts on my machine".
 *
 * Every entry is keyed on the handshake's cleartext ephemeral public key. It
 * is in the capture, it is unique per session, and it is sent before anything
 * protected -- so a reader holding only a capture and a keylog can bind one to
 * the other with no external state, and can tell two concurrent sessions
 * apart. Keying on the address and port tuple was tried and is wrong: ports
 * are reused across sessions, and one observed listener port was shared by two
 * transports.
 *
 * The format, which is the prototype's and is deliberately TLS-keylog-shaped:
 *
 *     RDLINK_SHARED     <ephemeral pub hex>  <shared secret hex>
 *     RDLINK_CLIENT_ENC <ephemeral pub hex>  <key hex>
 *     RDLINK_SERVER_ENC <ephemeral pub hex>  <key hex>
 *
 * A line giving the shared secret is enough on its own: the two direction keys
 * are HKDF-SHA-512 of it under the labels below, with an empty salt. That is
 * not taken on the protocol documentation's word -- it was checked against a
 * keylog carrying all three, where SHA-512 reproduces both direction keys
 * byte-for-byte and SHA-256 reproduces neither. Supporting it means key
 * capture can record one value per session instead of three.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/secrets.h>
#include <epan/strutil.h>
#include <wsutil/wsgcrypt.h>
#include <wiretap/secrets-types.h>

#include <string.h>

#include "packet-continuity.h"

/* The keys ride inside a capture in a Decryption Secrets Block of type
 * SECRETS_TYPE_CONTINUITY ("LFKL"). The number was chosen while this was a
 * loadable module and captures already carry it, so it is kept rather than
 * renumbered. */

/* HKDF labels for the data channel.
 *
 * Neither string appears anywhere in the system's shared cache, which for a
 * while looked like evidence that they were wrong. They are not: a frame the
 * *phone* encrypted decrypts under them. The absence is a property of how the
 * strings are stored, and the empirical result settles it.
 */
static const char client_enc_label[] = "ClientEncrypt-main";
static const char server_enc_label[] = "ServerEncrypt-main";

static const char *pref_keylog_file = "";

/* ephemeral public key, as lowercase hex -> continuity_session_keys */
static GHashTable *key_table;

/* Secrets whose session is not known: a line keyed on the all-zero session.
 *
 * The key capture cannot name the session a secret belongs to -- the value
 * that names it is not an argument of the derivation it observes, and which
 * curve argument it is depends on which end opened the connection. So it
 * writes zeros, and the session is found here instead: the decrypt tries these
 * against a connection that has no key, and Poly1305 settles the pairing,
 * since a wrong one cannot authenticate.
 *
 * A list, not one table entry. Every unbound secret shares the zero session,
 * and keyed on it they overwrote one another, first one winning -- so a keylog
 * recording four handshakes opened at most one of them. Stream sub-connections
 * make this the ordinary case rather than an edge: each derives its own key,
 * and none of them has a handshake to be named by. */
static GPtrArray *unbound_keys;

static void keys_init(void)
{
    if (key_table != NULL) {
        g_hash_table_destroy(key_table);
    }
    key_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    if (unbound_keys != NULL) {
        g_ptr_array_free(unbound_keys, true);
    }
    unbound_keys = g_ptr_array_new_with_free_func(g_free);
}

static void keys_cleanup(void)
{
    if (key_table != NULL) {
        g_hash_table_destroy(key_table);
        key_table = NULL;
    }
    if (unbound_keys != NULL) {
        g_ptr_array_free(unbound_keys, true);
        unbound_keys = NULL;
    }
}

static bool all_zero(const uint8_t *bytes, unsigned len)
{
    for (unsigned i = 0; i < len; i++) {
        if (bytes[i] != 0) {
            return false;
        }
    }
    return true;
}

/* Keeps an unbound secret unless it holds nothing or is already held. The
 * same handshake reaches the keylog more than once -- its two direction
 * derivations take the same input -- and also arrives twice when a capture
 * carries its keys and the operator names the keylog as well. */
static void add_unbound(continuity_session_keys *keys)
{
    if (unbound_keys == NULL) {
        keys_init();
    }
    if (!keys->has_client && !keys->has_server) {
        g_free(keys);
        return;
    }
    for (unsigned i = 0; i < unbound_keys->len; i++) {
        if (memcmp(g_ptr_array_index(unbound_keys, i), keys, sizeof *keys) == 0) {
            g_free(keys);
            return;
        }
    }
    g_ptr_array_add(unbound_keys, keys);
}

static continuity_session_keys *entry_for(const char *session_hex)
{
    if (key_table == NULL) {
        keys_init();
    }
    continuity_session_keys *keys =
        (continuity_session_keys *)g_hash_table_lookup(key_table, session_hex);
    if (keys == NULL) {
        keys = g_new0(continuity_session_keys, 1);
        g_hash_table_insert(key_table, g_strdup(session_hex), keys);
    }
    return keys;
}

/* Derive one direction's key from the shared secret.
 *
 * HKDF-SHA-512 with an empty salt, done against the crypto library directly
 * rather than through the toolkit's hkdf_expand(). That helper cannot do
 * SHA-512: it buffers one hash block in a 48-byte array -- "maximum hash
 * output size: 48 bytes for SHA-384", as its own comment says -- and rejects
 * anything longer as an invalid argument. SHA-512 produces 64.
 *
 * The failure is worth describing because of how it presented. The helper
 * returns an error, the derivation reports it did not happen, and every frame
 * of the session is then reported unread -- which is indistinguishable from
 * having been given the wrong key. It was caught by carrying a keylog holding
 * only the shared secret, expecting the session to open, and finding it did
 * not; and pinned down by running the same construction against the library
 * directly, which produced the expected key on the first try.
 *
 * Only one output block is needed, since 32 bytes is less than one SHA-512
 * digest, so this is HKDF's expand step with N = 1 rather than a general
 * implementation of it.
 *
 * The empty salt is written out as HashLen zero bytes, which is what RFC 5869
 * defines it to mean.
 */
static bool derive_direction_key(const uint8_t *shared, const char *label, uint8_t out[32])
{
    static const uint8_t empty_salt[64] = { 0 };
    uint8_t prk[64];

    gcry_md_hd_t hash;
    if (gcry_md_open(&hash, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC) != 0) {
        return false;
    }

    bool derived = false;
    if (gcry_md_setkey(hash, empty_salt, sizeof empty_salt) == 0) {
        gcry_md_write(hash, shared, CONTINUITY_KEY_LEN);
        const uint8_t *extracted = gcry_md_read(hash, GCRY_MD_SHA512);
        if (extracted != NULL) {
            memcpy(prk, extracted, sizeof prk);

            gcry_md_reset(hash);
            if (gcry_md_setkey(hash, prk, sizeof prk) == 0) {
                gcry_md_write(hash, (const uint8_t *)label, strlen(label));
                gcry_md_putc(hash, 1);
                const uint8_t *expanded = gcry_md_read(hash, GCRY_MD_SHA512);
                if (expanded != NULL) {
                    memcpy(out, expanded, CONTINUITY_KEY_LEN);
                    derived = true;
                }
            }
        }
    }

    gcry_md_close(hash);
    memset(prk, 0, sizeof prk);
    return derived;
}

/* Parse one line. Silently ignores anything that is not one of the three
 * forms, which is how a keylog gains a comment or a blank line without the
 * reader needing to care. */
static void parse_line(const char *line)
{
    char **field = g_strsplit_set(line, " \t", -1);
    char *label = NULL;
    char *session = NULL;
    char *value = NULL;

    for (unsigned i = 0; field[i] != NULL; i++) {
        if (field[i][0] == '\0') {
            continue;
        }
        if (label == NULL) {
            label = field[i];
        } else if (session == NULL) {
            session = field[i];
        } else if (value == NULL) {
            value = field[i];
        } else {
            value = NULL; /* a fourth token: not a line of this format */
            break;
        }
    }

    if (label == NULL || session == NULL || value == NULL) {
        g_strfreev(field);
        return;
    }

    GByteArray *session_bytes = g_byte_array_new();
    GByteArray *value_bytes = g_byte_array_new();
    bool usable = hex_str_to_bytes(session, session_bytes, false) &&
                  hex_str_to_bytes(value, value_bytes, false) &&
                  session_bytes->len == CONTINUITY_SESSION_LEN &&
                  value_bytes->len == CONTINUITY_KEY_LEN;

    if (usable) {
        bool unbound = all_zero(session_bytes->data, session_bytes->len);
        continuity_session_keys *keys;
        if (unbound) {
            keys = g_new0(continuity_session_keys, 1);
        } else {
            char *session_hex = g_ascii_strdown(session, -1);
            keys = entry_for(session_hex);
            g_free(session_hex);
        }

        if (g_ascii_strcasecmp(label, "RDLINK_CLIENT_ENC") == 0) {
            memcpy(keys->client_enc, value_bytes->data, CONTINUITY_KEY_LEN);
            keys->has_client = true;
        } else if (g_ascii_strcasecmp(label, "RDLINK_SERVER_ENC") == 0) {
            memcpy(keys->server_enc, value_bytes->data, CONTINUITY_KEY_LEN);
            keys->has_server = true;
        } else if (g_ascii_strcasecmp(label, "RDLINK_SHARED") == 0) {
            /* A direction key given explicitly wins over one derived here:
             * the explicit one is what was observed, the derived one is what
             * this code believes follows from it. Where they disagree the
             * observation is the evidence. */
            if (!keys->has_client &&
                derive_direction_key(value_bytes->data, client_enc_label, keys->client_enc)) {
                keys->has_client = true;
            }
            if (!keys->has_server &&
                derive_direction_key(value_bytes->data, server_enc_label, keys->server_enc)) {
                keys->has_server = true;
            }
        }

        if (unbound) {
            add_unbound(keys);
        }
    }

    g_byte_array_free(session_bytes, true);
    g_byte_array_free(value_bytes, true);
    g_strfreev(field);
}

static void parse_keylog_text(const char *text, size_t length)
{
    char *owned = g_strndup(text, length);
    char **lines = g_strsplit_set(owned, "\r\n", -1);
    for (unsigned i = 0; lines[i] != NULL; i++) {
        parse_line(lines[i]);
    }
    g_strfreev(lines);
    g_free(owned);
}

/* The capture's own key material.
 *
 * Registered against a privately numbered secrets type. The block's payload is
 * the same text a keylog file holds, so a capture that carries its own keys
 * and a capture with a keylog beside it are read by identical code.
 */
static void secrets_block_callback(const void *secrets, unsigned size)
{
    if (secrets == NULL || size == 0) {
        return;
    }
    parse_keylog_text((const char *)secrets, size);
}

/* The operator's key material, re-read whenever a capture is loaded.
 *
 * Re-reading rather than caching on the filename is deliberate: during an
 * investigation the file is often being appended to by a capture that is still
 * running, and "reload the capture to pick up new keys" is a rule an operator
 * can act on, whereas "restart the program" is not.
 */
static void load_keylog_file(void)
{
    if (pref_keylog_file == NULL || pref_keylog_file[0] == '\0') {
        return;
    }
    char *contents = NULL;
    size_t length = 0;
    if (!g_file_get_contents(pref_keylog_file, &contents, &length, NULL)) {
        return;
    }
    parse_keylog_text(contents, length);
    g_free(contents);
}

const continuity_session_keys *continuity_keys_lookup(const char *session_hex)
{
    if (key_table == NULL || session_hex == NULL) {
        return NULL;
    }
    char *lower = g_ascii_strdown(session_hex, -1);
    const continuity_session_keys *keys =
        (const continuity_session_keys *)g_hash_table_lookup(key_table, lower);
    g_free(lower);
    return keys;
}

bool continuity_keys_any_loaded(void)
{
    return (key_table != NULL && g_hash_table_size(key_table) > 0) ||
           continuity_keys_unbound_count() > 0;
}

unsigned continuity_keys_unbound_count(void)
{
    return unbound_keys == NULL ? 0 : unbound_keys->len;
}

const continuity_session_keys *continuity_keys_unbound_at(unsigned index)
{
    if (unbound_keys == NULL || index >= unbound_keys->len) {
        return NULL;
    }
    return (const continuity_session_keys *)g_ptr_array_index(unbound_keys, index);
}

static void keys_load_all(void)
{
    keys_init();
    load_keylog_file();
    /* Secrets blocks arrive from the container as it is read, through the
     * callback above, so nothing is pulled in for them here. */
}

void continuity_keys_register(int proto)
{
    module_t *module = prefs_register_protocol(proto, NULL);

    prefs_register_filename_preference(
        module, "keylog_file", "Session key log file",
        "A file of RDLINK_SHARED / RDLINK_CLIENT_ENC / RDLINK_SERVER_ENC lines, each keyed "
        "on the handshake's cleartext ephemeral public key. Keys carried inside the capture "
        "are read as well, and need no preference.",
        &pref_keylog_file, false);

    register_init_routine(keys_load_all);
    register_cleanup_routine(keys_cleanup);
}

void continuity_keys_handoff(void)
{
    secrets_register_type(SECRETS_TYPE_CONTINUITY, secrets_block_callback);
}
