/* packet-continuity-ble.c — Apple Continuity BLE advertisements.
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
 * Apple's manufacturer-specific advertisement data is a run of
 * type/length/value messages: Handoff, NearbyInfo, AirDrop, FindMy and the
 * rest. It attaches by registration on company id 0x004C, so nothing in the
 * Bluetooth dissectors is edited to reach it.
 *
 * Two things this decode deliberately does not do.
 *
 * It does not report the advertising address, its kind, or the signal
 * strength under names of its own: the Bluetooth dissection already reports
 * all three, and a second name for one byte is worse than no second name --
 * it looks authoritative while being a copy.
 *
 * And it does not tell you what a NearbyInfo activity level means. The
 * sending device encrypts that nibble before transmitting it: its own log
 * says `sending activity level, original: 0x7 encrypted:0xa`. A table lookup
 * against the captured value returns a confident wrong answer, which is a
 * worse failure than an admitted absence.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include "packet-bluetooth.h"

#include "packet-continuity.h"

static int proto_continuity_ble = -1;

static int hf_ble_message = -1;
static int hf_ble_type = -1;
static int hf_ble_length = -1;
static int hf_ble_data = -1;
static int hf_ble_unknown_type = -1;
static int hf_ble_activity = -1;
static int hf_ble_activity_protected = -1;
static int hf_ble_activity_if_plain = -1;
static int hf_ble_flags = -1;
static int hf_ble_address_kind = -1;
static int hf_ble_direction = -1;
static int hf_ble_instance = -1;
static int hf_ble_ad_length = -1;

static int ett_continuity_ble = -1;
static int ett_continuity_ble_message = -1;

static expert_field ei_ble_unknown_type;
static expert_field ei_ble_truncated;

#define APPLE_COMPANY_ID 0x004C

/* The top two bits of the advertising address.
 *
 * An addition, not a restatement: the Bluetooth decode reports the address
 * and whether it is public or random, and stops there. Which kind of random
 * it is lives in these two bits and is reported nowhere -- and it is the
 * whole answer to a question this investigation actually asked. Resolving
 * Rapport's advertisements against every known identity key returned nothing,
 * which looked like a failure and was not: a static random address is
 * structurally not resolvable, and these two bits say so.
 *
 * The names below are conditional on purpose. These bits carry that meaning
 * only when the address is random, and whether it is random is the Bluetooth
 * decode's `bthci_evt.le_peer_address_type` to say -- which is not available
 * here. Naming the bit pattern "non-resolvable random" on a *public* address,
 * where the same bits mean nothing at all, would be a confident wrong answer
 * of exactly the kind this component exists to avoid.
 */
static const value_string address_kinds[] = {
    { 0, "0b00 - non-resolvable, if the address is random" },
    { 1, "0b01 - resolvable, if the address is random" },
    { 2, "0b10 - reserved, if the address is random" },
    { 3, "0b11 - static, if the address is random" },
    { 0, NULL },
};

/* The message types, as established by public analysis -- Martin, Mayberry et
 * al., "Handoff All Your Privacy", and the furiousMAC tables. A type absent
 * from this list is still reported; see the unknown-type path below. */
#define CONTINUITY_MSG_NEARBY_INFO 0x10

static const value_string continuity_message_types[] = {
    { 0x02, "iBeacon" },
    { 0x05, "AirDrop" },
    { 0x06, "HomeKit" },
    { 0x07, "Proximity Pairing" },
    { 0x08, "Hey Siri" },
    { 0x09, "AirPlay Target" },
    { 0x0a, "AirPlay Source" },
    { 0x0b, "Magic Switch" },
    { 0x0c, "Handoff" },
    { 0x0d, "Tethering Target" },
    { 0x0e, "Tethering Source" },
    { 0x0f, "Nearby Action" },
    { 0x10, "Nearby Info" },
    { 0x12, "Find My" },
    { 0, NULL },
};

/* The services these advertisements belong to.
 *
 * A Continuity message names its service on the wire, in one byte, with no key
 * needed -- which makes the advertisement the one transport where the service
 * attribution is read rather than inferred. The table is the umbrella's, not
 * this file's: the same service reached over another transport must come back
 * under the same name, or selecting "this service, everywhere" selects half of
 * it.
 *
 * Only the types this decode actually recognises are registered. A service
 * that is registered and never attributed would appear in the table as
 * something this decode supports, which is a claim, and an empty one.
 */
static void dissect_nearby_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                int length);

static const continuity_service ble_services[] = {
    { "ibeacon",            "iBeacon",            NULL, NULL },
    { "airdrop",            "AirDrop",            NULL, NULL },
    { "homekit",            "HomeKit",            NULL, NULL },
    { "proximity-pairing",  "Proximity Pairing",  NULL, NULL },
    { "hey-siri",           "Hey Siri",           NULL, NULL },
    { "airplay-target",     "AirPlay Target",     NULL, NULL },
    { "airplay-source",     "AirPlay Source",     NULL, NULL },
    { "magic-switch",       "Magic Switch",       NULL, NULL },
    { "handoff",            "Handoff",            NULL, NULL },
    { "tethering-target",   "Tethering Target",   NULL, NULL },
    { "tethering-source",   "Tethering Source",   NULL, NULL },
    { "nearby-action",      "Nearby Action",      NULL, NULL },
    { "nearby-info",        "Nearby Info",        dissect_nearby_info, NULL },
    { "find-my",            "Find My",            NULL, NULL },
};

/* Message type -> index into the table above, in the same order as the type
 * list. Kept as a lookup rather than a field on the type list so that the
 * type list stays what it is: what the dissection binary renders for the
 * type byte. */
static const uint8_t ble_service_types[] = {
    0x02, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x12,
};

static const continuity_service *service_for_type(uint8_t type)
{
    for (unsigned i = 0; i < array_length(ble_service_types); i++) {
        if (ble_service_types[i] == type) {
            return &ble_services[i];
        }
    }
    /* An unrecognised type keeps its bytes and its type identifier and gains
     * no service. Naming it would be inventing one. */
    return NULL;
}

/* What each activity value would mean if the nibble were plaintext. Offered
 * only as a conditional, never as the field's meaning -- see the file comment.
 */
static const value_string nearby_activity_if_plain[] = {
    { 0x00, "Unknown" },
    { 0x01, "Idle" },
    { 0x03, "Audio playing with screen off" },
    { 0x05, "Screen on" },
    { 0x07, "Screen on and video playing" },
    { 0x09, "Watch on wrist and unlocked" },
    { 0x0a, "Recent user interaction" },
    { 0x0b, "User driving" },
    { 0x0d, "Active call or FaceTime" },
    { 0, NULL },
};

static void dissect_nearby_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                int offset, int length)
{
    if (length < 1) {
        return;
    }
    uint8_t first = tvb_get_uint8(tvb, offset);
    uint8_t activity = first & 0x0f;

    proto_tree_add_uint(tree, hf_ble_flags, tvb, offset, 1, first >> 4);

    /* The value as transmitted, named for what it is. */
    proto_item *item = proto_tree_add_uint(tree, hf_ble_activity, tvb, offset, 1, activity);
    proto_item_append_text(item, " (protected on the wire)");

    proto_item *protected_item =
        proto_tree_add_boolean(tree, hf_ble_activity_protected, tvb, offset, 1, true);
    proto_item_set_generated(protected_item);

    /* The interpretation, marked as conditional on the value having been
     * recovered -- which it has not been.
     *
     * The qualifier is part of the *value*, not only of how the value is
     * displayed. A reader of the packet detail sees either one, but a field
     * extraction reports the value alone -- so a qualifier that lived only in
     * the display text would vanish exactly where this decode's output is
     * most likely to be read by a machine and pasted into a report. Caught by
     * a test that extracted the field and got "Audio playing with screen off"
     * back with nothing to say it was a guess about ciphertext.
     *
     * And no comma in it. A field extraction separates a frame's repeated
     * values with commas, so a comma inside one value splits it into two
     * that each look like a value. Also caught by that test, on the sentence
     * this comment is about.
     */
    const char *conditional = try_val_to_str(activity, nearby_activity_if_plain);
    if (conditional != NULL) {
        proto_item *guess = proto_tree_add_string(
            tree, hf_ble_activity_if_plain, tvb, offset, 1,
            wmem_strdup_printf(pinfo->pool,
                               "%s -- an interpretation that holds only for an "
                               "untransformed value; this one is transformed",
                               conditional));
        proto_item_set_generated(guess);
    }
}

/* ---------------------------------------------------------------------------
 * Advertising data the capturing device sends.
 *
 * A Mac hands its own advertising data to the controller in a vendor command,
 * 0xfd4b, not in the standard advertising-data commands -- measured on the
 * reference capture (macOS 15.7.9, BCM4378): 53 such commands, every one
 * carrying Apple manufacturer data, and no standard advertising-data command
 * at all. The Bluetooth dissection reports it as an unknown vendor command,
 * so what the device announced was in the capture and in no record.
 *
 * Its parameters are  instance(1) | data_length(1) | AD data (31, padded).
 *
 * The AD bytes are handed to the Bluetooth dissection's own AD walk, exactly
 * as it hands over a standard command's -- so flags, TX power and the
 * manufacturer framing are decoded where they always are, and the Apple data
 * reaches this component through the same registration a received report
 * does. Sent and received messages share one decode by construction.
 */
#define VENDOR_ADVERTISING_DATA_OPCODE 0xfd4b
#define ADVERTISING_DATA_MAX 31

static dissector_handle_t ad_handle;

/* The HCI command decode's own fields: which command this is, and the bytes it
 * reports as the command's parameters. Read rather than re-parsed, so this
 * does not depend on how the frame is encapsulated. */
static int hf_hci_opcode = -1;
static int hf_hci_parameter = -1;
static int proto_hci_command = -1;

/* What the command header said, for the record its Apple data produces. */
typedef struct {
    uint8_t instance;
    uint8_t data_length;
} sent_advertising_header;

/* The command decode's own subtree, to put the advertising data inside --
 * where that decode puts a standard advertising-data command's. At the top of
 * the tree it reads as a separate protocol layer, which a reader expecting
 * advertising data only inside an HCI packet does not find. */
typedef struct {
    int proto;
    proto_tree *found;
} protocol_subtree;

static void find_protocol_subtree(proto_node *node, void *data)
{
    protocol_subtree *search = (protocol_subtree *)data;
    if (search->found == NULL && node->finfo != NULL && node->finfo->hfinfo != NULL &&
        node->finfo->hfinfo->id == search->proto) {
        search->found = proto_item_get_subtree((proto_item *)node);
    }
}

/* The first occurrence of a field in this frame's tree, or NULL. */
static field_info *first_field(proto_tree *tree, int hf)
{
    if (hf < 0) {
        return NULL;
    }
    GPtrArray *found = proto_find_first_finfo(tree, hf);
    return found != NULL && found->len > 0 ? (field_info *)g_ptr_array_index(found, 0) : NULL;
}

/* A post-dissector, acting only on 0xfd4b, because registering in the
 * command decode's own table does not work. The command decode does
 * offer every vendor command to its "Decode As" table first, but that table
 * can only be given a current entry, never an initial one, and loading the
 * Decode As settings at start-up resets every current entry -- so a dissector
 * could stay there only by re-asserting itself over the operator's own choice
 * each time a file is opened. This takes nothing from the command decode: it
 * reads the fields it already reports and adds the advertising data beside
 * them. Frames that are not 0xfd4b are not touched.
 *
 * Accepted only when the header is self-consistent: data_length <= 31 and
 * 2 + data_length <= the parameters present. A decode that read a malformed
 * header would report structure that was never sent. */
/* Where the first pass found a sent advertisement's command parameters, in
 * the frame. The command decode's fields are only guaranteed to this
 * post-dissector on the first pass (they are primed then and not on later
 * ones, which a two-pass read or a filtered redissection does), so later
 * passes read the parameters from where the first one found them. */
typedef struct {
    int start;
    int length;
} sent_parameters;

#define SENT_PARAMETERS_KEY 1

static int dissect_continuity_sent_advertising(tvbuff_t *tvb, packet_info *pinfo,
                                               proto_tree *tree, void *data _U_)
{
    if (tree == NULL || ad_handle == NULL || !proto_is_frame_protocol(pinfo->layers, "bthci_cmd")) {
        return 0;
    }

    tvbuff_t *params = NULL;
    int length = 0;
    if (PINFO_FD_VISITED(pinfo)) {
        const sent_parameters *found = (const sent_parameters *)p_get_proto_data(
            wmem_file_scope(), pinfo, proto_continuity_ble, SENT_PARAMETERS_KEY);
        if (found == NULL) {
            return 0;
        }
        params = tvb_new_subset_length(tvb, found->start, found->length);
        length = found->length;
    } else {
        field_info *opcode = first_field(tree, hf_hci_opcode);
        if (opcode == NULL ||
            fvalue_get_uinteger(opcode->value) != VENDOR_ADVERTISING_DATA_OPCODE) {
            return 0;
        }
        field_info *parameters = first_field(tree, hf_hci_parameter);
        if (parameters == NULL || parameters->ds_tvb != tvb || parameters->length < 2) {
            return 0;
        }
        params = tvb_new_subset_length(tvb, parameters->start, parameters->length);
        length = parameters->length;
    }

    uint8_t data_length = tvb_get_uint8(params, 1);
    if (data_length == 0 || data_length > ADVERTISING_DATA_MAX || 2 + data_length > length) {
        return 0;
    }

    /* Under the command's own node where the tree has it, else at the top:
     * a pass that builds only the fields asked for may not have the node. */
    protocol_subtree command = { proto_hci_command, NULL };
    proto_tree_children_foreach(tree, find_protocol_subtree, &command);
    proto_tree *parent = command.found != NULL ? command.found : tree;

    if (!PINFO_FD_VISITED(pinfo)) {
        if (command.found == NULL) {
            return 0;
        }
        sent_parameters *found = wmem_new(wmem_file_scope(), sent_parameters);
        found->start = tvb_raw_offset(params) - tvb_raw_offset(tvb);
        found->length = length;
        p_add_proto_data(wmem_file_scope(), pinfo, proto_continuity_ble, SENT_PARAMETERS_KEY,
                         found);
    }

    sent_advertising_header *header = wmem_new(pinfo->pool, sent_advertising_header);
    header->instance = tvb_get_uint8(params, 0);
    header->data_length = data_length;
    p_add_proto_data(pinfo->pool, pinfo, proto_continuity_ble, 0, header);

    bluetooth_eir_ad_data_t *ad_data = wmem_new0(pinfo->pool, bluetooth_eir_ad_data_t);
    call_dissector_with_data(ad_handle, tvb_new_subset_length(params, 2, data_length), pinfo,
                             parent, ad_data);
    return length;
}

static int dissect_continuity_ble(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                  void *data)
{
    int offset = 0;
    int remaining = tvb_reported_length(tvb);

    proto_item *root = proto_tree_add_item(tree, proto_continuity_ble, tvb, 0, -1, ENC_NA);
    proto_tree *ble_tree = proto_item_add_subtree(root, ett_continuity_ble);

    /* The umbrella first, before anything of this decode's own. */
    continuity_mark(pinfo, ble_tree, tvb, NULL);

    /* Which way the advertisement went, from the packet that carried it: an
     * HCI command is the host asking its controller to transmit -- this device
     * sending -- and an HCI event is the controller reporting what it heard.
     * Not from the address: a command carries none, and addresses rotate. */
    bool sent = proto_is_frame_protocol(pinfo->layers, "bthci_cmd");
    proto_item *direction =
        proto_tree_add_string(ble_tree, hf_ble_direction, tvb, 0, 0, sent ? "sent" : "received");
    proto_item_set_generated(direction);

    sent_advertising_header *header =
        (sent_advertising_header *)p_get_proto_data(pinfo->pool, pinfo, proto_continuity_ble, 0);
    if (sent && header != NULL) {
        proto_item *instance =
            proto_tree_add_uint(ble_tree, hf_ble_instance, tvb, 0, 0, header->instance);
        proto_item_set_generated(instance);
        proto_item *length =
            proto_tree_add_uint(ble_tree, hf_ble_ad_length, tvb, 0, 0, header->data_length);
        proto_item_set_generated(length);
    }

    bluetooth_eir_ad_data_t *ad_data = (bluetooth_eir_ad_data_t *)data;
    if (ad_data != NULL && ad_data->bd_addr != NULL) {
        uint8_t kind = ad_data->bd_addr[0] >> 6;
        proto_item *kind_item =
            proto_tree_add_uint(ble_tree, hf_ble_address_kind, tvb, 0, 0, kind);
        proto_item_set_generated(kind_item);
    }

    col_append_sep_str(pinfo->cinfo, COL_PROTOCOL, "/", "Continuity");

    unsigned messages = 0;
    while (remaining >= 2) {
        uint8_t type = tvb_get_uint8(tvb, offset);
        uint8_t length = tvb_get_uint8(tvb, offset + 1);

        /* A message whose declared length runs past the advertisement. It is
         * reported with its type and the bytes that are actually there,
         * rather than dropped: those bytes are what the device transmitted,
         * and a record that vanishes because one field disagreed with itself
         * is the failure this component is supposed to avoid.
         *
         * Observed here, not hypothetical. Every type-0x06 message in the
         * reference capture declares a length that overruns its own
         * advertising entry -- 0x31 against 17 bytes present -- so either
         * that type does not carry a plain length byte or these reports are
         * truncated by the controller. Which of the two it is has not been
         * established, so nothing here decides: the type is reported, the
         * bytes are reported, and the disagreement is reported as a
         * disagreement.
         */
        bool truncated = (2 + length > remaining);
        int present = truncated ? remaining - 2 : length;

        proto_item *message_item = proto_tree_add_item(ble_tree, hf_ble_message, tvb, offset,
                                                       2 + present, ENC_NA);
        proto_tree *message_tree =
            proto_item_add_subtree(message_item, ett_continuity_ble_message);
        const char *name = try_val_to_str(type, continuity_message_types);
        proto_item_set_text(message_item, "%s message", name != NULL ? name : "Unknown");

        /* The service this message belongs to, on the message rather than on
         * the record: one advertisement can carry messages of two services,
         * and attributing the record to the first of them would be a wrong
         * answer that reads like a right one. */
        const continuity_service *service = service_for_type(type);
        continuity_service_report(pinfo, message_tree, tvb, service);

        proto_tree_add_item(message_tree, hf_ble_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(message_tree, hf_ble_length, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
        if (present > 0) {
            /* The raw bytes, always -- for a type this decode understands as
             * much as for one it does not, and for a truncated message as
             * much as for a whole one. An operator looking at an unfamiliar
             * message needs the bytes more than anyone. */
            proto_tree_add_item(message_tree, hf_ble_data, tvb, offset + 2, present, ENC_NA);
        }
        if (truncated) {
            expert_add_info_format(pinfo, message_item, &ei_ble_truncated,
                                   "Declares %u byte(s) but only %d are present in the "
                                   "advertisement; the type and the present bytes are "
                                   "reported and the rest of the advertisement is not "
                                   "walked",
                                   length, present);
        }

        if (name == NULL) {
            /* Preserved with its type and bytes, and flagged, rather than
             * skipped. The set of types these devices carry changes without
             * notice, and an operator investigating an unknown one is a
             * primary use of this component rather than an error case. */
            proto_item *unknown = proto_tree_add_uint(message_tree, hf_ble_unknown_type, tvb,
                                                      offset, 1, type);
            proto_item_set_generated(unknown);
            expert_add_info_format(pinfo, message_item, &ei_ble_unknown_type,
                                   "Continuity message type 0x%02x is not in any published "
                                   "table; its %u byte(s) are reported undecoded",
                                   type, length);
        } else if (service != NULL && service->dissect != NULL) {
            /* Through the table, not a branch on the type. A further service
             * that learns to read its own payload is then a registration --
             * which is the property the whole split exists for, since the
             * next services to arrive are on a different transport entirely
             * and must not have to edit this file. */
            service->dissect(tvb, pinfo, message_tree, offset + 2, present);
        }

        col_append_sep_str(pinfo->cinfo, COL_INFO, ", ",
                           name != NULL ? name : "Unknown Continuity message");

        offset += 2 + present;
        remaining -= 2 + present;
        messages++;

        if (truncated) {
            /* Walking on would read the next "type" out of the middle of
             * this message's bytes and report a message that was never
             * sent. */
            break;
        }
    }

    proto_item_append_text(root, ", %u message(s)", messages);
    return tvb_captured_length(tvb);
}

void proto_register_continuity_ble(void)
{
    static hf_register_info hf[] = {
        { &hf_ble_message,
          { "Continuity message", "continuity.ble.message", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL } },
        { &hf_ble_type,
          { "Type", "continuity.ble.type", FT_UINT8, BASE_HEX,
            VALS(continuity_message_types), 0x0, NULL, HFILL } },
        { &hf_ble_length,
          { "Length", "continuity.ble.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ble_data,
          { "Data", "continuity.ble.data", FT_BYTES, BASE_NONE, NULL, 0x0,
            "The message's bytes as transmitted", HFILL } },
        { &hf_ble_unknown_type,
          { "Unrecognised type", "continuity.ble.unknown_type", FT_UINT8, BASE_HEX, NULL, 0x0,
            "A message type this decode does not recognise, retained with its bytes",
            HFILL } },
        { &hf_ble_activity,
          { "Activity level", "continuity.ble.nearby.activity", FT_UINT8, BASE_HEX, NULL, 0x0,
            "As transmitted. The sender transforms this value before sending it, so this "
            "is not the device's activity level", HFILL } },
        { &hf_ble_activity_protected,
          { "Activity level is protected", "continuity.ble.nearby.activity_protected",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "The sender encrypts this field before transmission", HFILL } },
        { &hf_ble_activity_if_plain,
          { "Activity level, conditionally", "continuity.ble.nearby.activity_if_plain",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "What the transmitted value would mean if it had not been transformed. "
            "Not established", HFILL } },
        { &hf_ble_address_kind,
          { "Advertising address type bits", "continuity.ble.address_kind", FT_UINT8,
            BASE_DEC, VALS(address_kinds), 0x0,
            "The top two bits of the advertising address. They say which kind of "
            "random address it is -- and only a resolvable one can be matched against "
            "an identity key -- but only when the address is random, which "
            "bthci_evt.le_peer_address_type is what says", HFILL } },
        { &hf_ble_direction,
          { "Direction", "continuity.ble.direction", FT_STRING, BASE_NONE, NULL, 0x0,
            "\"sent\" for advertising data the capturing device handed to its controller, "
            "\"received\" for an advertising report of another device's advertisement. "
            "From the HCI packet that carried it, not from the address", HFILL } },
        { &hf_ble_instance,
          { "Advertising instance", "continuity.ble.instance", FT_UINT8, BASE_DEC, NULL, 0x0,
            "The advertising set the sent data belongs to, from the vendor command's header",
            HFILL } },
        { &hf_ble_ad_length,
          { "Advertising data length", "continuity.ble.ad_length", FT_UINT8, BASE_DEC, NULL, 0x0,
            "How many bytes of advertising data the vendor command declared, out of 31",
            HFILL } },
        { &hf_ble_flags,
          { "Flags", "continuity.ble.nearby.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
            HFILL } },
    };

    static int *ett[] = { &ett_continuity_ble, &ett_continuity_ble_message };

    static ei_register_info ei[] = {
        { &ei_ble_unknown_type,
          { "continuity.ble.unknown_type.expert", PI_UNDECODED, PI_NOTE,
            "Unrecognised Continuity message type, retained undecoded", EXPFILL } },
        { &ei_ble_truncated,
          { "continuity.ble.truncated", PI_MALFORMED, PI_WARN,
            "Continuity message runs past the end of the advertisement", EXPFILL } },
    };

    proto_continuity_ble = proto_register_protocol("Apple Continuity Advertisement",
                                                   "Continuity BLE", "continuity.ble");
    proto_register_field_array(proto_continuity_ble, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_module_t *expert = expert_register_protocol(proto_continuity_ble);
    expert_register_field_array(expert, ei, array_length(ei));

    register_dissector("continuity.ble", dissect_continuity_ble, proto_continuity_ble);
}

void proto_reg_handoff_continuity_ble(void)
{
    for (unsigned i = 0; i < array_length(ble_services); i++) {
        continuity_service_register(&ble_services[i]);
    }

    /* By registration on the company id, against the table the Bluetooth
     * dissection already keys manufacturer-specific data by. This is what
     * reaches both the legacy and the extended advertising report without
     * either being handled here: the report form is the Bluetooth
     * dissection's problem, and it has already solved it. A decoder that
     * walked the reports itself and handled only the legacy form would yield
     * nothing at all on current hardware, which uses extended reports
     * exclusively.
     */
    dissector_add_uint("btcommon.eir_ad.manufacturer_company_id", APPLE_COMPANY_ID,
                       find_dissector("continuity.ble"));

    ad_handle = find_dissector("btcommon.eir_ad.ad");
    hf_hci_opcode = proto_registrar_get_id_byname("bthci_cmd.opcode");
    hf_hci_parameter = proto_registrar_get_id_byname("bthci_cmd.parameter");
    proto_hci_command = proto_get_id_by_filter_name("bthci_cmd");

    /* Sent advertising data, read from the command decode's own fields. The
     * fields -- and the command's node -- are declared wanted, so they are in
     * the tree for this to read whatever else the operator filters on. */
    dissector_handle_t sent_handle = create_dissector_handle(dissect_continuity_sent_advertising,
                                                             proto_continuity_ble);
    register_postdissector(sent_handle);
    GArray *wanted = g_array_new(false, false, (unsigned)sizeof(int));
    g_array_append_val(wanted, hf_hci_opcode);
    g_array_append_val(wanted, hf_hci_parameter);
    /* The command's own node too: without it a filtered pass fakes it away,
     * and there is nowhere inside the command to put the advertising data. */
    g_array_append_val(wanted, proto_hci_command);
    set_postdissector_wanted_hfids(sent_handle, wanted);
}
