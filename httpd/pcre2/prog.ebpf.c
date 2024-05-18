#include <uapi/linux/bpf.h>
#include <uapi/linux/ptrace.h>
#include <linux/version.h>
#include <linux/types.h>
// Struct definitions for map values
struct s64_value {
    s64 state;
    s64* addr;
};

struct u64_value {
    u64 state;
    u64* addr;
};

struct s32_value {
    s32 state;
    s32* addr;
};

struct u32_value {
    u32 state;
    u32* addr;
};

struct s16_value {
    s16 state;
    s16* addr;
};

struct u16_value {
    u16 state;
    u16* addr;
};

struct s8_value {
    s8 state;
    s8* addr;
};

struct u8_value {
    u8 state;
    u8* addr;
};
// Map declarations for all types
BPF_HASH(s64_map, u32, struct s64_value);
BPF_HASH(u64_map, u32, struct u64_value);
BPF_HASH(s32_map, u32, struct s32_value);
BPF_HASH(u32_map, u32, struct u32_value);
BPF_HASH(s16_map, u32, struct s16_value);
BPF_HASH(u16_map, u32, struct u16_value);
BPF_HASH(s8_map, u32, struct s8_value);
BPF_HASH(u8_map, u32, struct u8_value);
// Enum for representing types
enum value_type {
    TYPE_S64,
    TYPE_U64,
    TYPE_S32,
    TYPE_U32,
    TYPE_S16,
    TYPE_U16,
    TYPE_S8,
    TYPE_U8
};

static void store_value(u32 tmpFieldId, void* state, void* addr, enum value_type type) {
    switch (type) {
        case TYPE_S64:
            {
                struct s64_value value = {
                    .state = *(s64*)state,
                    .addr = addr
                };
                s64_map.update(&tmpFieldId, &value);
            }
            break;
        case TYPE_U64:
            {
                struct u64_value value = {
                    .state = *(u64*)state,
                    .addr = addr
                };
                u64_map.update(&tmpFieldId, &value);
            }
            break;
        case TYPE_S32:
            {
                struct s32_value value = {
                    .state = *(s32*)state,
                    .addr = addr
                };
                s32_map.update(&tmpFieldId, &value);
            }
            break;
        case TYPE_U32:
            {
                struct u32_value value = {
                    .state = *(u32*)state,
                    .addr = addr
                };
                u32_map.update(&tmpFieldId, &value);
            }
            break;
        case TYPE_S16:
            {
                struct s16_value value = {
                    .state = *(s16*)state,
                    .addr = addr
                };
                s16_map.update(&tmpFieldId, &value);
            }
            break;
        case TYPE_U16:
            {
                struct u16_value value = {
                    .state = *(u16*)state,
                    .addr = addr
                };
                u16_map.update(&tmpFieldId, &value);
            }
            break;
        case TYPE_S8:
            {
                struct s8_value value = {
                    .state = *(s8*)state,
                    .addr = addr
                };
                s8_map.update(&tmpFieldId, &value);
            }
            break;
        case TYPE_U8:
            {
                struct u8_value value = {
                    .state = *(u8*)state,
                    .addr = addr
                };
                u8_map.update(&tmpFieldId, &value);
            }
            break;
        default:
            break;
    }
}

static void check_field(u32 unique_field_id, enum value_type type) {
    switch (type) {
        case TYPE_S64:
            {
                struct s64_value *value = s64_map.lookup(&unique_field_id);
                if (value != NULL) {
                    s64 current_state;
                    bpf_probe_read(&current_state, sizeof(s64), value->addr);
                    if (value->state != current_state) {
                        bpf_trace_printk("illegal update");
                    }
                }
            }
            break;
        case TYPE_U64:
            {
                struct u64_value *value = u64_map.lookup(&unique_field_id);
                if (value != NULL) {
                    u64 current_state;
                    bpf_probe_read(&current_state, sizeof(u64), value->addr);
                    if (value->state != current_state) {
                        bpf_trace_printk("illegal update");
                    }
                }
            }
            break;
        case TYPE_S32:
            {
                struct s32_value *value = s32_map.lookup(&unique_field_id);
                if (value != NULL) {
                    s32 current_state;
                    bpf_probe_read(&current_state, sizeof(s32), value->addr);
                    if (value->state != current_state) {
                        bpf_trace_printk("illegal update");
                    }
                }
            }
            break;
        case TYPE_U32:
            {
                struct u32_value *value = u32_map.lookup(&unique_field_id);
                if (value != NULL) {
                    u32 current_state;
                    bpf_probe_read(&current_state, sizeof(u32), value->addr);
                    if (value->state != current_state) {
                        bpf_trace_printk("illegal update");
                    }
                }
            }
            break;
        case TYPE_S16:
            {
                struct s16_value *value = s16_map.lookup(&unique_field_id);
                if (value != NULL) {
                    s16 current_state;
                    bpf_probe_read(&current_state, sizeof(s16), value->addr);
                    if (value->state != current_state) {
                        bpf_trace_printk("illegal update");
                    }
                }
            }
            break;
        case TYPE_U16:
            {
                struct u16_value *value = u16_map.lookup(&unique_field_id);
                if (value != NULL) {
                    u16 current_state;
                    bpf_probe_read(&current_state, sizeof(u16), value->addr);
                    if (value->state != current_state) {
                        bpf_trace_printk("illegal update");
                    }
                }
            }
            break;
        case TYPE_S8:
            {
                struct s8_value *value = s8_map.lookup(&unique_field_id);
                if (value != NULL) {
                    s8 current_state;
                    bpf_probe_read(&current_state, sizeof(s8), value->addr);
                    if (value->state != current_state) {
                        bpf_trace_printk("illegal update");
                    }
                }
            }
            break;
        case TYPE_U8:
            {
                struct u8_value *value = u8_map.lookup(&unique_field_id);
                if (value != NULL) {
                    u8 current_state;
                    bpf_probe_read(&current_state, sizeof(u8), value->addr);
                    if (value->state != current_state) {
                        bpf_trace_printk("illegal update");
                    }
                }
            }
            break;
        default:
            break;
    }
}
struct pcre2_real_general_context_8{
	char memctl[24];
};
int uprobe_pcre2_match_data_create_8(struct pt_regs *ctx, unsigned int oveccount, struct pcre2_real_general_context_8* gcontext) {
	unsigned tmpFieldId;
	u32 randVal;
	return 0;
}

int uretprobe_pcre2_match_data_create_8( struct pt_regs *ctx ) {
	unsigned tmpFieldId;
	return 0;
}

struct pcre2_real_match_data_8{
	char memctl[24];
	u64* code;
	u8 subject;
	u8 mark;
	u64* heapframes;
	u64 heapframes_size;
	u64 subject_length;
	u64 leftchar;
	u64 rightchar;
	u64 startchar;
	u8 matchedby;
	u8 flags;
	u16 oveccount;
	s32 rc;
	long unsigned int ovector [131072];
};
int uprobe_pcre2_match_data_free_8(struct pt_regs *ctx, struct pcre2_real_match_data_8* match_data) {
	unsigned tmpFieldId;
	u32 randVal;
	tmpFieldId = 2864522904;
	store_value(tmpFieldId, &match_data->code, &match_data->code, TYPE_U64);
	tmpFieldId = 2864522912;
	store_value(tmpFieldId, &match_data->subject, &match_data->subject, TYPE_U64);
	tmpFieldId = 2864522920;
	store_value(tmpFieldId, &match_data->mark, &match_data->mark, TYPE_U64);
	tmpFieldId = 2864522928;
	store_value(tmpFieldId, &match_data->heapframes, &match_data->heapframes, TYPE_U64);
	tmpFieldId = 2864522936;
	store_value(tmpFieldId, &match_data->heapframes_size, &match_data->heapframes_size, TYPE_U64);
	tmpFieldId = 2864522944;
	store_value(tmpFieldId, &match_data->subject_length, &match_data->subject_length, TYPE_U64);
	tmpFieldId = 2864522952;
	store_value(tmpFieldId, &match_data->leftchar, &match_data->leftchar, TYPE_U64);
	tmpFieldId = 2864522960;
	store_value(tmpFieldId, &match_data->rightchar, &match_data->rightchar, TYPE_U64);
	tmpFieldId = 2864522968;
	store_value(tmpFieldId, &match_data->startchar, &match_data->startchar, TYPE_U64);
	tmpFieldId = 2864522976;
	store_value(tmpFieldId, &match_data->matchedby, &match_data->matchedby, TYPE_U8);
	tmpFieldId = 2864522977;
	store_value(tmpFieldId, &match_data->flags, &match_data->flags, TYPE_U8);
	tmpFieldId = 2864522978;
	store_value(tmpFieldId, &match_data->oveccount, &match_data->oveccount, TYPE_U16);
	tmpFieldId = 2864522980;
	store_value(tmpFieldId, &match_data->rc, &match_data->rc, TYPE_S32);
	return 0;
}

int uretprobe_pcre2_match_data_free_8( struct pt_regs *ctx ) {
	unsigned tmpFieldId;
	check_field(2864522936, TYPE_U64);
	check_field(2864522944, TYPE_U64);
	check_field(2864522952, TYPE_U64);
	check_field(2864522960, TYPE_U64);
	check_field(2864522968, TYPE_U64);
	check_field(2864522976, TYPE_U8);
	check_field(2864522977, TYPE_U8);
	check_field(2864522978, TYPE_U16);
	check_field(2864522980, TYPE_S32);
	return 0;
}

int uprobe_pcre2_get_ovector_pointer_8(struct pt_regs *ctx, struct pcre2_real_match_data_8* match_data) {
	unsigned tmpFieldId;
	u32 randVal;
	tmpFieldId = 354461016;
	store_value(tmpFieldId, &match_data->code, &match_data->code, TYPE_U64);
	tmpFieldId = 354461024;
	store_value(tmpFieldId, &match_data->subject, &match_data->subject, TYPE_U64);
	tmpFieldId = 354461032;
	store_value(tmpFieldId, &match_data->mark, &match_data->mark, TYPE_U64);
	tmpFieldId = 354461040;
	store_value(tmpFieldId, &match_data->heapframes, &match_data->heapframes, TYPE_U64);
	tmpFieldId = 354461048;
	store_value(tmpFieldId, &match_data->heapframes_size, &match_data->heapframes_size, TYPE_U64);
	tmpFieldId = 354460928;
	store_value(tmpFieldId, &match_data->subject_length, &match_data->subject_length, TYPE_U64);
	tmpFieldId = 354460936;
	store_value(tmpFieldId, &match_data->leftchar, &match_data->leftchar, TYPE_U64);
	tmpFieldId = 354460944;
	store_value(tmpFieldId, &match_data->rightchar, &match_data->rightchar, TYPE_U64);
	tmpFieldId = 354460952;
	store_value(tmpFieldId, &match_data->startchar, &match_data->startchar, TYPE_U64);
	tmpFieldId = 354460960;
	store_value(tmpFieldId, &match_data->matchedby, &match_data->matchedby, TYPE_U8);
	tmpFieldId = 354460961;
	store_value(tmpFieldId, &match_data->flags, &match_data->flags, TYPE_U8);
	tmpFieldId = 354460962;
	store_value(tmpFieldId, &match_data->oveccount, &match_data->oveccount, TYPE_U16);
	tmpFieldId = 354460964;
	store_value(tmpFieldId, &match_data->rc, &match_data->rc, TYPE_S32);
	return 0;
}

int uretprobe_pcre2_get_ovector_pointer_8( struct pt_regs *ctx ) {
	unsigned tmpFieldId;
	check_field(354461048, TYPE_U64);
	check_field(354460928, TYPE_U64);
	check_field(354460936, TYPE_U64);
	check_field(354460944, TYPE_U64);
	check_field(354460952, TYPE_U64);
	check_field(354460960, TYPE_U8);
	check_field(354460961, TYPE_U8);
	check_field(354460962, TYPE_U16);
	check_field(354460964, TYPE_S32);
	return 0;
}

