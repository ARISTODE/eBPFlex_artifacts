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
	bpf_trace_printk("STORE");
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
	bpf_trace_printk("CHECK");
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
struct z_stream_s{
	unsigned char* next_in;
	u32 avail_in;
	u64 total_in;
	unsigned char* next_out;
	u32 avail_out;
	u64 total_out;
	char* msg;
	u64* state;
	void* (*zalloc)(void* strm, unsigned int level, unsigned int method);
	void  (*zfree)(void* strm, void* level);
	void* opaque;
	s32 data_type;
	u64 adler;
	u64 reserved;
};
/*int uprobe_deflateInit2_(struct pt_regs *ctx, struct z_stream_s* strm, int level, int method, int windowBits, int memLevel, int strategy, const char* version, int stream_size) {
	unsigned tmpFieldId;
	u32 randVal;
	tmpFieldId = 2917807968;
	store_value(tmpFieldId, &strm->next_in, &strm->next_in, TYPE_U64);
	tmpFieldId = 2917807976;
	store_value(tmpFieldId, &strm->avail_in, &strm->avail_in, TYPE_U32);
	tmpFieldId = 2917807984;
	store_value(tmpFieldId, &strm->total_in, &strm->total_in, TYPE_U64);
	tmpFieldId = 2917807992;
	store_value(tmpFieldId, &strm->next_out, &strm->next_out, TYPE_U64);
	tmpFieldId = 2917807936;
	store_value(tmpFieldId, &strm->avail_out, &strm->avail_out, TYPE_U32);
	tmpFieldId = 2917807944;
	store_value(tmpFieldId, &strm->total_out, &strm->total_out, TYPE_U64);
	tmpFieldId = 2917807952;
	store_value(tmpFieldId, &strm->msg, &strm->msg, TYPE_U64);
	tmpFieldId = 2917807960;
	store_value(tmpFieldId, &strm->state, &strm->state, TYPE_U64);
	tmpFieldId = 2917807904;
	store_value(tmpFieldId, &strm->zalloc, &strm->zalloc, TYPE_U64);
	tmpFieldId = 2917807912;
	store_value(tmpFieldId, &strm->zfree, &strm->zfree, TYPE_U64);
	tmpFieldId = 2917807920;
	store_value(tmpFieldId, &strm->opaque, &strm->opaque, TYPE_U64);
	tmpFieldId = 2917807928;
	store_value(tmpFieldId, &strm->data_type, &strm->data_type, TYPE_S32);
	tmpFieldId = 2917807872;
	store_value(tmpFieldId, &strm->adler, &strm->adler, TYPE_U64);
	tmpFieldId = 2917807880;
	store_value(tmpFieldId, &strm->reserved, &strm->reserved, TYPE_U64);
	return 0;
}*/

int uretprobe_deflateInit2_( struct pt_regs *ctx ) {
	unsigned tmpFieldId;
	check_field(2917807976, TYPE_U32);
	check_field(2917807984, TYPE_U64);
	check_field(2917807936, TYPE_U32);
	check_field(2917807944, TYPE_U64);
	check_field(2917807928, TYPE_S32);
	check_field(2917807872, TYPE_U64);
	check_field(2917807880, TYPE_U64);
	return 0;
}

int uprobe_deflateEnd(struct pt_regs *ctx, struct z_stream_s* strm) {
	unsigned tmpFieldId;
	u32 randVal;
	tmpFieldId = 3768623200;
	store_value(tmpFieldId, &strm->next_in, &strm->next_in, TYPE_U64);
	tmpFieldId = 3768623208;
	store_value(tmpFieldId, &strm->avail_in, &strm->avail_in, TYPE_U32);
	tmpFieldId = 3768623216;
	store_value(tmpFieldId, &strm->total_in, &strm->total_in, TYPE_U64);
	tmpFieldId = 3768623224;
	store_value(tmpFieldId, &strm->next_out, &strm->next_out, TYPE_U64);
	tmpFieldId = 3768623168;
	store_value(tmpFieldId, &strm->avail_out, &strm->avail_out, TYPE_U32);
	tmpFieldId = 3768623176;
	store_value(tmpFieldId, &strm->total_out, &strm->total_out, TYPE_U64);
	tmpFieldId = 3768623184;
	store_value(tmpFieldId, &strm->msg, &strm->msg, TYPE_U64);
	tmpFieldId = 3768623192;
	store_value(tmpFieldId, &strm->state, &strm->state, TYPE_U64);
	tmpFieldId = 3768623136;
	store_value(tmpFieldId, &strm->zalloc, &strm->zalloc, TYPE_U64);
	tmpFieldId = 3768623144;
	store_value(tmpFieldId, &strm->zfree, &strm->zfree, TYPE_U64);
	tmpFieldId = 3768623152;
	store_value(tmpFieldId, &strm->opaque, &strm->opaque, TYPE_U64);
	tmpFieldId = 3768623160;
	store_value(tmpFieldId, &strm->data_type, &strm->data_type, TYPE_S32);
	tmpFieldId = 3768623104;
	store_value(tmpFieldId, &strm->adler, &strm->adler, TYPE_U64);
	tmpFieldId = 3768623112;
	store_value(tmpFieldId, &strm->reserved, &strm->reserved, TYPE_U64);
	return 0;
}

int uretprobe_deflateEnd( struct pt_regs *ctx ) {
	unsigned tmpFieldId;
	check_field(3768623208, TYPE_U32);
	check_field(3768623216, TYPE_U64);
	check_field(3768623168, TYPE_U32);
	check_field(3768623176, TYPE_U64);
	check_field(3768623160, TYPE_S32);
	check_field(3768623104, TYPE_U64);
	check_field(3768623112, TYPE_U64);
	return 0;
}

int uprobe_deflate(struct pt_regs *ctx, struct z_stream_s* strm, int flush) {
	unsigned tmpFieldId;
	u32 randVal;
	tmpFieldId = 652631392;
	store_value(tmpFieldId, &strm->next_in, &strm->next_in, TYPE_U64);
	tmpFieldId = 652631400;
	store_value(tmpFieldId, &strm->avail_in, &strm->avail_in, TYPE_U32);
	tmpFieldId = 652631408;
	store_value(tmpFieldId, &strm->total_in, &strm->total_in, TYPE_U64);
	tmpFieldId = 652631416;
	store_value(tmpFieldId, &strm->next_out, &strm->next_out, TYPE_U64);
	tmpFieldId = 652631360;
	store_value(tmpFieldId, &strm->avail_out, &strm->avail_out, TYPE_U32);
	tmpFieldId = 652631368;
	store_value(tmpFieldId, &strm->total_out, &strm->total_out, TYPE_U64);
	tmpFieldId = 652631376;
	store_value(tmpFieldId, &strm->msg, &strm->msg, TYPE_U64);
	tmpFieldId = 652631384;
	store_value(tmpFieldId, &strm->state, &strm->state, TYPE_U64);
	tmpFieldId = 652631328;
	store_value(tmpFieldId, &strm->zalloc, &strm->zalloc, TYPE_U64);
	tmpFieldId = 652631336;
	store_value(tmpFieldId, &strm->zfree, &strm->zfree, TYPE_U64);
	tmpFieldId = 652631344;
	store_value(tmpFieldId, &strm->opaque, &strm->opaque, TYPE_U64);
	tmpFieldId = 652631352;
	store_value(tmpFieldId, &strm->data_type, &strm->data_type, TYPE_S32);
	tmpFieldId = 652631296;
	store_value(tmpFieldId, &strm->adler, &strm->adler, TYPE_U64);
	tmpFieldId = 652631304;
	store_value(tmpFieldId, &strm->reserved, &strm->reserved, TYPE_U64);
	return 0;
}

int uretprobe_deflate( struct pt_regs *ctx ) {
	unsigned tmpFieldId;
	check_field(652631400, TYPE_U32);
	check_field(652631408, TYPE_U64);
	check_field(652631360, TYPE_U32);
	check_field(652631368, TYPE_U64);
	check_field(652631352, TYPE_S32);
	check_field(652631296, TYPE_U64);
	check_field(652631304, TYPE_U64);
	return 0;
}

