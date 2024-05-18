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
struct poptContext_s{
	u64 optionStack [10];
	u64* os;
	s8 leftovers;
	s32 numLeftovers;
	s32 allocLeftovers;
	s32 nextLeftover;
	u64* options;
	s32 restLeftover;
	const char* appName;
	u64* aliases;
	s32 numAliases;
	u32 flags;
	u64* execs;
	s32 numExecs;
	char* execFail;
	s8 finalArgv;
	s32 finalArgvCount;
	s32 finalArgvAlloced;
	int (*maincall)(int, const char** path);
	u64* doExec;
	const char* execPath;
	s32 execAbsolute;
	const char* otherHelp;
	u64* arg_strip;
};
int uprobe_poptSetExecPath(struct pt_regs *ctx, struct poptContext_s* con, const char* path, int allowAbsolute) {
	unsigned tmpFieldId;
	u32 randVal;
	tmpFieldId = 1401931808;
	store_value(tmpFieldId, &con->os, &con->os, TYPE_U64);
	tmpFieldId = 1401931816;
	store_value(tmpFieldId, &con->leftovers, &con->leftovers, TYPE_U64);
	tmpFieldId = 1401931824;
	store_value(tmpFieldId, &con->numLeftovers, &con->numLeftovers, TYPE_S32);
	tmpFieldId = 1401931828;
	store_value(tmpFieldId, &con->allocLeftovers, &con->allocLeftovers, TYPE_S32);
	tmpFieldId = 1401931832;
	store_value(tmpFieldId, &con->nextLeftover, &con->nextLeftover, TYPE_S32);
	tmpFieldId = 1401931776;
	store_value(tmpFieldId, &con->options, &con->options, TYPE_U64);
	tmpFieldId = 1401931784;
	store_value(tmpFieldId, &con->restLeftover, &con->restLeftover, TYPE_S32);
	tmpFieldId = 1401931792;
	store_value(tmpFieldId, &con->appName, &con->appName, TYPE_U64);
	tmpFieldId = 1401931800;
	store_value(tmpFieldId, &con->aliases, &con->aliases, TYPE_U64);
	tmpFieldId = 1401931872;
	store_value(tmpFieldId, &con->numAliases, &con->numAliases, TYPE_S32);
	tmpFieldId = 1401931876;
	store_value(tmpFieldId, &con->flags, &con->flags, TYPE_U32);
	tmpFieldId = 1401931880;
	store_value(tmpFieldId, &con->execs, &con->execs, TYPE_U64);
	tmpFieldId = 1401931888;
	store_value(tmpFieldId, &con->numExecs, &con->numExecs, TYPE_S32);
	tmpFieldId = 1401931896;
	store_value(tmpFieldId, &con->execFail, &con->execFail, TYPE_U64);
	tmpFieldId = 1401931840;
	store_value(tmpFieldId, &con->finalArgv, &con->finalArgv, TYPE_U64);
	tmpFieldId = 1401931848;
	store_value(tmpFieldId, &con->finalArgvCount, &con->finalArgvCount, TYPE_S32);
	tmpFieldId = 1401931852;
	store_value(tmpFieldId, &con->finalArgvAlloced, &con->finalArgvAlloced, TYPE_S32);
	tmpFieldId = 1401931856;
	store_value(tmpFieldId, &con->maincall, &con->maincall, TYPE_U64);
	tmpFieldId = 1401931864;
	store_value(tmpFieldId, &con->doExec, &con->doExec, TYPE_U64);
	tmpFieldId = 1401932192;
	store_value(tmpFieldId, &con->execPath, &con->execPath, TYPE_U64);
	tmpFieldId = 1401932200;
	store_value(tmpFieldId, &con->execAbsolute, &con->execAbsolute, TYPE_S32);
	tmpFieldId = 1401932208;
	store_value(tmpFieldId, &con->otherHelp, &con->otherHelp, TYPE_U64);
	tmpFieldId = 1401932216;
	store_value(tmpFieldId, &con->arg_strip, &con->arg_strip, TYPE_U64);
	return 0;
}

int uretprobe_poptSetExecPath( struct pt_regs *ctx ) {
	unsigned tmpFieldId;
	check_field(1401931824, TYPE_S32);
	check_field(1401931828, TYPE_S32);
	check_field(1401931832, TYPE_S32);
	check_field(1401931784, TYPE_S32);
	check_field(1401931872, TYPE_S32);
	check_field(1401931876, TYPE_U32);
	check_field(1401931888, TYPE_S32);
	check_field(1401931848, TYPE_S32);
	check_field(1401931852, TYPE_S32);
	check_field(1401932200, TYPE_S32);
	return 0;
}

struct poptOption{
	const char* longName;
	s8 shortName;
	u32 argInfo;
	void* arg;
	s32 val;
	const char* descrip;
	const char* argDescrip;
};
int uprobe_poptGetContext(struct pt_regs *ctx, const char* name, int argc, const char** argv, const struct poptOption* options, unsigned int flags) {
	unsigned tmpFieldId;
	u32 randVal;
	tmpFieldId = 2039723488;
	store_value(tmpFieldId, &options->longName, &options->longName, TYPE_U64);
	tmpFieldId = 2039723496;
	store_value(tmpFieldId, &options->shortName, &options->shortName, TYPE_S8);
	tmpFieldId = 2039723500;
	store_value(tmpFieldId, &options->argInfo, &options->argInfo, TYPE_U32);
	tmpFieldId = 2039723504;
	store_value(tmpFieldId, &options->arg, &options->arg, TYPE_U64);
	tmpFieldId = 2039723512;
	store_value(tmpFieldId, &options->val, &options->val, TYPE_S32);
	tmpFieldId = 2039723456;
	store_value(tmpFieldId, &options->descrip, &options->descrip, TYPE_U64);
	tmpFieldId = 2039723464;
	store_value(tmpFieldId, &options->argDescrip, &options->argDescrip, TYPE_U64);
	return 0;
}

int uretprobe_poptGetContext( struct pt_regs *ctx ) {
	unsigned tmpFieldId;
	check_field(2039723496, TYPE_S8);
	check_field(2039723500, TYPE_U32);
	check_field(2039723512, TYPE_S32);
	return 0;
}

int uprobe_poptResetContext(struct pt_regs *ctx, struct poptContext_s* con) {
	unsigned tmpFieldId;
	u32 randVal;
	tmpFieldId = 104140800;
	store_value(tmpFieldId, &con->os, &con->os, TYPE_U64);
	tmpFieldId = 104140808;
	store_value(tmpFieldId, &con->leftovers, &con->leftovers, TYPE_U64);
	tmpFieldId = 104140816;
	store_value(tmpFieldId, &con->numLeftovers, &con->numLeftovers, TYPE_S32);
	tmpFieldId = 104140820;
	store_value(tmpFieldId, &con->allocLeftovers, &con->allocLeftovers, TYPE_S32);
	tmpFieldId = 104140824;
	store_value(tmpFieldId, &con->nextLeftover, &con->nextLeftover, TYPE_S32);
	tmpFieldId = 104140832;
	store_value(tmpFieldId, &con->options, &con->options, TYPE_U64);
	tmpFieldId = 104140840;
	store_value(tmpFieldId, &con->restLeftover, &con->restLeftover, TYPE_S32);
	tmpFieldId = 104140848;
	store_value(tmpFieldId, &con->appName, &con->appName, TYPE_U64);
	tmpFieldId = 104140856;
	store_value(tmpFieldId, &con->aliases, &con->aliases, TYPE_U64);
	tmpFieldId = 104140864;
	store_value(tmpFieldId, &con->numAliases, &con->numAliases, TYPE_S32);
	tmpFieldId = 104140868;
	store_value(tmpFieldId, &con->flags, &con->flags, TYPE_U32);
	tmpFieldId = 104140872;
	store_value(tmpFieldId, &con->execs, &con->execs, TYPE_U64);
	tmpFieldId = 104140880;
	store_value(tmpFieldId, &con->numExecs, &con->numExecs, TYPE_S32);
	tmpFieldId = 104140888;
	store_value(tmpFieldId, &con->execFail, &con->execFail, TYPE_U64);
	tmpFieldId = 104140896;
	store_value(tmpFieldId, &con->finalArgv, &con->finalArgv, TYPE_U64);
	tmpFieldId = 104140904;
	store_value(tmpFieldId, &con->finalArgvCount, &con->finalArgvCount, TYPE_S32);
	tmpFieldId = 104140908;
	store_value(tmpFieldId, &con->finalArgvAlloced, &con->finalArgvAlloced, TYPE_S32);
	tmpFieldId = 104140912;
	store_value(tmpFieldId, &con->maincall, &con->maincall, TYPE_U64);
	tmpFieldId = 104140920;
	store_value(tmpFieldId, &con->doExec, &con->doExec, TYPE_U64);
	tmpFieldId = 104141184;
	store_value(tmpFieldId, &con->execPath, &con->execPath, TYPE_U64);
	tmpFieldId = 104141192;
	store_value(tmpFieldId, &con->execAbsolute, &con->execAbsolute, TYPE_S32);
	tmpFieldId = 104141200;
	store_value(tmpFieldId, &con->otherHelp, &con->otherHelp, TYPE_U64);
	tmpFieldId = 104141208;
	store_value(tmpFieldId, &con->arg_strip, &con->arg_strip, TYPE_U64);
	return 0;
}

int uretprobe_poptResetContext( struct pt_regs *ctx ) {
	unsigned tmpFieldId;
	check_field(104140816, TYPE_S32);
	check_field(104140820, TYPE_S32);
	check_field(104140824, TYPE_S32);
	check_field(104140840, TYPE_S32);
	check_field(104140864, TYPE_S32);
	check_field(104140868, TYPE_U32);
	check_field(104140880, TYPE_S32);
	check_field(104140904, TYPE_S32);
	check_field(104140908, TYPE_S32);
	check_field(104141192, TYPE_S32);
	return 0;
}

int uprobe_findProgramPath(struct pt_regs *ctx, const char* argv0) {
	unsigned tmpFieldId;
	u32 randVal;
	return 0;
}

int uretprobe_findProgramPath( struct pt_regs *ctx ) {
	unsigned tmpFieldId;
	return 0;
}

int uprobe_poptSaveLong(struct pt_regs *ctx, long int* arg, unsigned int argInfo, long int aLong) {
	unsigned tmpFieldId;
	u32 randVal;
	return 0;
}

int uretprobe_poptSaveLong( struct pt_regs *ctx ) {
	unsigned tmpFieldId;
	return 0;
}

int uprobe_poptSaveInt(struct pt_regs *ctx, int* arg, unsigned int argInfo, long int aLong) {
	unsigned tmpFieldId;
	u32 randVal;
	return 0;
}

int uretprobe_poptSaveInt( struct pt_regs *ctx ) {
	unsigned tmpFieldId;
	return 0;
}

int uprobe_poptGetNextOpt(struct pt_regs *ctx, struct poptContext_s* con) {
	unsigned tmpFieldId;
	u32 randVal;
	tmpFieldId = 1555757568;
	store_value(tmpFieldId, &con->os, &con->os, TYPE_U64);
	tmpFieldId = 1555757576;
	store_value(tmpFieldId, &con->leftovers, &con->leftovers, TYPE_U64);
	tmpFieldId = 1555757584;
	store_value(tmpFieldId, &con->numLeftovers, &con->numLeftovers, TYPE_S32);
	tmpFieldId = 1555757588;
	store_value(tmpFieldId, &con->allocLeftovers, &con->allocLeftovers, TYPE_S32);
	tmpFieldId = 1555757592;
	store_value(tmpFieldId, &con->nextLeftover, &con->nextLeftover, TYPE_S32);
	tmpFieldId = 1555757600;
	store_value(tmpFieldId, &con->options, &con->options, TYPE_U64);
	tmpFieldId = 1555757608;
	store_value(tmpFieldId, &con->restLeftover, &con->restLeftover, TYPE_S32);
	tmpFieldId = 1555757616;
	store_value(tmpFieldId, &con->appName, &con->appName, TYPE_U64);
	tmpFieldId = 1555757624;
	store_value(tmpFieldId, &con->aliases, &con->aliases, TYPE_U64);
	tmpFieldId = 1555757632;
	store_value(tmpFieldId, &con->numAliases, &con->numAliases, TYPE_S32);
	tmpFieldId = 1555757636;
	store_value(tmpFieldId, &con->flags, &con->flags, TYPE_U32);
	tmpFieldId = 1555757640;
	store_value(tmpFieldId, &con->execs, &con->execs, TYPE_U64);
	tmpFieldId = 1555757648;
	store_value(tmpFieldId, &con->numExecs, &con->numExecs, TYPE_S32);
	tmpFieldId = 1555757656;
	store_value(tmpFieldId, &con->execFail, &con->execFail, TYPE_U64);
	tmpFieldId = 1555757664;
	store_value(tmpFieldId, &con->finalArgv, &con->finalArgv, TYPE_U64);
	tmpFieldId = 1555757672;
	store_value(tmpFieldId, &con->finalArgvCount, &con->finalArgvCount, TYPE_S32);
	tmpFieldId = 1555757676;
	store_value(tmpFieldId, &con->finalArgvAlloced, &con->finalArgvAlloced, TYPE_S32);
	tmpFieldId = 1555757680;
	store_value(tmpFieldId, &con->maincall, &con->maincall, TYPE_U64);
	tmpFieldId = 1555757688;
	store_value(tmpFieldId, &con->doExec, &con->doExec, TYPE_U64);
	tmpFieldId = 1555757952;
	store_value(tmpFieldId, &con->execPath, &con->execPath, TYPE_U64);
	tmpFieldId = 1555757960;
	store_value(tmpFieldId, &con->execAbsolute, &con->execAbsolute, TYPE_S32);
	tmpFieldId = 1555757968;
	store_value(tmpFieldId, &con->otherHelp, &con->otherHelp, TYPE_U64);
	tmpFieldId = 1555757976;
	store_value(tmpFieldId, &con->arg_strip, &con->arg_strip, TYPE_U64);
	return 0;
}

int uretprobe_poptGetNextOpt( struct pt_regs *ctx ) {
	unsigned tmpFieldId;
	check_field(1555757584, TYPE_S32);
	check_field(1555757588, TYPE_S32);
	check_field(1555757592, TYPE_S32);
	check_field(1555757608, TYPE_S32);
	check_field(1555757632, TYPE_S32);
	check_field(1555757636, TYPE_U32);
	check_field(1555757648, TYPE_S32);
	check_field(1555757672, TYPE_S32);
	check_field(1555757676, TYPE_S32);
	check_field(1555757960, TYPE_S32);
	return 0;
}

int uprobe_poptGetOptArg(struct pt_regs *ctx, struct poptContext_s* con) {
	unsigned tmpFieldId;
	u32 randVal;
	tmpFieldId = 3309935040;
	store_value(tmpFieldId, &con->os, &con->os, TYPE_U64);
	tmpFieldId = 3309935048;
	store_value(tmpFieldId, &con->leftovers, &con->leftovers, TYPE_U64);
	tmpFieldId = 3309935056;
	store_value(tmpFieldId, &con->numLeftovers, &con->numLeftovers, TYPE_S32);
	tmpFieldId = 3309935060;
	store_value(tmpFieldId, &con->allocLeftovers, &con->allocLeftovers, TYPE_S32);
	tmpFieldId = 3309935064;
	store_value(tmpFieldId, &con->nextLeftover, &con->nextLeftover, TYPE_S32);
	tmpFieldId = 3309935072;
	store_value(tmpFieldId, &con->options, &con->options, TYPE_U64);
	tmpFieldId = 3309935080;
	store_value(tmpFieldId, &con->restLeftover, &con->restLeftover, TYPE_S32);
	tmpFieldId = 3309935088;
	store_value(tmpFieldId, &con->appName, &con->appName, TYPE_U64);
	tmpFieldId = 3309935096;
	store_value(tmpFieldId, &con->aliases, &con->aliases, TYPE_U64);
	tmpFieldId = 3309934976;
	store_value(tmpFieldId, &con->numAliases, &con->numAliases, TYPE_S32);
	tmpFieldId = 3309934980;
	store_value(tmpFieldId, &con->flags, &con->flags, TYPE_U32);
	tmpFieldId = 3309934984;
	store_value(tmpFieldId, &con->execs, &con->execs, TYPE_U64);
	tmpFieldId = 3309934992;
	store_value(tmpFieldId, &con->numExecs, &con->numExecs, TYPE_S32);
	tmpFieldId = 3309935000;
	store_value(tmpFieldId, &con->execFail, &con->execFail, TYPE_U64);
	tmpFieldId = 3309935008;
	store_value(tmpFieldId, &con->finalArgv, &con->finalArgv, TYPE_U64);
	tmpFieldId = 3309935016;
	store_value(tmpFieldId, &con->finalArgvCount, &con->finalArgvCount, TYPE_S32);
	tmpFieldId = 3309935020;
	store_value(tmpFieldId, &con->finalArgvAlloced, &con->finalArgvAlloced, TYPE_S32);
	tmpFieldId = 3309935024;
	store_value(tmpFieldId, &con->maincall, &con->maincall, TYPE_U64);
	tmpFieldId = 3309935032;
	store_value(tmpFieldId, &con->doExec, &con->doExec, TYPE_U64);
	tmpFieldId = 3309934656;
	store_value(tmpFieldId, &con->execPath, &con->execPath, TYPE_U64);
	tmpFieldId = 3309934664;
	store_value(tmpFieldId, &con->execAbsolute, &con->execAbsolute, TYPE_S32);
	tmpFieldId = 3309934672;
	store_value(tmpFieldId, &con->otherHelp, &con->otherHelp, TYPE_U64);
	tmpFieldId = 3309934680;
	store_value(tmpFieldId, &con->arg_strip, &con->arg_strip, TYPE_U64);
	return 0;
}

int uretprobe_poptGetOptArg( struct pt_regs *ctx ) {
	unsigned tmpFieldId;
	check_field(3309935056, TYPE_S32);
	check_field(3309935060, TYPE_S32);
	check_field(3309935064, TYPE_S32);
	check_field(3309935080, TYPE_S32);
	check_field(3309934976, TYPE_S32);
	check_field(3309934980, TYPE_U32);
	check_field(3309934992, TYPE_S32);
	check_field(3309935016, TYPE_S32);
	check_field(3309935020, TYPE_S32);
	check_field(3309934664, TYPE_S32);
	return 0;
}

int uprobe_poptGetArg(struct pt_regs *ctx, struct poptContext_s* con) {
	unsigned tmpFieldId;
	u32 randVal;
	tmpFieldId = 3873094624;
	store_value(tmpFieldId, &con->os, &con->os, TYPE_U64);
	tmpFieldId = 3873094632;
	store_value(tmpFieldId, &con->leftovers, &con->leftovers, TYPE_U64);
	tmpFieldId = 3873094640;
	store_value(tmpFieldId, &con->numLeftovers, &con->numLeftovers, TYPE_S32);
	tmpFieldId = 3873094644;
	store_value(tmpFieldId, &con->allocLeftovers, &con->allocLeftovers, TYPE_S32);
	tmpFieldId = 3873094648;
	store_value(tmpFieldId, &con->nextLeftover, &con->nextLeftover, TYPE_S32);
	tmpFieldId = 3873094592;
	store_value(tmpFieldId, &con->options, &con->options, TYPE_U64);
	tmpFieldId = 3873094600;
	store_value(tmpFieldId, &con->restLeftover, &con->restLeftover, TYPE_S32);
	tmpFieldId = 3873094608;
	store_value(tmpFieldId, &con->appName, &con->appName, TYPE_U64);
	tmpFieldId = 3873094616;
	store_value(tmpFieldId, &con->aliases, &con->aliases, TYPE_U64);
	tmpFieldId = 3873094560;
	store_value(tmpFieldId, &con->numAliases, &con->numAliases, TYPE_S32);
	tmpFieldId = 3873094564;
	store_value(tmpFieldId, &con->flags, &con->flags, TYPE_U32);
	tmpFieldId = 3873094568;
	store_value(tmpFieldId, &con->execs, &con->execs, TYPE_U64);
	tmpFieldId = 3873094576;
	store_value(tmpFieldId, &con->numExecs, &con->numExecs, TYPE_S32);
	tmpFieldId = 3873094584;
	store_value(tmpFieldId, &con->execFail, &con->execFail, TYPE_U64);
	tmpFieldId = 3873094528;
	store_value(tmpFieldId, &con->finalArgv, &con->finalArgv, TYPE_U64);
	tmpFieldId = 3873094536;
	store_value(tmpFieldId, &con->finalArgvCount, &con->finalArgvCount, TYPE_S32);
	tmpFieldId = 3873094540;
	store_value(tmpFieldId, &con->finalArgvAlloced, &con->finalArgvAlloced, TYPE_S32);
	tmpFieldId = 3873094544;
	store_value(tmpFieldId, &con->maincall, &con->maincall, TYPE_U64);
	tmpFieldId = 3873094552;
	store_value(tmpFieldId, &con->doExec, &con->doExec, TYPE_U64);
	tmpFieldId = 3873094240;
	store_value(tmpFieldId, &con->execPath, &con->execPath, TYPE_U64);
	tmpFieldId = 3873094248;
	store_value(tmpFieldId, &con->execAbsolute, &con->execAbsolute, TYPE_S32);
	tmpFieldId = 3873094256;
	store_value(tmpFieldId, &con->otherHelp, &con->otherHelp, TYPE_U64);
	tmpFieldId = 3873094264;
	store_value(tmpFieldId, &con->arg_strip, &con->arg_strip, TYPE_U64);
	return 0;
}

int uretprobe_poptGetArg( struct pt_regs *ctx ) {
	unsigned tmpFieldId;
	check_field(3873094640, TYPE_S32);
	check_field(3873094644, TYPE_S32);
	check_field(3873094648, TYPE_S32);
	check_field(3873094600, TYPE_S32);
	check_field(3873094560, TYPE_S32);
	check_field(3873094564, TYPE_U32);
	check_field(3873094576, TYPE_S32);
	check_field(3873094536, TYPE_S32);
	check_field(3873094540, TYPE_S32);
	check_field(3873094248, TYPE_S32);
	return 0;
}

int uprobe_poptPeekArg(struct pt_regs *ctx, struct poptContext_s* con) {
	unsigned tmpFieldId;
	u32 randVal;
	tmpFieldId = 3197098464;
	store_value(tmpFieldId, &con->os, &con->os, TYPE_U64);
	tmpFieldId = 3197098472;
	store_value(tmpFieldId, &con->leftovers, &con->leftovers, TYPE_U64);
	tmpFieldId = 3197098480;
	store_value(tmpFieldId, &con->numLeftovers, &con->numLeftovers, TYPE_S32);
	tmpFieldId = 3197098484;
	store_value(tmpFieldId, &con->allocLeftovers, &con->allocLeftovers, TYPE_S32);
	tmpFieldId = 3197098488;
	store_value(tmpFieldId, &con->nextLeftover, &con->nextLeftover, TYPE_S32);
	tmpFieldId = 3197098432;
	store_value(tmpFieldId, &con->options, &con->options, TYPE_U64);
	tmpFieldId = 3197098440;
	store_value(tmpFieldId, &con->restLeftover, &con->restLeftover, TYPE_S32);
	tmpFieldId = 3197098448;
	store_value(tmpFieldId, &con->appName, &con->appName, TYPE_U64);
	tmpFieldId = 3197098456;
	store_value(tmpFieldId, &con->aliases, &con->aliases, TYPE_U64);
	tmpFieldId = 3197098400;
	store_value(tmpFieldId, &con->numAliases, &con->numAliases, TYPE_S32);
	tmpFieldId = 3197098404;
	store_value(tmpFieldId, &con->flags, &con->flags, TYPE_U32);
	tmpFieldId = 3197098408;
	store_value(tmpFieldId, &con->execs, &con->execs, TYPE_U64);
	tmpFieldId = 3197098416;
	store_value(tmpFieldId, &con->numExecs, &con->numExecs, TYPE_S32);
	tmpFieldId = 3197098424;
	store_value(tmpFieldId, &con->execFail, &con->execFail, TYPE_U64);
	tmpFieldId = 3197098368;
	store_value(tmpFieldId, &con->finalArgv, &con->finalArgv, TYPE_U64);
	tmpFieldId = 3197098376;
	store_value(tmpFieldId, &con->finalArgvCount, &con->finalArgvCount, TYPE_S32);
	tmpFieldId = 3197098380;
	store_value(tmpFieldId, &con->finalArgvAlloced, &con->finalArgvAlloced, TYPE_S32);
	tmpFieldId = 3197098384;
	store_value(tmpFieldId, &con->maincall, &con->maincall, TYPE_U64);
	tmpFieldId = 3197098392;
	store_value(tmpFieldId, &con->doExec, &con->doExec, TYPE_U64);
	tmpFieldId = 3197098080;
	store_value(tmpFieldId, &con->execPath, &con->execPath, TYPE_U64);
	tmpFieldId = 3197098088;
	store_value(tmpFieldId, &con->execAbsolute, &con->execAbsolute, TYPE_S32);
	tmpFieldId = 3197098096;
	store_value(tmpFieldId, &con->otherHelp, &con->otherHelp, TYPE_U64);
	tmpFieldId = 3197098104;
	store_value(tmpFieldId, &con->arg_strip, &con->arg_strip, TYPE_U64);
	return 0;
}

int uretprobe_poptPeekArg( struct pt_regs *ctx ) {
	unsigned tmpFieldId;
	check_field(3197098480, TYPE_S32);
	check_field(3197098484, TYPE_S32);
	check_field(3197098488, TYPE_S32);
	check_field(3197098440, TYPE_S32);
	check_field(3197098400, TYPE_S32);
	check_field(3197098404, TYPE_U32);
	check_field(3197098416, TYPE_S32);
	check_field(3197098376, TYPE_S32);
	check_field(3197098380, TYPE_S32);
	check_field(3197098088, TYPE_S32);
	return 0;
}

int uprobe_poptGetArgs(struct pt_regs *ctx, struct poptContext_s* con) {
	unsigned tmpFieldId;
	u32 randVal;
	tmpFieldId = 3172183584;
	store_value(tmpFieldId, &con->os, &con->os, TYPE_U64);
	tmpFieldId = 3172183592;
	store_value(tmpFieldId, &con->leftovers, &con->leftovers, TYPE_U64);
	tmpFieldId = 3172183600;
	store_value(tmpFieldId, &con->numLeftovers, &con->numLeftovers, TYPE_S32);
	tmpFieldId = 3172183604;
	store_value(tmpFieldId, &con->allocLeftovers, &con->allocLeftovers, TYPE_S32);
	tmpFieldId = 3172183608;
	store_value(tmpFieldId, &con->nextLeftover, &con->nextLeftover, TYPE_S32);
	tmpFieldId = 3172183552;
	store_value(tmpFieldId, &con->options, &con->options, TYPE_U64);
	tmpFieldId = 3172183560;
	store_value(tmpFieldId, &con->restLeftover, &con->restLeftover, TYPE_S32);
	tmpFieldId = 3172183568;
	store_value(tmpFieldId, &con->appName, &con->appName, TYPE_U64);
	tmpFieldId = 3172183576;
	store_value(tmpFieldId, &con->aliases, &con->aliases, TYPE_U64);
	tmpFieldId = 3172183648;
	store_value(tmpFieldId, &con->numAliases, &con->numAliases, TYPE_S32);
	tmpFieldId = 3172183652;
	store_value(tmpFieldId, &con->flags, &con->flags, TYPE_U32);
	tmpFieldId = 3172183656;
	store_value(tmpFieldId, &con->execs, &con->execs, TYPE_U64);
	tmpFieldId = 3172183664;
	store_value(tmpFieldId, &con->numExecs, &con->numExecs, TYPE_S32);
	tmpFieldId = 3172183672;
	store_value(tmpFieldId, &con->execFail, &con->execFail, TYPE_U64);
	tmpFieldId = 3172183616;
	store_value(tmpFieldId, &con->finalArgv, &con->finalArgv, TYPE_U64);
	tmpFieldId = 3172183624;
	store_value(tmpFieldId, &con->finalArgvCount, &con->finalArgvCount, TYPE_S32);
	tmpFieldId = 3172183628;
	store_value(tmpFieldId, &con->finalArgvAlloced, &con->finalArgvAlloced, TYPE_S32);
	tmpFieldId = 3172183632;
	store_value(tmpFieldId, &con->maincall, &con->maincall, TYPE_U64);
	tmpFieldId = 3172183640;
	store_value(tmpFieldId, &con->doExec, &con->doExec, TYPE_U64);
	tmpFieldId = 3172183968;
	store_value(tmpFieldId, &con->execPath, &con->execPath, TYPE_U64);
	tmpFieldId = 3172183976;
	store_value(tmpFieldId, &con->execAbsolute, &con->execAbsolute, TYPE_S32);
	tmpFieldId = 3172183984;
	store_value(tmpFieldId, &con->otherHelp, &con->otherHelp, TYPE_U64);
	tmpFieldId = 3172183992;
	store_value(tmpFieldId, &con->arg_strip, &con->arg_strip, TYPE_U64);
	return 0;
}

int uretprobe_poptGetArgs( struct pt_regs *ctx ) {
	unsigned tmpFieldId;
	check_field(3172183600, TYPE_S32);
	check_field(3172183604, TYPE_S32);
	check_field(3172183608, TYPE_S32);
	check_field(3172183560, TYPE_S32);
	check_field(3172183648, TYPE_S32);
	check_field(3172183652, TYPE_U32);
	check_field(3172183664, TYPE_S32);
	check_field(3172183624, TYPE_S32);
	check_field(3172183628, TYPE_S32);
	check_field(3172183976, TYPE_S32);
	return 0;
}

int uprobe_poptFreeContext(struct pt_regs *ctx, struct poptContext_s* con) {
	unsigned tmpFieldId;
	u32 randVal;
	tmpFieldId = 2921764896;
	store_value(tmpFieldId, &con->os, &con->os, TYPE_U64);
	tmpFieldId = 2921764904;
	store_value(tmpFieldId, &con->leftovers, &con->leftovers, TYPE_U64);
	tmpFieldId = 2921764912;
	store_value(tmpFieldId, &con->numLeftovers, &con->numLeftovers, TYPE_S32);
	tmpFieldId = 2921764916;
	store_value(tmpFieldId, &con->allocLeftovers, &con->allocLeftovers, TYPE_S32);
	tmpFieldId = 2921764920;
	store_value(tmpFieldId, &con->nextLeftover, &con->nextLeftover, TYPE_S32);
	tmpFieldId = 2921764864;
	store_value(tmpFieldId, &con->options, &con->options, TYPE_U64);
	tmpFieldId = 2921764872;
	store_value(tmpFieldId, &con->restLeftover, &con->restLeftover, TYPE_S32);
	tmpFieldId = 2921764880;
	store_value(tmpFieldId, &con->appName, &con->appName, TYPE_U64);
	tmpFieldId = 2921764888;
	store_value(tmpFieldId, &con->aliases, &con->aliases, TYPE_U64);
	tmpFieldId = 2921764960;
	store_value(tmpFieldId, &con->numAliases, &con->numAliases, TYPE_S32);
	tmpFieldId = 2921764964;
	store_value(tmpFieldId, &con->flags, &con->flags, TYPE_U32);
	tmpFieldId = 2921764968;
	store_value(tmpFieldId, &con->execs, &con->execs, TYPE_U64);
	tmpFieldId = 2921764976;
	store_value(tmpFieldId, &con->numExecs, &con->numExecs, TYPE_S32);
	tmpFieldId = 2921764984;
	store_value(tmpFieldId, &con->execFail, &con->execFail, TYPE_U64);
	tmpFieldId = 2921764928;
	store_value(tmpFieldId, &con->finalArgv, &con->finalArgv, TYPE_U64);
	tmpFieldId = 2921764936;
	store_value(tmpFieldId, &con->finalArgvCount, &con->finalArgvCount, TYPE_S32);
	tmpFieldId = 2921764940;
	store_value(tmpFieldId, &con->finalArgvAlloced, &con->finalArgvAlloced, TYPE_S32);
	tmpFieldId = 2921764944;
	store_value(tmpFieldId, &con->maincall, &con->maincall, TYPE_U64);
	tmpFieldId = 2921764952;
	store_value(tmpFieldId, &con->doExec, &con->doExec, TYPE_U64);
	tmpFieldId = 2921765280;
	store_value(tmpFieldId, &con->execPath, &con->execPath, TYPE_U64);
	tmpFieldId = 2921765288;
	store_value(tmpFieldId, &con->execAbsolute, &con->execAbsolute, TYPE_S32);
	tmpFieldId = 2921765296;
	store_value(tmpFieldId, &con->otherHelp, &con->otherHelp, TYPE_U64);
	tmpFieldId = 2921765304;
	store_value(tmpFieldId, &con->arg_strip, &con->arg_strip, TYPE_U64);
	return 0;
}

int uretprobe_poptFreeContext( struct pt_regs *ctx ) {
	unsigned tmpFieldId;
	check_field(2921764912, TYPE_S32);
	check_field(2921764916, TYPE_S32);
	check_field(2921764920, TYPE_S32);
	check_field(2921764872, TYPE_S32);
	check_field(2921764960, TYPE_S32);
	check_field(2921764964, TYPE_U32);
	check_field(2921764976, TYPE_S32);
	check_field(2921764936, TYPE_S32);
	check_field(2921764940, TYPE_S32);
	check_field(2921765288, TYPE_S32);
	return 0;
}

int uprobe_poptAddAlias(struct pt_regs *ctx, struct poptContext_s* con, int flags) {
	unsigned tmpFieldId;
	u32 randVal;
	tmpFieldId = 501119488;
	store_value(tmpFieldId, &con->os, &con->os, TYPE_U64);
	tmpFieldId = 501119496;
	store_value(tmpFieldId, &con->leftovers, &con->leftovers, TYPE_U64);
	tmpFieldId = 501119504;
	store_value(tmpFieldId, &con->numLeftovers, &con->numLeftovers, TYPE_S32);
	tmpFieldId = 501119508;
	store_value(tmpFieldId, &con->allocLeftovers, &con->allocLeftovers, TYPE_S32);
	tmpFieldId = 501119512;
	store_value(tmpFieldId, &con->nextLeftover, &con->nextLeftover, TYPE_S32);
	tmpFieldId = 501119520;
	store_value(tmpFieldId, &con->options, &con->options, TYPE_U64);
	tmpFieldId = 501119528;
	store_value(tmpFieldId, &con->restLeftover, &con->restLeftover, TYPE_S32);
	tmpFieldId = 501119536;
	store_value(tmpFieldId, &con->appName, &con->appName, TYPE_U64);
	tmpFieldId = 501119544;
	store_value(tmpFieldId, &con->aliases, &con->aliases, TYPE_U64);
	tmpFieldId = 501119552;
	store_value(tmpFieldId, &con->numAliases, &con->numAliases, TYPE_S32);
	tmpFieldId = 501119556;
	store_value(tmpFieldId, &con->flags, &con->flags, TYPE_U32);
	tmpFieldId = 501119560;
	store_value(tmpFieldId, &con->execs, &con->execs, TYPE_U64);
	tmpFieldId = 501119568;
	store_value(tmpFieldId, &con->numExecs, &con->numExecs, TYPE_S32);
	tmpFieldId = 501119576;
	store_value(tmpFieldId, &con->execFail, &con->execFail, TYPE_U64);
	tmpFieldId = 501119584;
	store_value(tmpFieldId, &con->finalArgv, &con->finalArgv, TYPE_U64);
	tmpFieldId = 501119592;
	store_value(tmpFieldId, &con->finalArgvCount, &con->finalArgvCount, TYPE_S32);
	tmpFieldId = 501119596;
	store_value(tmpFieldId, &con->finalArgvAlloced, &con->finalArgvAlloced, TYPE_S32);
	tmpFieldId = 501119600;
	store_value(tmpFieldId, &con->maincall, &con->maincall, TYPE_U64);
	tmpFieldId = 501119608;
	store_value(tmpFieldId, &con->doExec, &con->doExec, TYPE_U64);
	tmpFieldId = 501119872;
	store_value(tmpFieldId, &con->execPath, &con->execPath, TYPE_U64);
	tmpFieldId = 501119880;
	store_value(tmpFieldId, &con->execAbsolute, &con->execAbsolute, TYPE_S32);
	tmpFieldId = 501119888;
	store_value(tmpFieldId, &con->otherHelp, &con->otherHelp, TYPE_U64);
	tmpFieldId = 501119896;
	store_value(tmpFieldId, &con->arg_strip, &con->arg_strip, TYPE_U64);
	return 0;
}

int uretprobe_poptAddAlias( struct pt_regs *ctx ) {
	unsigned tmpFieldId;
	check_field(501119504, TYPE_S32);
	check_field(501119508, TYPE_S32);
	check_field(501119512, TYPE_S32);
	check_field(501119528, TYPE_S32);
	check_field(501119552, TYPE_S32);
	check_field(501119556, TYPE_U32);
	check_field(501119568, TYPE_S32);
	check_field(501119592, TYPE_S32);
	check_field(501119596, TYPE_S32);
	check_field(501119880, TYPE_S32);
	return 0;
}

struct poptItem_s{
	char option[48];
	s32 argc;
	const char** argv;
};
int uprobe_poptAddItem(struct pt_regs *ctx, struct poptContext_s* con, struct poptItem_s* newItem, int flags) {
	unsigned tmpFieldId;
	u32 randVal;
	tmpFieldId = 3934836256;
	store_value(tmpFieldId, &con->os, &con->os, TYPE_U64);
	tmpFieldId = 3934836264;
	store_value(tmpFieldId, &con->leftovers, &con->leftovers, TYPE_U64);
	tmpFieldId = 3934836272;
	store_value(tmpFieldId, &con->numLeftovers, &con->numLeftovers, TYPE_S32);
	tmpFieldId = 3934836276;
	store_value(tmpFieldId, &con->allocLeftovers, &con->allocLeftovers, TYPE_S32);
	tmpFieldId = 3934836280;
	store_value(tmpFieldId, &con->nextLeftover, &con->nextLeftover, TYPE_S32);
	tmpFieldId = 3934836224;
	store_value(tmpFieldId, &con->options, &con->options, TYPE_U64);
	tmpFieldId = 3934836232;
	store_value(tmpFieldId, &con->restLeftover, &con->restLeftover, TYPE_S32);
	tmpFieldId = 3934836240;
	store_value(tmpFieldId, &con->appName, &con->appName, TYPE_U64);
	tmpFieldId = 3934836248;
	store_value(tmpFieldId, &con->aliases, &con->aliases, TYPE_U64);
	tmpFieldId = 3934836320;
	store_value(tmpFieldId, &con->numAliases, &con->numAliases, TYPE_S32);
	tmpFieldId = 3934836324;
	store_value(tmpFieldId, &con->flags, &con->flags, TYPE_U32);
	tmpFieldId = 3934836328;
	store_value(tmpFieldId, &con->execs, &con->execs, TYPE_U64);
	tmpFieldId = 3934836336;
	store_value(tmpFieldId, &con->numExecs, &con->numExecs, TYPE_S32);
	tmpFieldId = 3934836344;
	store_value(tmpFieldId, &con->execFail, &con->execFail, TYPE_U64);
	tmpFieldId = 3934836288;
	store_value(tmpFieldId, &con->finalArgv, &con->finalArgv, TYPE_U64);
	tmpFieldId = 3934836296;
	store_value(tmpFieldId, &con->finalArgvCount, &con->finalArgvCount, TYPE_S32);
	tmpFieldId = 3934836300;
	store_value(tmpFieldId, &con->finalArgvAlloced, &con->finalArgvAlloced, TYPE_S32);
	tmpFieldId = 3934836304;
	store_value(tmpFieldId, &con->maincall, &con->maincall, TYPE_U64);
	tmpFieldId = 3934836312;
	store_value(tmpFieldId, &con->doExec, &con->doExec, TYPE_U64);
	tmpFieldId = 3934836640;
	store_value(tmpFieldId, &con->execPath, &con->execPath, TYPE_U64);
	tmpFieldId = 3934836648;
	store_value(tmpFieldId, &con->execAbsolute, &con->execAbsolute, TYPE_S32);
	tmpFieldId = 3934836656;
	store_value(tmpFieldId, &con->otherHelp, &con->otherHelp, TYPE_U64);
	tmpFieldId = 3934836664;
	store_value(tmpFieldId, &con->arg_strip, &con->arg_strip, TYPE_U64);
	tmpFieldId = 3934835888;
	store_value(tmpFieldId, &newItem->argc, &newItem->argc, TYPE_S32);
	tmpFieldId = 3934835896;
	store_value(tmpFieldId, &newItem->argv, &newItem->argv, TYPE_U64);
	return 0;
}

int uretprobe_poptAddItem( struct pt_regs *ctx ) {
	unsigned tmpFieldId;
	check_field(3934836272, TYPE_S32);
	check_field(3934836276, TYPE_S32);
	check_field(3934836280, TYPE_S32);
	check_field(3934836232, TYPE_S32);
	check_field(3934836320, TYPE_S32);
	check_field(3934836324, TYPE_U32);
	check_field(3934836336, TYPE_S32);
	check_field(3934836296, TYPE_S32);
	check_field(3934836300, TYPE_S32);
	check_field(3934836648, TYPE_S32);
	check_field(3934835888, TYPE_S32);
	return 0;
}

int uprobe_poptBadOption(struct pt_regs *ctx, struct poptContext_s* con, unsigned int flags) {
	unsigned tmpFieldId;
	u32 randVal;
	tmpFieldId = 1674249504;
	store_value(tmpFieldId, &con->os, &con->os, TYPE_U64);
	tmpFieldId = 1674249512;
	store_value(tmpFieldId, &con->leftovers, &con->leftovers, TYPE_U64);
	tmpFieldId = 1674249520;
	store_value(tmpFieldId, &con->numLeftovers, &con->numLeftovers, TYPE_S32);
	tmpFieldId = 1674249524;
	store_value(tmpFieldId, &con->allocLeftovers, &con->allocLeftovers, TYPE_S32);
	tmpFieldId = 1674249528;
	store_value(tmpFieldId, &con->nextLeftover, &con->nextLeftover, TYPE_S32);
	tmpFieldId = 1674249472;
	store_value(tmpFieldId, &con->options, &con->options, TYPE_U64);
	tmpFieldId = 1674249480;
	store_value(tmpFieldId, &con->restLeftover, &con->restLeftover, TYPE_S32);
	tmpFieldId = 1674249488;
	store_value(tmpFieldId, &con->appName, &con->appName, TYPE_U64);
	tmpFieldId = 1674249496;
	store_value(tmpFieldId, &con->aliases, &con->aliases, TYPE_U64);
	tmpFieldId = 1674249568;
	store_value(tmpFieldId, &con->numAliases, &con->numAliases, TYPE_S32);
	tmpFieldId = 1674249572;
	store_value(tmpFieldId, &con->flags, &con->flags, TYPE_U32);
	tmpFieldId = 1674249576;
	store_value(tmpFieldId, &con->execs, &con->execs, TYPE_U64);
	tmpFieldId = 1674249584;
	store_value(tmpFieldId, &con->numExecs, &con->numExecs, TYPE_S32);
	tmpFieldId = 1674249592;
	store_value(tmpFieldId, &con->execFail, &con->execFail, TYPE_U64);
	tmpFieldId = 1674249536;
	store_value(tmpFieldId, &con->finalArgv, &con->finalArgv, TYPE_U64);
	tmpFieldId = 1674249544;
	store_value(tmpFieldId, &con->finalArgvCount, &con->finalArgvCount, TYPE_S32);
	tmpFieldId = 1674249548;
	store_value(tmpFieldId, &con->finalArgvAlloced, &con->finalArgvAlloced, TYPE_S32);
	tmpFieldId = 1674249552;
	store_value(tmpFieldId, &con->maincall, &con->maincall, TYPE_U64);
	tmpFieldId = 1674249560;
	store_value(tmpFieldId, &con->doExec, &con->doExec, TYPE_U64);
	tmpFieldId = 1674249376;
	store_value(tmpFieldId, &con->execPath, &con->execPath, TYPE_U64);
	tmpFieldId = 1674249384;
	store_value(tmpFieldId, &con->execAbsolute, &con->execAbsolute, TYPE_S32);
	tmpFieldId = 1674249392;
	store_value(tmpFieldId, &con->otherHelp, &con->otherHelp, TYPE_U64);
	tmpFieldId = 1674249400;
	store_value(tmpFieldId, &con->arg_strip, &con->arg_strip, TYPE_U64);
	return 0;
}

int uretprobe_poptBadOption( struct pt_regs *ctx ) {
	unsigned tmpFieldId;
	check_field(1674249520, TYPE_S32);
	check_field(1674249524, TYPE_S32);
	check_field(1674249528, TYPE_S32);
	check_field(1674249480, TYPE_S32);
	check_field(1674249568, TYPE_S32);
	check_field(1674249572, TYPE_U32);
	check_field(1674249584, TYPE_S32);
	check_field(1674249544, TYPE_S32);
	check_field(1674249548, TYPE_S32);
	check_field(1674249384, TYPE_S32);
	return 0;
}

int uprobe_poptStrerror(struct pt_regs *ctx, const int error) {
	unsigned tmpFieldId;
	u32 randVal;
	return 0;
}

int uretprobe_poptStrerror( struct pt_regs *ctx ) {
	unsigned tmpFieldId;
	return 0;
}

int uprobe_poptStuffArgs(struct pt_regs *ctx, struct poptContext_s* con, const char** argv) {
	unsigned tmpFieldId;
	u32 randVal;
	tmpFieldId = 718491488;
	store_value(tmpFieldId, &con->os, &con->os, TYPE_U64);
	tmpFieldId = 718491496;
	store_value(tmpFieldId, &con->leftovers, &con->leftovers, TYPE_U64);
	tmpFieldId = 718491504;
	store_value(tmpFieldId, &con->numLeftovers, &con->numLeftovers, TYPE_S32);
	tmpFieldId = 718491508;
	store_value(tmpFieldId, &con->allocLeftovers, &con->allocLeftovers, TYPE_S32);
	tmpFieldId = 718491512;
	store_value(tmpFieldId, &con->nextLeftover, &con->nextLeftover, TYPE_S32);
	tmpFieldId = 718491456;
	store_value(tmpFieldId, &con->options, &con->options, TYPE_U64);
	tmpFieldId = 718491464;
	store_value(tmpFieldId, &con->restLeftover, &con->restLeftover, TYPE_S32);
	tmpFieldId = 718491472;
	store_value(tmpFieldId, &con->appName, &con->appName, TYPE_U64);
	tmpFieldId = 718491480;
	store_value(tmpFieldId, &con->aliases, &con->aliases, TYPE_U64);
	tmpFieldId = 718491424;
	store_value(tmpFieldId, &con->numAliases, &con->numAliases, TYPE_S32);
	tmpFieldId = 718491428;
	store_value(tmpFieldId, &con->flags, &con->flags, TYPE_U32);
	tmpFieldId = 718491432;
	store_value(tmpFieldId, &con->execs, &con->execs, TYPE_U64);
	tmpFieldId = 718491440;
	store_value(tmpFieldId, &con->numExecs, &con->numExecs, TYPE_S32);
	tmpFieldId = 718491448;
	store_value(tmpFieldId, &con->execFail, &con->execFail, TYPE_U64);
	tmpFieldId = 718491392;
	store_value(tmpFieldId, &con->finalArgv, &con->finalArgv, TYPE_U64);
	tmpFieldId = 718491400;
	store_value(tmpFieldId, &con->finalArgvCount, &con->finalArgvCount, TYPE_S32);
	tmpFieldId = 718491404;
	store_value(tmpFieldId, &con->finalArgvAlloced, &con->finalArgvAlloced, TYPE_S32);
	tmpFieldId = 718491408;
	store_value(tmpFieldId, &con->maincall, &con->maincall, TYPE_U64);
	tmpFieldId = 718491416;
	store_value(tmpFieldId, &con->doExec, &con->doExec, TYPE_U64);
	tmpFieldId = 718491360;
	store_value(tmpFieldId, &con->execPath, &con->execPath, TYPE_U64);
	tmpFieldId = 718491368;
	store_value(tmpFieldId, &con->execAbsolute, &con->execAbsolute, TYPE_S32);
	tmpFieldId = 718491376;
	store_value(tmpFieldId, &con->otherHelp, &con->otherHelp, TYPE_U64);
	tmpFieldId = 718491384;
	store_value(tmpFieldId, &con->arg_strip, &con->arg_strip, TYPE_U64);
	return 0;
}

int uretprobe_poptStuffArgs( struct pt_regs *ctx ) {
	unsigned tmpFieldId;
	check_field(718491504, TYPE_S32);
	check_field(718491508, TYPE_S32);
	check_field(718491512, TYPE_S32);
	check_field(718491464, TYPE_S32);
	check_field(718491424, TYPE_S32);
	check_field(718491428, TYPE_U32);
	check_field(718491440, TYPE_S32);
	check_field(718491400, TYPE_S32);
	check_field(718491404, TYPE_S32);
	check_field(718491368, TYPE_S32);
	return 0;
}

int uprobe_poptGetInvocationName(struct pt_regs *ctx, struct poptContext_s* con) {
	unsigned tmpFieldId;
	u32 randVal;
	tmpFieldId = 3213314912;
	store_value(tmpFieldId, &con->os, &con->os, TYPE_U64);
	tmpFieldId = 3213314920;
	store_value(tmpFieldId, &con->leftovers, &con->leftovers, TYPE_U64);
	tmpFieldId = 3213314928;
	store_value(tmpFieldId, &con->numLeftovers, &con->numLeftovers, TYPE_S32);
	tmpFieldId = 3213314932;
	store_value(tmpFieldId, &con->allocLeftovers, &con->allocLeftovers, TYPE_S32);
	tmpFieldId = 3213314936;
	store_value(tmpFieldId, &con->nextLeftover, &con->nextLeftover, TYPE_S32);
	tmpFieldId = 3213314880;
	store_value(tmpFieldId, &con->options, &con->options, TYPE_U64);
	tmpFieldId = 3213314888;
	store_value(tmpFieldId, &con->restLeftover, &con->restLeftover, TYPE_S32);
	tmpFieldId = 3213314896;
	store_value(tmpFieldId, &con->appName, &con->appName, TYPE_U64);
	tmpFieldId = 3213314904;
	store_value(tmpFieldId, &con->aliases, &con->aliases, TYPE_U64);
	tmpFieldId = 3213314848;
	store_value(tmpFieldId, &con->numAliases, &con->numAliases, TYPE_S32);
	tmpFieldId = 3213314852;
	store_value(tmpFieldId, &con->flags, &con->flags, TYPE_U32);
	tmpFieldId = 3213314856;
	store_value(tmpFieldId, &con->execs, &con->execs, TYPE_U64);
	tmpFieldId = 3213314864;
	store_value(tmpFieldId, &con->numExecs, &con->numExecs, TYPE_S32);
	tmpFieldId = 3213314872;
	store_value(tmpFieldId, &con->execFail, &con->execFail, TYPE_U64);
	tmpFieldId = 3213314816;
	store_value(tmpFieldId, &con->finalArgv, &con->finalArgv, TYPE_U64);
	tmpFieldId = 3213314824;
	store_value(tmpFieldId, &con->finalArgvCount, &con->finalArgvCount, TYPE_S32);
	tmpFieldId = 3213314828;
	store_value(tmpFieldId, &con->finalArgvAlloced, &con->finalArgvAlloced, TYPE_S32);
	tmpFieldId = 3213314832;
	store_value(tmpFieldId, &con->maincall, &con->maincall, TYPE_U64);
	tmpFieldId = 3213314840;
	store_value(tmpFieldId, &con->doExec, &con->doExec, TYPE_U64);
	tmpFieldId = 3213314784;
	store_value(tmpFieldId, &con->execPath, &con->execPath, TYPE_U64);
	tmpFieldId = 3213314792;
	store_value(tmpFieldId, &con->execAbsolute, &con->execAbsolute, TYPE_S32);
	tmpFieldId = 3213314800;
	store_value(tmpFieldId, &con->otherHelp, &con->otherHelp, TYPE_U64);
	tmpFieldId = 3213314808;
	store_value(tmpFieldId, &con->arg_strip, &con->arg_strip, TYPE_U64);
	return 0;
}

int uretprobe_poptGetInvocationName( struct pt_regs *ctx ) {
	unsigned tmpFieldId;
	check_field(3213314928, TYPE_S32);
	check_field(3213314932, TYPE_S32);
	check_field(3213314936, TYPE_S32);
	check_field(3213314888, TYPE_S32);
	check_field(3213314848, TYPE_S32);
	check_field(3213314852, TYPE_U32);
	check_field(3213314864, TYPE_S32);
	check_field(3213314824, TYPE_S32);
	check_field(3213314828, TYPE_S32);
	check_field(3213314792, TYPE_S32);
	return 0;
}

int uprobe_poptStrippedArgv(struct pt_regs *ctx, struct poptContext_s* con, int argc, char** argv) {
	unsigned tmpFieldId;
	u32 randVal;
	tmpFieldId = 1290502624;
	store_value(tmpFieldId, &con->os, &con->os, TYPE_U64);
	tmpFieldId = 1290502632;
	store_value(tmpFieldId, &con->leftovers, &con->leftovers, TYPE_U64);
	tmpFieldId = 1290502640;
	store_value(tmpFieldId, &con->numLeftovers, &con->numLeftovers, TYPE_S32);
	tmpFieldId = 1290502644;
	store_value(tmpFieldId, &con->allocLeftovers, &con->allocLeftovers, TYPE_S32);
	tmpFieldId = 1290502648;
	store_value(tmpFieldId, &con->nextLeftover, &con->nextLeftover, TYPE_S32);
	tmpFieldId = 1290502592;
	store_value(tmpFieldId, &con->options, &con->options, TYPE_U64);
	tmpFieldId = 1290502600;
	store_value(tmpFieldId, &con->restLeftover, &con->restLeftover, TYPE_S32);
	tmpFieldId = 1290502608;
	store_value(tmpFieldId, &con->appName, &con->appName, TYPE_U64);
	tmpFieldId = 1290502616;
	store_value(tmpFieldId, &con->aliases, &con->aliases, TYPE_U64);
	tmpFieldId = 1290502560;
	store_value(tmpFieldId, &con->numAliases, &con->numAliases, TYPE_S32);
	tmpFieldId = 1290502564;
	store_value(tmpFieldId, &con->flags, &con->flags, TYPE_U32);
	tmpFieldId = 1290502568;
	store_value(tmpFieldId, &con->execs, &con->execs, TYPE_U64);
	tmpFieldId = 1290502576;
	store_value(tmpFieldId, &con->numExecs, &con->numExecs, TYPE_S32);
	tmpFieldId = 1290502584;
	store_value(tmpFieldId, &con->execFail, &con->execFail, TYPE_U64);
	tmpFieldId = 1290502528;
	store_value(tmpFieldId, &con->finalArgv, &con->finalArgv, TYPE_U64);
	tmpFieldId = 1290502536;
	store_value(tmpFieldId, &con->finalArgvCount, &con->finalArgvCount, TYPE_S32);
	tmpFieldId = 1290502540;
	store_value(tmpFieldId, &con->finalArgvAlloced, &con->finalArgvAlloced, TYPE_S32);
	tmpFieldId = 1290502544;
	store_value(tmpFieldId, &con->maincall, &con->maincall, TYPE_U64);
	tmpFieldId = 1290502552;
	store_value(tmpFieldId, &con->doExec, &con->doExec, TYPE_U64);
	tmpFieldId = 1290502240;
	store_value(tmpFieldId, &con->execPath, &con->execPath, TYPE_U64);
	tmpFieldId = 1290502248;
	store_value(tmpFieldId, &con->execAbsolute, &con->execAbsolute, TYPE_S32);
	tmpFieldId = 1290502256;
	store_value(tmpFieldId, &con->otherHelp, &con->otherHelp, TYPE_U64);
	tmpFieldId = 1290502264;
	store_value(tmpFieldId, &con->arg_strip, &con->arg_strip, TYPE_U64);
	return 0;
}

int uretprobe_poptStrippedArgv( struct pt_regs *ctx ) {
	unsigned tmpFieldId;
	check_field(1290502640, TYPE_S32);
	check_field(1290502644, TYPE_S32);
	check_field(1290502648, TYPE_S32);
	check_field(1290502600, TYPE_S32);
	check_field(1290502560, TYPE_S32);
	check_field(1290502564, TYPE_U32);
	check_field(1290502576, TYPE_S32);
	check_field(1290502536, TYPE_S32);
	check_field(1290502540, TYPE_S32);
	check_field(1290502248, TYPE_S32);
	return 0;
}

