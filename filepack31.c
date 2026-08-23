#define _CRT_SECURE_NO_WARNINGS

/*
 * Build from an x86 or x64 Visual Studio Developer Command Prompt:
 *   cl /nologo /O2 /W4 /MT /utf-8 /TC filepack31.c /Fe:filepack31.exe
 *
 * Build with the matching MinGW-w64 toolchain:
 *   gcc -std=c11 -O2 -municode filepack31.c -o filepack31.exe
 */

#include <windows.h>
#include <io.h>
#include <direct.h>
#include <errno.h>
#include <limits.h>
#include <locale.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wchar.h>
#include <wctype.h>

#define IO_BUFFER_SIZE (1024U * 1024U)
#define BPE_STACK_SIZE 4096U
#define INVALID_INDEX UINT32_MAX
#define KEY_FILE_NAME L"pack_keyfile_kfueheish15538fa9or.key"

/*
 * 以下五个结构体直接映射 PACK 文件中的二进制数据。
 * 必须保持 1 字节对齐并使用定宽整数，否则 x86、x64 生成的文件将不兼容。
 */
#pragma pack(push, 1)
/* PACK 尾部总头：记录条目数量以及条目表在文件中的绝对偏移。 */
typedef struct PACKHEAD {
    unsigned char signature[16]; /* 固定签名 "FilePackVer3.1"。 */
    uint32_t entry_count;        /* 文件条目数量。 */
    /*
     * 旧代码把此字段拆成 entry_offset 和 unknown1 两个 uint32_t。
     * 实际磁盘格式中它们分别是偏移的低、高 32 位，合并后仍占 8 字节，
     * 因而 PACKHEAD 的 28 字节布局不变，同时可定位 4 GiB 之后的条目表。
     */
    uint64_t entry_offset;       /* 条目表的 64 位绝对文件偏移。 */
} PACKHEAD;

/* PACK 密钥块：位于总头之前，保存归档密钥材料及哈希块长度。 */
typedef struct PACKKEY {
    unsigned char signature[32]; /* 经过链式加密的密钥块签名。 */
    uint32_t hash_size;          /* PACKHASH 与哈希数据的总长度。 */
    unsigned char key[1024];     /* 前 256 字节用于计算归档主密钥。 */
} PACKKEY;

/* 文件名哈希区头：描述 256 个桶、文件索引和可选压缩状态。 */
typedef struct PACKHASH {
    unsigned char signature[16]; /* 固定签名 "HashVer1.4"。 */
    uint32_t table_size;         /* 哈希桶数量，当前格式固定为 256。 */
    uint32_t file_count;         /* 哈希区记录的文件数量。 */
    uint32_t index_size;         /* 文件索引数组的字节数。 */
    uint32_t data_size;          /* 紧随本结构的哈希数据长度。 */
    uint32_t is_compressed;      /* 哈希数据压缩标志，当前写入零。 */
    /*
     * EXE 的 Delphi RTTI 将该字段命名为 FSaftyDataSize（原程序拼写如此）。
     * 非零时，哈希表读写接口要求每项关联数据的长度与此值相等；零表示不校验。
     * TFilePack 构造函数默认设置为 4，因为每个文件名映射到一个 uint32_t 条目索引。
     */
    uint32_t safety_data_size;   /* 哈希项关联数据的预期长度，原版默认值为 4。 */
    uint32_t string_hash_version; /* 文件名字符串哈希算法版本，当前版本为 0。 */
    unsigned char reserved[24];  /* HashVer1.4 保留区，当前样本及原版写入均为零。 */
} PACKHASH;

/* 单文件条目：偏移为 64 位；长度及状态字段保持原格式的 32 位表示。 */
typedef struct PACKENTRY {
    /*
     * 旧代码把此字段拆成 offset 和 unknown1 两个 uint32_t。
     * 实际两者共同组成小端序 64 位偏移，合并后 PACKENTRY 仍为 28 字节。
     */
    uint64_t offset;             /* 文件数据在 PACK 中的 64 位绝对偏移。 */
    uint32_t length;             /* PACK 内实际存储长度。 */
    uint32_t original_length;    /* 解压后的原始长度。 */
    uint32_t is_compressed;      /* 非零表示数据使用 BPE 压缩。 */
    uint32_t is_obfuscated;      /* 0：无处理，1/2：两种混淆模式。 */
    uint32_t hash;               /* 存储数据（解密前）的完整性哈希。 */
} PACKENTRY;

/* BPE 压缩流头，位于每个压缩条目解密后的数据起始处。 */
typedef struct BPE_HEADER {
    unsigned char signature[4];  /* 固定签名 "1PC\xFF"。 */
    uint32_t flags;              /* bit 0 决定块长度使用 16 位或 32 位。 */
    uint32_t original_length;    /* 解压后应得到的字节数。 */
} BPE_HEADER;
#pragma pack(pop)

/* 编译期校验磁盘结构大小，防止编译选项或平台差异悄然破坏格式。 */
typedef char assert_packhead_size[(sizeof(PACKHEAD) == 28) ? 1 : -1];
typedef char assert_packkey_size[(sizeof(PACKKEY) == 1060) ? 1 : -1];
typedef char assert_packhash_size[(sizeof(PACKHASH) == 68) ? 1 : -1];
typedef char assert_packhash_safety_offset[
    (offsetof(PACKHASH, safety_data_size) == 36) ? 1 : -1];
typedef char assert_packhash_version_offset[
    (offsetof(PACKHASH, string_hash_version) == 40) ? 1 : -1];
typedef char assert_packhash_reserved_offset[
    (offsetof(PACKHASH, reserved) == 44) ? 1 : -1];
typedef char assert_packentry_size[(sizeof(PACKENTRY) == 28) ? 1 : -1];
typedef char assert_wchar_size[(sizeof(wchar_t) == 2) ? 1 : -1];

/* 可增量更新的原版哈希状态，使大文件无需一次性载入内存。 */
typedef struct HASH_CONTEXT {
    uint64_t value;              /* 当前四个 16 位通道组成的哈希状态。 */
    uint64_t counter;            /* 每处理一个 8 字节块都会更新的计数器。 */
    unsigned char tail[8];       /* 跨流式缓冲区保存的不完整数据块。 */
    size_t tail_length;          /* tail 中有效字节数。 */
} HASH_CONTEXT;

/* 文件数据混淆的流式状态；跨缓冲区保留反馈值和密钥位置。 */
typedef struct OBFUSCATION_CONTEXT {
    uint32_t mode;               /* 0、1、2 三种 PACK 存储模式。 */
    bool encrypting;             /* true 为加密，false 为解密。 */
    const uint32_t *file_key;    /* 由文件名、长度和归档密钥派生。 */
    const uint32_t *common_key;  /* 由特殊 key 文件派生，仅模式 2 使用。 */
    uint64_t feedback;           /* 上一数据块产生的链式反馈值。 */
    uint32_t key_position;       /* 当前密钥读取位置。 */
} OBFUSCATION_CONTEXT;

/* 构建文件名哈希区时使用的自动扩容字节数组。 */
typedef struct BYTE_BUFFER {
    unsigned char *data;
    size_t length;
    size_t capacity;
} BYTE_BUFFER;

/* 待打包文件的内存描述，不直接写入 PACK。 */
typedef struct FILE_ITEM {
    wchar_t *full_path;
    wchar_t *relative_path;
    uint64_t size;
    uint32_t name_hash;
} FILE_ITEM;

/* 递归枚举得到的文件列表。 */
typedef struct FILE_LIST {
    FILE_ITEM *items;
    size_t count;
    size_t capacity;
} FILE_LIST;

/* 条目解密读取器：从 PACK 分块读取并原地解除混淆。 */
typedef struct ENTRY_READER {
    FILE *file;
    uint64_t unread_file_bytes;
    unsigned char *buffer;
    size_t buffer_position;
    size_t buffer_length;
    OBFUSCATION_CONTEXT obfuscation;
} ENTRY_READER;

/* BPE 解压输出器：限制总输出长度并合并小字节写操作。 */
typedef struct OUTPUT_WRITER {
    FILE *file;
    unsigned char buffer[65536];
    size_t used;
    uint64_t total;
    uint64_t limit;
} OUTPUT_WRITER;

/* BPE 字典中的一个替换对；left 等于自身时代表字面量。 */
typedef struct BPE_PAIR {
    unsigned char left;
    unsigned char right;
} BPE_PAIR;

/* 通过 memcpy 读取未对齐的 64 位值，避免直接指针转换造成未定义行为。 */
static uint64_t load_u64(const void *source)
{
    uint64_t value;
    memcpy(&value, source, sizeof(value));
    return value;
}

/* 将 64 位值安全写回可能未对齐的字节地址。 */
static void store_u64(void *destination, uint64_t value)
{
    memcpy(destination, &value, sizeof(value));
}

/* 将一个 32 位数复制到 64 位值的高、低两个通道。 */
static uint64_t duplicate_u32(uint32_t value)
{
    return (uint64_t)value | ((uint64_t)value << 32);
}

/* 模拟旧版 MMX 的八个独立 8 位通道加法，通道之间不传递进位。 */
static uint64_t add_u8_lanes(uint64_t left, uint64_t right)
{
    uint64_t result = 0;
    unsigned int index;
    for (index = 0; index < 8; ++index) {
        uint8_t value = (uint8_t)((uint8_t)(left >> (index * 8)) +
                                  (uint8_t)(right >> (index * 8)));
        result |= (uint64_t)value << (index * 8);
    }
    return result;
}

/* 模拟旧版 MMX 的四个独立 16 位通道加法。 */
static uint64_t add_u16_lanes(uint64_t left, uint64_t right)
{
    uint64_t result = 0;
    unsigned int index;
    for (index = 0; index < 4; ++index) {
        uint16_t value = (uint16_t)((uint16_t)(left >> (index * 16)) +
                                    (uint16_t)(right >> (index * 16)));
        result |= (uint64_t)value << (index * 16);
    }
    return result;
}

/* 对 64 位值中的两个 32 位通道分别相加。 */
static uint64_t add_u32_lanes(uint64_t left, uint64_t right)
{
    uint32_t low = (uint32_t)left + (uint32_t)right;
    uint32_t high = (uint32_t)(left >> 32) + (uint32_t)(right >> 32);
    return (uint64_t)low | ((uint64_t)high << 32);
}

/* 对高、低两个 32 位通道分别左移。 */
static uint64_t shift_left_u32_lanes(uint64_t value, unsigned int count)
{
    uint32_t low = (uint32_t)value << count;
    uint32_t high = (uint32_t)(value >> 32) << count;
    return (uint64_t)low | ((uint64_t)high << 32);
}

/* 对高、低两个 32 位通道分别循环左移。 */
static uint64_t rotate_left_u32_lanes(uint64_t value, unsigned int count)
{
    uint32_t low = (uint32_t)value;
    uint32_t high = (uint32_t)(value >> 32);
    low = (low << count) | (low >> (32 - count));
    high = (high << count) | (high >> (32 - count));
    return (uint64_t)low | ((uint64_t)high << 32);
}

/* 根据本轮混合值和明文生成下一轮链式反馈。 */
static uint64_t feedback_value(uint64_t mixed, uint64_t plain)
{
    uint64_t byte_sum = add_u8_lanes(mixed, plain);
    uint64_t value = shift_left_u32_lanes(byte_sum ^ plain, 1);
    return add_u16_lanes(value, plain);
}

/* 初始化可流式计算的 PACK 哈希状态。 */
static void hash_init(HASH_CONTEXT *context)
{
    memset(context, 0, sizeof(*context));
}

/* 按原算法处理一个完整的 8 字节哈希块。 */
static void hash_process_block(HASH_CONTEXT *context, const unsigned char block[8])
{
    const uint64_t constant = duplicate_u32(0xA35793A7U);
    uint64_t mixed;
    context->counter = add_u16_lanes(context->counter, constant);
    mixed = add_u16_lanes(context->value, load_u64(block) ^ context->counter);
    context->value = rotate_left_u32_lanes(mixed, 3);
}

/* 向哈希状态追加任意长度数据，并保存末尾不足 8 字节的部分。 */
static void hash_update(HASH_CONTEXT *context, const unsigned char *data, size_t length)
{
    /* 先尝试用新输入补齐上一次调用留下的尾块。 */
    if (context->tail_length != 0) {
        size_t needed = 8 - context->tail_length;
        size_t copied = length < needed ? length : needed;
        memcpy(context->tail + context->tail_length, data, copied);
        context->tail_length += copied;
        data += copied;
        length -= copied;
        if (context->tail_length == 8) {
            hash_process_block(context, context->tail);
            context->tail_length = 0;
        }
    }

    /* 主体按 8 字节块处理，结果与旧版一次性计算完全相同。 */
    while (length >= 8) {
        hash_process_block(context, data);
        data += 8;
        length -= 8;
    }

    /* 最后不足 8 字节的数据不参与旧算法计算，留待下一次更新补齐。 */
    if (length != 0) {
        memcpy(context->tail, data, length);
        context->tail_length = length;
    }
}

/* 将四个 16 位哈希通道折叠成 PACKENTRY 使用的 32 位结果。 */
static uint32_t hash_finish(const HASH_CONTEXT *context)
{
    int16_t lane0 = (int16_t)(context->value & 0xFFFFU);
    int16_t lane1 = (int16_t)((context->value >> 16) & 0xFFFFU);
    int16_t lane2 = (int16_t)((context->value >> 32) & 0xFFFFU);
    int16_t lane3 = (int16_t)((context->value >> 48) & 0xFFFFU);
    uint32_t result = (uint32_t)((int32_t)lane0 * (int32_t)lane2);
    result += (uint32_t)((int32_t)lane1 * (int32_t)lane3);
    return result;
}

/* 计算一段内存的原版 PACK 哈希。 */
static uint32_t hash_memory(const unsigned char *data, size_t length)
{
    HASH_CONTEXT context;
    hash_init(&context);
    hash_update(&context, data, length);
    return hash_finish(&context);
}

/*
 * 对密钥块或哈希区执行可逆的 8 字节链式异或。
 * 解密时反馈使用恢复出的明文，因此同一函数可同时兼容两个方向。
 */
static void chain_crypt(uint32_t key, unsigned char *data, size_t length, bool encrypting)
{
    uint64_t state = duplicate_u32((key + (uint32_t)length) ^ 0xFEC9753EU);
    uint64_t accumulator = duplicate_u32(0xA73C5F9DU);
    const uint64_t increment = duplicate_u32(0xCE24F523U);
    size_t offset;

    for (offset = 0; offset + 8 <= length; offset += 8) {
        uint64_t original = load_u64(data + offset);
        uint64_t output;
        accumulator = add_u32_lanes(accumulator, increment) ^ state;
        output = original ^ accumulator;
        store_u64(data + offset, output);
        state = encrypting ? original : output;
    }
}

/* 使用归档密钥对 UTF-16 文件名逐字符异或；再次执行即可恢复原名。 */
static void name_crypt(uint32_t key, wchar_t *name, uint32_t length)
{
    uint32_t state;
    uint32_t index;
    key ^= (key >> 16) & 0xFFFFU;
    key = (key ^ (length ^ 0x3E13U) ^ (length * length)) & 0xFFFFU;
    state = key;
    for (index = 0; index < length; ++index) {
        state = (index + (state << 3) + key) & 0xFFFFU;
        name[index] = (wchar_t)((uint16_t)name[index] ^ (uint16_t)state);
    }
}

/* 根据模式 1 的种子生成伪随机文件密钥序列。 */
static void create_key1_seed(uint32_t *output, uint32_t count, uint32_t seed)
{
    uint32_t index;
    for (index = 0; index < count; ++index) {
        uint32_t value = seed ^ 0x8DF21431U;
        seed = (uint32_t)(((uint64_t)2381452337U * value) >> 32) + 2381452337U * value;
        output[index] = seed;
    }
}

/* 根据模式 2 的种子生成伪随机文件密钥序列。 */
static void create_key2_seed(uint32_t *output, uint32_t count, uint32_t seed)
{
    uint32_t index;
    for (index = 0; index < count; ++index) {
        uint32_t value = seed ^ 0x8A77F473U;
        seed = (uint32_t)(((uint64_t)2323117171U * value) >> 32) + 2323117171U * value;
        output[index] = seed;
    }
}

/* 用文件名、数据长度和归档密钥派生模式 1 的文件密钥。 */
static void create_file_key1(uint32_t *output, uint32_t count, const wchar_t *name,
                             uint32_t name_length, uint32_t data_length, uint32_t key)
{
    uint32_t first = 8779058U;
    uint32_t second = 3405377U;
    uint32_t index;
    uint32_t seed;
    for (index = 0; index < name_length; ++index) {
        first += (uint32_t)(uint16_t)name[index] << (index & 7U);
        second ^= first;
    }
    seed = (key ^ (7U * (data_length & 0xFFFFFFU) + data_length + first +
                   (first ^ data_length ^ 0x8F32DCU))) + second;
    create_key1_seed(output, count, 9U * (seed & 0xFFFFFFU));
}

/* 用文件名、数据长度和归档密钥派生模式 2 的文件密钥。 */
static void create_file_key2(uint32_t *output, uint32_t count, const wchar_t *name,
                             uint32_t name_length, uint32_t data_length, uint32_t key)
{
    uint32_t first = 8845282U;
    uint32_t second = 4470769U;
    uint32_t index;
    uint32_t seed;
    for (index = 0; index < name_length; ++index) {
        first += (uint32_t)(uint16_t)name[index] << (index & 7U);
        second ^= first;
    }
    seed = second + (key ^ (13U * (data_length & 0xFFFFFFU) + data_length + first +
                            (first ^ data_length ^ 0x56E213U)));
    create_key2_seed(output, count, 13U * (seed & 0xFFFFFFU));
}

/* 初始化单个文件条目的流式混淆状态。 */
static void obfuscation_init(OBFUSCATION_CONTEXT *context, uint32_t mode, bool encrypting,
                             const uint32_t *file_key, const uint32_t *common_key)
{
    memset(context, 0, sizeof(*context));
    context->mode = mode;
    context->encrypting = encrypting;
    context->file_key = file_key;
    context->common_key = common_key;
    if (mode == 1) {
        context->key_position = 8U * (file_key[13] & 0xFU);
        context->feedback = load_u64((const unsigned char *)file_key + 24);
    }
    else if (mode == 2) {
        context->key_position = 8U * (file_key[8] & 0xDU);
        context->feedback = load_u64((const unsigned char *)file_key + 24);
    }
}

/*
 * 原地加密或解密一块文件数据。
 * 调用方使用 8 字节对齐大小的中间缓冲区，使反馈状态可以跨块连续运行。
 */
static void obfuscation_process(OBFUSCATION_CONTEXT *context, unsigned char *data, size_t length)
{
    size_t offset;
    if (context->mode == 0) {
        return;
    }

    for (offset = 0; offset + 8 <= length; offset += 8) {
        uint64_t original = load_u64(data + offset);
        uint64_t key_value;
        uint64_t mixed;
        uint64_t output;
        uint64_t plain;

        /* 模式 1 仅使用文件密钥；模式 2 还会与公共密钥组合。 */
        if (context->mode == 1) {
            key_value = load_u64((const unsigned char *)context->file_key + context->key_position);
            mixed = add_u32_lanes(context->feedback ^ key_value, key_value);
            context->key_position = (context->key_position + 8U) & 0x7FU;
        }
        else {
            uint32_t position = context->key_position;
            uint64_t first = load_u64((const unsigned char *)context->file_key + 8U * (position & 0xFU));
            uint64_t second = load_u64((const unsigned char *)context->common_key + 8U * (position & 0x7FU));
            key_value = first ^ second;
            mixed = add_u32_lanes(context->feedback ^ key_value, key_value);
            context->key_position = (position + 1U) & 0x7FU;
        }

        /* 加解密都是异或；反馈必须始终基于明文，两个方向取值不同。 */
        output = original ^ mixed;
        store_u64(data + offset, output);
        plain = context->encrypting ? original : output;
        context->feedback = feedback_value(mixed, plain);
    }
}

/* 计算文件名在 PACK 哈希表中的 30 位散列值。 */
static uint32_t filename_hash(const wchar_t *name, uint32_t length)
{
    uint32_t result = 0;
    uint32_t index;
    for (index = 1; index <= length; ++index) {
        result = (((uint32_t)(uint16_t)name[index - 1] << (index & 7U)) + result) & 0x3FFFFFFFU;
    }
    return result;
}

/* 将文件名哈希映射到格式固定的 256 个桶之一。 */
static uint32_t hash_bucket(uint32_t hash)
{
    uint32_t value = (uint16_t)hash + (hash >> 8) + (hash >> 16);
    return value % 256U;
}

/* 使用 Windows CRT 的 64 位接口跳转到绝对文件偏移。 */
static bool seek_absolute(FILE *file, uint64_t offset)
{
    if (offset > INT64_MAX) {
        return false;
    }
    return _fseeki64(file, (int64_t)offset, SEEK_SET) == 0;
}

/* 读取当前 64 位文件位置，避免 x86 下 long 在 2 GiB 处溢出。 */
static bool tell_position(FILE *file, uint64_t *position)
{
    int64_t value = _ftelli64(file);
    if (value < 0) {
        return false;
    }
    *position = (uint64_t)value;
    return true;
}

/* 获取完整 64 位文件长度，并将文件指针恢复到起始位置。 */
static bool file_size(FILE *file, uint64_t *size)
{
    int64_t value;
    if (_fseeki64(file, 0, SEEK_END) != 0) {
        return false;
    }
    value = _ftelli64(file);
    if (value < 0 || _fseeki64(file, 0, SEEK_SET) != 0) {
        return false;
    }
    *size = (uint64_t)value;
    return true;
}

/* 精确读取指定字节数；短读、到达文件尾或 I/O 错误都视为失败。 */
static bool read_exact(FILE *file, void *data, size_t length)
{
    return length == 0 || fread(data, 1, length, file) == length;
}

/* 精确写入指定字节数，避免调用方忽略磁盘写满等短写错误。 */
static bool write_exact(FILE *file, const void *data, size_t length)
{
    return length == 0 || fwrite(data, 1, length, file) == length;
}

/* 分配并复制一个以 NUL 结尾的宽字符串。 */
static wchar_t *duplicate_wide(const wchar_t *value)
{
    size_t length = wcslen(value);
    wchar_t *copy;
    if (length > (SIZE_MAX / sizeof(wchar_t)) - 1) {
        return NULL;
    }
    copy = (wchar_t *)malloc((length + 1) * sizeof(*copy));
    if (copy != NULL) {
        memcpy(copy, value, (length + 1) * sizeof(wchar_t));
    }
    return copy;
}

/* 拼接两个 Windows 路径，并按需补入目录分隔符。 */
static wchar_t *join_path(const wchar_t *left, const wchar_t *right)
{
    size_t left_length = wcslen(left);
    size_t right_length = wcslen(right);
    bool needs_separator = left_length != 0 && left[left_length - 1] != L'\\' && left[left_length - 1] != L'/';
    wchar_t *result;
    size_t total;
    if (left_length > SIZE_MAX - right_length - 2) {
        return NULL;
    }
    total = left_length + right_length + (needs_separator ? 1 : 0);
    result = (wchar_t *)malloc((total + 1) * sizeof(*result));
    if (result == NULL) {
        return NULL;
    }
    memcpy(result, left, left_length * sizeof(wchar_t));
    if (needs_separator) {
        result[left_length++] = L'\\';
    }
    memcpy(result + left_length, right, (right_length + 1) * sizeof(wchar_t));
    return result;
}

/* 将相对路径规范化为动态分配的绝对路径。 */
static wchar_t *full_path(const wchar_t *path)
{
    DWORD needed = GetFullPathNameW(path, 0, NULL, NULL);
    wchar_t *result;
    if (needed == 0) {
        return NULL;
    }
    result = (wchar_t *)malloc(((size_t)needed + 1) * sizeof(*result));
    if (result == NULL) {
        return NULL;
    }
    if (GetFullPathNameW(path, needed + 1, result, NULL) == 0) {
        free(result);
        return NULL;
    }
    return result;
}

/* 确保文件列表至少可容纳 needed 个元素，并检查容量计算溢出。 */
static bool list_reserve(FILE_LIST *list, size_t needed)
{
    FILE_ITEM *items;
    size_t capacity;
    if (needed <= list->capacity) {
        return true;
    }
    capacity = list->capacity == 0 ? 64 : list->capacity;
    while (capacity < needed) {
        if (capacity > SIZE_MAX / 2) {
            return false;
        }
        capacity *= 2;
    }
    if (capacity > SIZE_MAX / sizeof(FILE_ITEM)) {
        return false;
    }
    items = (FILE_ITEM *)realloc(list->items, capacity * sizeof(*items));
    if (items == NULL) {
        return false;
    }
    list->items = items;
    list->capacity = capacity;
    return true;
}

/* 将已取得所有权的完整路径和相对路径加入文件列表。 */
static bool list_add(FILE_LIST *list, wchar_t *full, wchar_t *relative)
{
    if (!list_reserve(list, list->count + 1)) {
        return false;
    }
    list->items[list->count].full_path = full;
    list->items[list->count].relative_path = relative;
    list->items[list->count].size = 0;
    list->items[list->count].name_hash = 0;
    ++list->count;
    return true;
}

/* 释放文件列表及其中每个路径字符串。 */
static void list_free(FILE_LIST *list)
{
    size_t index;
    for (index = 0; index < list->count; ++index) {
        free(list->items[index].full_path);
        free(list->items[index].relative_path);
    }
    free(list->items);
    memset(list, 0, sizeof(*list));
}

/*
 * 递归枚举输入目录中的普通文件。
 * 跳过目录重解析点，防止符号链接或联接导致循环及越界枚举。
 */
static bool enumerate_tree(const wchar_t *root, const wchar_t *relative_directory, FILE_LIST *list)
{
    wchar_t *directory = relative_directory[0] == 0 ? duplicate_wide(root) : join_path(root, relative_directory);
    wchar_t *pattern;
    WIN32_FIND_DATAW data;
    HANDLE handle;
    bool result = true;

    if (directory == NULL) {
        return false;
    }
    pattern = join_path(directory, L"*");
    if (pattern == NULL) {
        free(directory);
        return false;
    }

    handle = FindFirstFileW(pattern, &data);
    free(pattern);
    if (handle == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        free(directory);
        return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
    }

    do {
        wchar_t *relative;
        wchar_t *full;
        if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0) {
            continue;
        }
        relative = relative_directory[0] == 0 ? duplicate_wide(data.cFileName) :
                                                join_path(relative_directory, data.cFileName);
        full = join_path(root, relative != NULL ? relative : L"");
        if (relative == NULL || full == NULL) {
            free(relative);
            free(full);
            result = false;
            break;
        }

        /* 目录递归时拒绝重解析点；普通文件则把路径所有权交给列表。 */
        if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            if ((data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0) {
                result = enumerate_tree(root, relative, list);
            }
            free(relative);
            free(full);
            if (!result) {
                break;
            }
        }
        else {
            if (!list_add(list, full, relative)) {
                free(relative);
                free(full);
                result = false;
                break;
            }
        }
    } while (FindNextFileW(handle, &data));

    if (GetLastError() != ERROR_NO_MORE_FILES) {
        result = false;
    }
    FindClose(handle);
    free(directory);
    return result;
}

/* 为哈希区动态缓冲区扩容，并保证其长度可由格式中的 uint32_t 表示。 */
static bool buffer_reserve(BYTE_BUFFER *buffer, size_t additional)
{
    unsigned char *data;
    size_t needed;
    size_t capacity;
    if (additional > SIZE_MAX - buffer->length) {
        return false;
    }
    needed = buffer->length + additional;
    if (needed > UINT32_MAX) {
        return false;
    }
    if (needed <= buffer->capacity) {
        return true;
    }
    capacity = buffer->capacity == 0 ? 4096 : buffer->capacity;
    while (capacity < needed) {
        if (capacity > UINT32_MAX / 2U) {
            capacity = UINT32_MAX;
            break;
        }
        capacity *= 2;
    }
    data = (unsigned char *)realloc(buffer->data, capacity);
    if (data == NULL) {
        return false;
    }
    buffer->data = data;
    buffer->capacity = capacity;
    return true;
}

/* 向动态缓冲区尾部追加原始字节。 */
static bool buffer_append(BYTE_BUFFER *buffer, const void *data, size_t length)
{
    if (!buffer_reserve(buffer, length)) {
        return false;
    }
    memcpy(buffer->data + buffer->length, data, length);
    buffer->length += length;
    return true;
}

/* 按本机 Windows 小端序追加一个 16 位磁盘字段。 */
static bool buffer_append_u16(BYTE_BUFFER *buffer, uint16_t value)
{
    return buffer_append(buffer, &value, sizeof(value));
}

/* 按本机 Windows 小端序追加一个 32 位磁盘字段。 */
static bool buffer_append_u32(BYTE_BUFFER *buffer, uint32_t value)
{
    return buffer_append(buffer, &value, sizeof(value));
}

/* 按本机 Windows 小端序追加一个 64 位磁盘字段。 */
static bool buffer_append_u64(BYTE_BUFFER *buffer, uint64_t value)
{
    return buffer_append(buffer, &value, sizeof(value));
}

/*
 * 构建与原版 HashVer1.4 相同的文件名哈希数据。
 * 数据布局依次为 256 个桶的链表记录，以及按条目顺序排列的索引数组。
 */
static bool build_hash_data(FILE_LIST *list, BYTE_BUFFER *buffer)
{
    uint32_t heads[256];
    uint32_t tails[256];
    uint32_t depths[256];
    uint32_t *next;
    size_t index;
    uint32_t bucket;

    if (list->count > UINT32_MAX || list->count > SIZE_MAX / sizeof(uint32_t)) {
        return false;
    }
    next = (uint32_t *)malloc(list->count * sizeof(*next));
    if (next == NULL) {
        return false;
    }
    for (bucket = 0; bucket < 256; ++bucket) {
        heads[bucket] = tails[bucket] = INVALID_INDEX;
        depths[bucket] = 0;
    }

    /* 第一遍计算文件名哈希，并用数组下标串成每个桶的单向链表。 */
    for (index = 0; index < list->count; ++index) {
        uint32_t item = (uint32_t)index;
        uint32_t length = (uint32_t)wcslen(list->items[index].relative_path);
        list->items[index].name_hash = filename_hash(list->items[index].relative_path, length);
        bucket = hash_bucket(list->items[index].name_hash);
        next[item] = INVALID_INDEX;
        if (tails[bucket] == INVALID_INDEX) {
            heads[bucket] = item;
        }
        else {
            next[tails[bucket]] = item;
        }
        tails[bucket] = item;
        ++depths[bucket];
    }

    /* 第二遍按桶写入名称、条目索引偏移和名称哈希。 */
    for (bucket = 0; bucket < 256; ++bucket) {
        uint32_t item;
        if (!buffer_append_u32(buffer, depths[bucket])) {
            free(next);
            return false;
        }
        for (item = heads[bucket]; item != INVALID_INDEX; item = next[item]) {
            size_t name_length = wcslen(list->items[item].relative_path);
            uint64_t index_offset = (uint64_t)item * sizeof(uint32_t);
            if (name_length > UINT16_MAX ||
                !buffer_append_u16(buffer, (uint16_t)name_length) ||
                !buffer_append(buffer, list->items[item].relative_path, name_length * sizeof(wchar_t)) ||
                !buffer_append_u64(buffer, index_offset) ||
                !buffer_append_u32(buffer, list->items[item].name_hash)) {
                free(next);
                return false;
            }
        }
    }

    /* 哈希记录之后是文件条目索引数组。 */
    for (index = 0; index < list->count; ++index) {
        if (!buffer_append_u32(buffer, (uint32_t)index)) {
            free(next);
            return false;
        }
    }
    free(next);
    return true;
}

/*
 * 从特殊 key 文件随机访问 1024 个字节，派生模式 2 使用的公共密钥。
 * 只读取必要位置，不会因 key 文件很大而申请等量内存。
 */
static bool derive_common_key(FILE *file, uint32_t length, uint32_t output[256])
{
    unsigned char first_byte;
    unsigned char second_byte;
    unsigned char *key_bytes = (unsigned char *)output;
    uint32_t position;
    uint32_t step;
    uint32_t index;

    if (length < 80 || !seek_absolute(file, 49) || !read_exact(file, &first_byte, 1) ||
        !seek_absolute(file, 79) || !read_exact(file, &second_byte, 1)) {
        return false;
    }
    /* 先生成固定初始表，再由 key 文件内容逐字节扰动。 */
    for (index = 0; index < 256; ++index) {
        output[index] = index % 3U ? (index + 7U) * (uint32_t)(-(int32_t)(index + 3U)) :
                                    (index + 7U) * (index + 3U);
    }
    position = first_byte % 0x49U + 128U;
    step = second_byte % 7U + 7U;
    for (index = 0; index < 1024; ++index) {
        unsigned char value;
        position = (position + step) % length;
        if (!seek_absolute(file, position) || !read_exact(file, &value, 1)) {
            return false;
        }
        key_bytes[index] ^= value;
    }
    return true;
}

/* 以固定大小缓冲区计算 PACK 中一段文件区域的完整性哈希。 */
static bool hash_file_region(FILE *file, uint64_t offset, uint32_t length, uint32_t *result)
{
    unsigned char *buffer = (unsigned char *)malloc(IO_BUFFER_SIZE * sizeof(*buffer));
    uint64_t remaining = length;
    HASH_CONTEXT hash;
    if (buffer == NULL || !seek_absolute(file, offset)) {
        free(buffer);
        return false;
    }
    hash_init(&hash);
    while (remaining != 0) {
        size_t amount = remaining > IO_BUFFER_SIZE ? IO_BUFFER_SIZE : (size_t)remaining;
        if (!read_exact(file, buffer, amount)) {
            free(buffer);
            return false;
        }
        hash_update(&hash, buffer, amount);
        remaining -= amount;
    }
    *result = hash_finish(&hash);
    free(buffer);
    return true;
}

/*
 * 分块读取源文件、执行混淆、计算存储态哈希并写入 PACK。
 * 常驻内存约为 IO_BUFFER_SIZE，与文件实际大小无关。
 */
static bool stream_pack_file(FILE *output, FILE *input, uint32_t length,
                             OBFUSCATION_CONTEXT *obfuscation, uint32_t *hash_value)
{
    unsigned char *buffer = (unsigned char *)malloc(IO_BUFFER_SIZE * sizeof(*buffer));
    uint64_t remaining = length;
    HASH_CONTEXT hash;
    if (buffer == NULL || !seek_absolute(input, 0)) {
        free(buffer);
        return false;
    }
    hash_init(&hash);
    while (remaining != 0) {
        size_t amount = remaining > IO_BUFFER_SIZE ? IO_BUFFER_SIZE : (size_t)remaining;
        if (!read_exact(input, buffer, amount)) {
            free(buffer);
            return false;
        }
        /* PACKENTRY.hash 校验的是混淆后的存储数据，因此先混淆再计算哈希。 */
        obfuscation_process(obfuscation, buffer, amount);
        hash_update(&hash, buffer, amount);
        if (!write_exact(output, buffer, amount)) {
            free(buffer);
            return false;
        }
        remaining -= amount;
    }
    *hash_value = hash_finish(&hash);
    free(buffer);
    return true;
}

/* 逐级创建目录，并拒绝现有的非目录对象以及目录重解析点。 */
static bool ensure_directory_tree(const wchar_t *directory)
{
    wchar_t *copy = duplicate_wide(directory);
    size_t length;
    size_t index;
    size_t start = 0;
    bool result = true;
    if (copy == NULL) {
        return false;
    }
    length = wcslen(copy);
    while (length > 0 && (copy[length - 1] == L'\\' || copy[length - 1] == L'/')) {
        copy[--length] = 0;
    }
    if (length >= 3 && copy[1] == L':' && (copy[2] == L'\\' || copy[2] == L'/')) {
        start = 3;
    }
    else if (length >= 2 && copy[0] == L'\\' && copy[1] == L'\\') {
        wchar_t *server_end = wcschr(copy + 2, L'\\');
        wchar_t *share_end = server_end != NULL ? wcschr(server_end + 1, L'\\') : NULL;
        start = share_end != NULL ? (size_t)(share_end - copy + 1) : length;
    }

    for (index = start; index <= length; ++index) {
        if (index == length || copy[index] == L'\\' || copy[index] == L'/') {
            wchar_t saved = copy[index];
            DWORD attributes;
            copy[index] = 0;
            attributes = GetFileAttributesW(copy);
            if (attributes == INVALID_FILE_ATTRIBUTES) {
                if (!CreateDirectoryW(copy, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
                    result = false;
                }
            }
            else if ((attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
                     (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
                result = false;
            }
            copy[index] = saved;
            if (!result) {
                break;
            }
        }
    }
    free(copy);
    return result;
}

/* 从文件完整路径中截取父目录并确保其安全存在。 */
static bool ensure_parent_directory(const wchar_t *file_path)
{
    wchar_t *copy = duplicate_wide(file_path);
    wchar_t *separator;
    bool result;
    if (copy == NULL) {
        return false;
    }
    separator = wcsrchr(copy, L'\\');
    if (separator == NULL) {
        separator = wcsrchr(copy, L'/');
    }
    if (separator == NULL) {
        free(copy);
        return true;
    }
    *separator = 0;
    result = ensure_directory_tree(copy);
    free(copy);
    return result;
}

/* 检查单个路径段是否为 Windows 保留设备名或包含非法字符。 */
static bool segment_is_reserved(const wchar_t *segment, size_t length)
{
    wchar_t base[8];
    size_t base_length = 0;
    size_t index;
    while (base_length < length && segment[base_length] != L'.' && base_length < 7) {
        base[base_length] = towupper(segment[base_length]);
        ++base_length;
    }
    base[base_length] = 0;
    if (wcscmp(base, L"CON") == 0 || wcscmp(base, L"PRN") == 0 ||
        wcscmp(base, L"AUX") == 0 || wcscmp(base, L"NUL") == 0) {
        return true;
    }
    if (base_length == 4 && ((wcsncmp(base, L"COM", 3) == 0) ||
                             (wcsncmp(base, L"LPT", 3) == 0)) &&
        base[3] >= L'1' && base[3] <= L'9') {
        return true;
    }
    for (index = 0; index < length; ++index) {
        wchar_t value = segment[index];
        if (value < 32 || value == L':' || value == L'<' || value == L'>' ||
            value == L'"' || value == L'|' || value == L'?' || value == L'*') {
            return true;
        }
    }
    return length == 0 || segment[length - 1] == L'.' || segment[length - 1] == L' ';
}

/*
 * 验证归档内文件名只能是安全相对路径。
 * 拒绝绝对路径、盘符、空段、点目录、父目录跳转和设备名。
 */
static bool validate_relative_path(const wchar_t *path)
{
    const wchar_t *segment = path;
    const wchar_t *cursor = path;
    if (path[0] == 0 || path[0] == L'\\' || path[0] == L'/' ||
        (iswalpha(path[0]) && path[1] == L':')) {
        return false;
    }
    for (;;) {
        if (*cursor == L'\\' || *cursor == L'/' || *cursor == 0) {
            size_t length = (size_t)(cursor - segment);
            if ((length == 1 && segment[0] == L'.') ||
                (length == 2 && segment[0] == L'.' && segment[1] == L'.') ||
                segment_is_reserved(segment, length)) {
                return false;
            }
            if (*cursor == 0) {
                return true;
            }
            segment = cursor + 1;
        }
        ++cursor;
    }
}

/*
 * 将已验证的归档相对路径拼到输出根目录，并再次做绝对路径前缀检查。
 * 双重检查确保恶意条目不能逃逸到用户指定目录之外。
 */
static wchar_t *safe_output_path(const wchar_t *root, const wchar_t *relative)
{
    wchar_t *normalized;
    wchar_t *joined;
    wchar_t *absolute;
    size_t index;
    size_t root_length;
    if (!validate_relative_path(relative)) {
        return NULL;
    }
    normalized = duplicate_wide(relative);
    if (normalized == NULL) {
        return NULL;
    }
    for (index = 0; normalized[index] != 0; ++index) {
        if (normalized[index] == L'/') {
            normalized[index] = L'\\';
        }
    }
    joined = join_path(root, normalized);
    free(normalized);
    if (joined == NULL) {
        return NULL;
    }
    absolute = full_path(joined);
    free(joined);
    if (absolute == NULL) {
        return NULL;
    }
    root_length = wcslen(root);
    while (root_length > 0 && (root[root_length - 1] == L'\\' || root[root_length - 1] == L'/')) {
        --root_length;
    }
    if (_wcsnicmp(root, absolute, root_length) != 0 || absolute[root_length] != L'\\') {
        free(absolute);
        return NULL;
    }
    return absolute;
}

/* 为输出文件生成同目录下尚不存在的临时文件名。 */
static wchar_t *make_temporary_path(const wchar_t *final_path)
{
    DWORD process_id = GetCurrentProcessId();
    unsigned int attempt;
    size_t length = wcslen(final_path);
    for (attempt = 0; attempt < 1000; ++attempt) {
        wchar_t suffix[64];
        wchar_t *result;
        int suffix_length = swprintf(suffix, 64, L".filepack31.%lu.%u.tmp",
                                     (unsigned long)process_id, attempt);
        if (suffix_length <= 0 || length > SIZE_MAX - (size_t)suffix_length - 1) {
            return NULL;
        }
        result = (wchar_t *)malloc((length + (size_t)suffix_length + 1) * sizeof(*result));
        if (result == NULL) {
            return NULL;
        }
        memcpy(result, final_path, length * sizeof(wchar_t));
        memcpy(result + length, suffix, ((size_t)suffix_length + 1) * sizeof(wchar_t));
        if (GetFileAttributesW(result) == INVALID_FILE_ATTRIBUTES) {
            return result;
        }
        free(result);
    }
    return NULL;
}

/* 定位到条目数据并初始化带解密功能的流式读取器。 */
static bool reader_init(ENTRY_READER *reader, FILE *file, uint64_t offset, uint32_t length,
                        uint32_t mode, const uint32_t *file_key, const uint32_t *common_key)
{
    memset(reader, 0, sizeof(*reader));
    reader->buffer = (unsigned char *)malloc(IO_BUFFER_SIZE * sizeof(*reader->buffer));
    if (reader->buffer == NULL || !seek_absolute(file, offset)) {
        free(reader->buffer);
        reader->buffer = NULL;
        return false;
    }
    reader->file = file;
    reader->unread_file_bytes = length;
    obfuscation_init(&reader->obfuscation, mode, false, file_key, common_key);
    return true;
}

/* 释放条目读取缓冲区，并清空状态以便安全重复调用。 */
static void reader_close(ENTRY_READER *reader)
{
    free(reader->buffer);
    memset(reader, 0, sizeof(*reader));
}

/* 返回读取器中尚未交付给解码器的总字节数。 */
static uint64_t reader_available(const ENTRY_READER *reader)
{
    return reader->unread_file_bytes + (uint64_t)(reader->buffer_length - reader->buffer_position);
}

/* 从 PACK 读取下一块数据，并在缓冲区中原地解密。 */
static bool reader_fill(ENTRY_READER *reader)
{
    size_t amount;
    if (reader->unread_file_bytes == 0) {
        return false;
    }
    amount = reader->unread_file_bytes > IO_BUFFER_SIZE ? IO_BUFFER_SIZE :
                                                            (size_t)reader->unread_file_bytes;
    if (!read_exact(reader->file, reader->buffer, amount)) {
        return false;
    }
    obfuscation_process(&reader->obfuscation, reader->buffer, amount);
    reader->unread_file_bytes -= amount;
    reader->buffer_position = 0;
    reader->buffer_length = amount;
    return true;
}

/* 跨内部缓冲区边界精确读取指定字节数。 */
static bool reader_read(ENTRY_READER *reader, void *destination, size_t length)
{
    unsigned char *output = (unsigned char *)destination;
    while (length != 0) {
        size_t available;
        size_t copied;
        if (reader->buffer_position == reader->buffer_length && !reader_fill(reader)) {
            return false;
        }
        available = reader->buffer_length - reader->buffer_position;
        copied = length < available ? length : available;
        memcpy(output, reader->buffer + reader->buffer_position, copied);
        reader->buffer_position += copied;
        output += copied;
        length -= copied;
    }
    return true;
}

/* 从条目流读取一个 8 位值。 */
static bool reader_u8(ENTRY_READER *reader, uint8_t *value)
{
    return reader_read(reader, value, sizeof(*value));
}

/* 从条目流读取一个 16 位小端值。 */
static bool reader_u16(ENTRY_READER *reader, uint16_t *value)
{
    return reader_read(reader, value, sizeof(*value));
}

/* 从条目流读取一个 32 位小端值。 */
static bool reader_u32(ENTRY_READER *reader, uint32_t *value)
{
    return reader_read(reader, value, sizeof(*value));
}

/* 将 BPE 输出缓冲区的有效内容一次性写入目标文件。 */
static bool writer_flush(OUTPUT_WRITER *writer)
{
    if (writer->used != 0 && !write_exact(writer->file, writer->buffer, writer->used)) {
        return false;
    }
    writer->used = 0;
    return true;
}

/* 输出一个解压字节，同时强制执行声明的原始长度上限。 */
static bool writer_byte(OUTPUT_WRITER *writer, unsigned char value)
{
    if (writer->total >= writer->limit) {
        return false;
    }
    writer->buffer[writer->used++] = value;
    ++writer->total;
    return writer->used != sizeof(writer->buffer) || writer_flush(writer);
}

/*
 * 流式解码 FilePack 使用的 BPE 数据。
 * 对输入长度、输出长度和替换栈深度均设置硬边界，避免损坏归档造成越界。
 */
static bool bpe_decompress(ENTRY_READER *reader, FILE *output, uint32_t expected_length)
{
    BPE_HEADER header;
    BPE_PAIR table[256];
    unsigned char stack[BPE_STACK_SIZE];
    OUTPUT_WRITER writer;
    memset(&writer, 0, sizeof(writer));
    writer.file = output;
    writer.limit = expected_length;

    if (!reader_read(reader, &header, sizeof(header)) ||
        memcmp(header.signature, "1PC\xFF", 4) != 0 ||
        header.original_length != expected_length) {
        return false;
    }

    /* 一个压缩条目可以包含多个“字典 + 数据块”组合。 */
    while (reader_available(reader) != 0) {
        uint32_t table_index = 0;
        uint32_t block_length;
        size_t stack_length = 0;

        /* 重建本数据块使用的 256 项 BPE 替换表。 */
        while (table_index < 256) {
            uint8_t count;
            uint32_t literal_count;
            uint32_t pair_count;
            if (!reader_u8(reader, &count)) {
                return false;
            }
            literal_count = count > 127 ? (uint32_t)count - 127U : 0U;
            pair_count = count > 127 ? 1U : (uint32_t)count + 1U;
            if (literal_count > 256U - table_index) {
                return false;
            }
            while (literal_count-- != 0) {
                table[table_index].left = (unsigned char)table_index;
                table[table_index].right = 0;
                ++table_index;
            }

            for (; pair_count != 0 && table_index < 256;
                 --pair_count, ++table_index) {
                if (!reader_u8(reader, &table[table_index].left)) {
                    return false;
                }
                if (table_index != table[table_index].left) {
                    if (!reader_u8(reader, &table[table_index].right)) {
                        return false;
                    }
                }
                else {
                    table[table_index].right = 0;
                }
            }
        }

        /* flags bit 0 指定压缩块长度字段的宽度。 */
        if ((header.flags & 1U) != 0) {
            uint16_t short_length;
            if (!reader_u16(reader, &short_length)) {
                return false;
            }
            block_length = short_length;
        }
        else if (!reader_u32(reader, &block_length)) {
            return false;
        }
        if ((uint64_t)block_length > reader_available(reader)) {
            return false;
        }

        /*
         * 字面量直接输出；替换项按“右后入、左先出”压栈，
         * 从而保持递归展开顺序，同时避免真正的函数递归。
         */
        while (block_length != 0 || stack_length != 0) {
            unsigned char value;
            if (stack_length != 0) {
                value = stack[--stack_length];
            }
            else {
                if (!reader_u8(reader, &value)) {
                    return false;
                }
                --block_length;
            }

            if (value == table[value].left) {
                if (!writer_byte(&writer, value)) {
                    return false;
                }
            }
            else {
                if (stack_length > BPE_STACK_SIZE - 2) {
                    return false;
                }
                stack[stack_length++] = table[value].right;
                stack[stack_length++] = table[value].left;
            }
        }
    }
    return writer.total == expected_length && writer_flush(&writer);
}

/* 将未压缩条目从解密读取器直接流式复制到输出文件。 */
static bool copy_entry(ENTRY_READER *reader, FILE *output, uint32_t expected_length)
{
    unsigned char *buffer = (unsigned char *)malloc(IO_BUFFER_SIZE * sizeof(*buffer));
    uint64_t remaining = expected_length;
    if (buffer == NULL || reader_available(reader) != expected_length) {
        free(buffer);
        return false;
    }
    while (remaining != 0) {
        size_t amount = remaining > IO_BUFFER_SIZE ? IO_BUFFER_SIZE : (size_t)remaining;
        if (!reader_read(reader, buffer, amount) || !write_exact(output, buffer, amount)) {
            free(buffer);
            return false;
        }
        remaining -= amount;
    }
    free(buffer);
    return reader_available(reader) == 0;
}

/*
 * 校验、解密并提取单个条目。
 * 数据先写入同目录临时文件，全部成功后再原子替换最终路径。
 */
static bool extract_entry(FILE *archive, const wchar_t *root, const wchar_t *name,
                          const PACKENTRY *entry, uint32_t archive_key,
                          uint32_t common_key[256], bool *common_key_ready)
{
    wchar_t *final_path = NULL;
    wchar_t *temporary_path = NULL;
    FILE *output = NULL;
    ENTRY_READER reader;
    uint32_t file_key[64];
    uint32_t calculated_hash;
    uint32_t name_length = (uint32_t)wcslen(name);
    bool result = false;

    memset(&reader, 0, sizeof(reader));
    /* 解密之前先校验 PACK 中的原始存储数据，尽早发现损坏。 */
    if (!hash_file_region(archive, entry->offset, entry->length, &calculated_hash) ||
        calculated_hash != entry->hash) {
        fwprintf(stderr, L"Hash mismatch: %ls\n", name);
        return false;
    }
    if (entry->is_obfuscated > 2) {
        fwprintf(stderr, L"Unsupported obfuscation mode: %ls\n", name);
        return false;
    }
    /* 根据条目模式派生对应文件密钥；模式 2 必须已经处理过 key 文件。 */
    if (entry->is_obfuscated == 1) {
        create_file_key1(file_key, 64, name, name_length, entry->length, archive_key);
    }
    else if (entry->is_obfuscated == 2) {
        if (!*common_key_ready) {
            fwprintf(stderr, L"Common key has not been initialized: %ls\n", name);
            return false;
        }
        create_file_key2(file_key, 64, name, name_length, entry->length, archive_key);
    }

    /* 完成路径验证后才允许创建目录和临时输出文件。 */
    final_path = safe_output_path(root, name);
    if (final_path == NULL || !ensure_parent_directory(final_path)) {
        fwprintf(stderr, L"Unsafe or invalid output path: %ls\n", name);
        goto cleanup;
    }
    temporary_path = make_temporary_path(final_path);
    if (temporary_path == NULL) {
        fwprintf(stderr, L"Unable to allocate a temporary output path: %ls\n", name);
        goto cleanup;
    }
    output = _wfopen(temporary_path, L"w+b");
    if (output == NULL) {
        fwprintf(stderr, L"Unable to create output file: %ls\n", temporary_path);
        goto cleanup;
    }
    if (!reader_init(&reader, archive, entry->offset, entry->length, entry->is_obfuscated,
                     file_key, common_key)) {
        fwprintf(stderr, L"Unable to initialize entry reader: %ls\n", name);
        goto cleanup;
    }

    /* 解密由 reader 透明完成，此处只区分 BPE 解压或直接复制。 */
    if (entry->is_compressed) {
        result = bpe_decompress(&reader, output, entry->original_length);
    }
    else {
        result = copy_entry(&reader, output, entry->length);
    }
    reader_close(&reader);
    if (!result || fflush(output) != 0) {
        fwprintf(stderr, L"Unable to decode or write entry: %ls\n", name);
        result = false;
        goto cleanup;
    }
    if (_fseeki64(output, 0, SEEK_SET) != 0) {
        fwprintf(stderr, L"Unable to rewind output entry: %ls\n", name);
        result = false;
        goto cleanup;
    }
    /* 首个特殊 key 文件解密成功后，立即为后续模式 2 条目派生公共密钥。 */
    if (entry->is_obfuscated == 1 && wcscmp(name, KEY_FILE_NAME) == 0) {
        uint32_t output_length = entry->is_compressed ? entry->original_length : entry->length;
        if (!derive_common_key(output, output_length, common_key)) {
            fwprintf(stderr, L"Invalid common-key file: %ls\n", name);
            result = false;
            goto cleanup;
        }
        *common_key_ready = true;
    }
    if (fclose(output) != 0) {
        fwprintf(stderr, L"Unable to close output entry: %ls\n", name);
        output = NULL;
        result = false;
        goto cleanup;
    }
    output = NULL;
    /* 只有完整写入并成功关闭后，才用临时文件替换最终目标。 */
    if (!MoveFileExW(temporary_path, final_path,
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        fwprintf(stderr, L"Unable to install output entry %ls (Windows error %lu).\n",
                 name, (unsigned long)GetLastError());
        result = false;
        goto cleanup;
    }

cleanup:
    reader_close(&reader);
    if (output != NULL) {
        fclose(output);
    }
    if (!result && temporary_path != NULL) {
        _wremove(temporary_path);
    }
    free(temporary_path);
    free(final_path);
    return result;
}

/*
 * 解包主流程：从文件尾读取固定块，验证格式边界，再按条目表顺序提取。
 * 使用 64 位实际文件位置，因此 x86 程序也能访问超过 2 GiB 的归档。
 */
static int file_unpack(const wchar_t *input_path, const wchar_t *output_directory)
{
    FILE *archive = NULL;
    wchar_t *root = NULL;
    uint64_t archive_length;
    uint64_t hash_offset;
    PACKHEAD head;
    PACKKEY key;
    PACKHASH hash;
    uint32_t archive_key;
    uint32_t common_key[256];
    bool common_key_ready = false;
    uint32_t index;
    bool result = false;

    /* PACKHEAD 和 PACKKEY 固定放在文件尾部，先取得真实 64 位文件长度。 */
    archive = _wfopen(input_path, L"rb");
    if (archive == NULL || !file_size(archive, &archive_length) ||
        archive_length < sizeof(PACKHEAD) + sizeof(PACKKEY)) {
        fwprintf(stderr, L"Unable to open archive: %ls\n", input_path);
        goto cleanup;
    }
    if (!seek_absolute(archive, archive_length - sizeof(PACKHEAD)) ||
        !read_exact(archive, &head, sizeof(head)) ||
        memcmp(head.signature, "FilePackVer3.1\0\0", 16) != 0) {
        fwprintf(stderr, L"Invalid FilePack 3.1 header.\n");
        goto cleanup;
    }
    if (!seek_absolute(archive, archive_length - sizeof(PACKHEAD) - sizeof(PACKKEY)) ||
        !read_exact(archive, &key, sizeof(key)) ||
        key.hash_size < sizeof(PACKHASH) ||
        key.hash_size > archive_length - sizeof(PACKHEAD) - sizeof(PACKKEY)) {
        fwprintf(stderr, L"Invalid FilePack key block.\n");
        goto cleanup;
    }
    /* 根据尾部记录反推哈希区位置，并验证其声明长度没有越过文件边界。 */
    hash_offset = archive_length - sizeof(PACKHEAD) - sizeof(PACKKEY) - key.hash_size;
    if (!seek_absolute(archive, hash_offset) || !read_exact(archive, &hash, sizeof(hash)) ||
        memcmp(hash.signature, "HashVer1.4", 10) != 0 ||
        hash.data_size > key.hash_size - sizeof(PACKHASH)) {
        fwprintf(stderr, L"Invalid FilePack hash block.\n");
        goto cleanup;
    }

    /* 用密钥材料计算归档密钥，再解开并核对密钥块签名。 */
    archive_key = hash_memory(key.key, 256) & 0x0FFFFFFFU;
    chain_crypt(archive_key, key.signature, sizeof(key.signature), false);
    if (memcmp(key.signature, "8hr48uky,8ugi8ewra4g8d5vbf5hb5s6", 32) != 0 ||
        head.entry_offset > hash_offset || !seek_absolute(archive, head.entry_offset)) {
        fwprintf(stderr, L"Invalid FilePack key or entry table.\n");
        goto cleanup;
    }

    root = full_path(output_directory);
    if (root == NULL || !ensure_directory_tree(root)) {
        fwprintf(stderr, L"Unable to create output directory.\n");
        goto cleanup;
    }

    /* 条目表中的名称已加密；解密名称后再校验数据范围并提取。 */
    for (index = 0; index < head.entry_count; ++index) {
        uint16_t name_length;
        wchar_t *name;
        PACKENTRY entry;
        uint64_t table_remaining;
        uint64_t table_position;
        /* 条目数据必须全部位于条目表之前，不能指向尾部元数据。 */
        if (!tell_position(archive, &table_position) || table_position > hash_offset ||
            hash_offset - table_position < sizeof(name_length) ||
            !read_exact(archive, &name_length, sizeof(name_length))) {
            fwprintf(stderr, L"Truncated entry table.\n");
            goto cleanup;
        }
        table_remaining = (uint64_t)name_length * sizeof(wchar_t) + sizeof(entry);
        if (!tell_position(archive, &table_position) || table_position > hash_offset ||
            table_remaining > hash_offset - table_position) {
            fwprintf(stderr, L"Truncated entry table.\n");
            goto cleanup;
        }
        name = (wchar_t *)malloc(((size_t)name_length + 1) * sizeof(*name));
        if (name == NULL || !read_exact(archive, name, (size_t)name_length * sizeof(wchar_t)) ||
            !read_exact(archive, &entry, sizeof(entry))) {
            free(name);
            fwprintf(stderr, L"Truncated entry table.\n");
            goto cleanup;
        }
        name[name_length] = 0;
        name_crypt(archive_key, name, name_length);
        /* 用减法校验区间，避免 offset + length 在恶意归档中发生整数回绕。 */
        if (!tell_position(archive, &table_position) || table_position > hash_offset ||
            entry.offset > head.entry_offset ||
            entry.length > head.entry_offset - entry.offset) {
            free(name);
            fwprintf(stderr, L"Invalid entry offset.\n");
            goto cleanup;
        }
        wprintf(L"%ls...", name);
        if (!extract_entry(archive, root, name, &entry, archive_key,
                           common_key, &common_key_ready)) {
            free(name);
            wprintf(L"error\n");
            goto cleanup;
        }
        free(name);
        if (!seek_absolute(archive, table_position)) {
            goto cleanup;
        }
        wprintf(L"ok\n");
    }
    result = true;

cleanup:
    free(root);
    if (archive != NULL) {
        fclose(archive);
    }
    return result ? 0 : -1;
}

/* 从文件列表移除一个元素并保持后续元素顺序不变。 */
static void remove_list_item(FILE_LIST *list, size_t index)
{
    free(list->items[index].full_path);
    free(list->items[index].relative_path);
    if (index + 1 < list->count) {
        memmove(list->items + index, list->items + index + 1,
                (list->count - index - 1) * sizeof(FILE_ITEM));
    }
    --list->count;
}

/*
 * 打开并检查所有输入文件，统计数据区长度，并把特殊 key 文件移动到首项。
 * 同时排除位于输入目录中的目标 PACK，避免程序把自身输出再次打包。
 */
static bool prepare_file_list(FILE_LIST *list, const wchar_t *output_full_path, uint64_t *total_size)
{
    size_t index = 0;
    size_t key_index = SIZE_MAX;
    *total_size = 0;
    while (index < list->count) {
        wchar_t *item_full = full_path(list->items[index].full_path);
        FILE *file;
        uint64_t length;
        bool is_output = item_full != NULL && _wcsicmp(item_full, output_full_path) == 0;
        free(item_full);
        if (is_output) {
            remove_list_item(list, index);
            continue;
        }
        if (wcslen(list->items[index].relative_path) > UINT16_MAX) {
            return false;
        }
        file = _wfopen(list->items[index].full_path, L"rb");
        if (file == NULL || !file_size(file, &length)) {
            if (file != NULL) fclose(file);
            return false;
        }
        fclose(file);
        /* 单文件长度仍是 uint32_t；归档总大小和偏移则使用有符号 64 位文件 API。 */
        if (length > UINT32_MAX || *total_size > (uint64_t)INT64_MAX - length) {
            return false;
        }
        list->items[index].size = length;
        *total_size += length;
        if (wcscmp(list->items[index].relative_path, KEY_FILE_NAME) == 0) {
            key_index = index;
        }
        ++index;
    }
    if (list->count == 0 || list->count > UINT32_MAX || key_index == SIZE_MAX ||
        list->items[key_index].size < 80) {
        return false;
    }
    /* 模式 2 依赖公共密钥，因此 key 文件必须最先写入和最先解包。 */
    if (key_index != 0) {
        FILE_ITEM key_item = list->items[key_index];
        memmove(list->items + 1, list->items, key_index * sizeof(FILE_ITEM));
        list->items[0] = key_item;
    }
    return true;
}

/*
 * 打包主流程：枚举输入、构建密钥和哈希区、流式写入数据及条目表，
 * 最后追加 PACKHASH、PACKKEY、PACKHEAD，并原子安装完整归档。
 */
static int file_pack(const wchar_t *input_directory, const wchar_t *output_path)
{
    FILE_LIST list;
    BYTE_BUFFER hash_data;
    PACKHEAD head;
    PACKKEY key;
    PACKHASH hash;
    PACKENTRY *entries = NULL;
    wchar_t *root = NULL;
    wchar_t *output_full = NULL;
    wchar_t *temporary_path = NULL;
    FILE *output = NULL;
    uint32_t common_key[256];
    uint32_t archive_key;
    uint64_t total_size;
    size_t index;
    bool result = false;

    memset(&list, 0, sizeof(list));
    memset(&hash_data, 0, sizeof(hash_data));
    memset(&head, 0, sizeof(head));
    memset(&key, 0, sizeof(key));
    memset(&hash, 0, sizeof(hash));

    /* 第一阶段只收集和验证元数据，不创建最终输出文件。 */
    root = full_path(input_directory);
    output_full = full_path(output_path);
    if (root == NULL || output_full == NULL ||
        !enumerate_tree(root, L"", &list) ||
        !prepare_file_list(&list, output_full, &total_size)) {
        fwprintf(stderr, L"Unable to enumerate input files, key file is missing/short, an entry exceeds 4 GiB, or archive offsets exceed INT64_MAX.\n");
        goto cleanup;
    }
    if (!build_hash_data(&list, &hash_data)) {
        fwprintf(stderr, L"Unable to build FilePack hash data.\n");
        goto cleanup;
    }
    if (list.count > UINT32_MAX / sizeof(uint32_t) ||
        hash_data.length > UINT32_MAX - sizeof(PACKHASH)) {
        fwprintf(stderr, L"FilePack metadata exceeds its 32-bit format fields.\n");
        goto cleanup;
    }

    entries = (PACKENTRY *)calloc(list.count, sizeof(*entries));
    if (entries == NULL || !ensure_parent_directory(output_full)) {
        goto cleanup;
    }
    temporary_path = make_temporary_path(output_full);
    if (temporary_path == NULL) {
        goto cleanup;
    }
    /* 所有内容写入临时 PACK，任何中途错误都不会破坏已有目标文件。 */
    output = _wfopen(temporary_path, L"w+b");
    if (output == NULL) {
        goto cleanup;
    }

    /* 生成与旧版相同的随机归档密钥材料和加密签名。 */
    memcpy(head.signature, "FilePackVer3.1", 14);
    head.entry_count = (uint32_t)list.count;
    srand((unsigned int)time(NULL));
    for (index = 0; index < 256; ++index) {
        key.key[index] = (unsigned char)(rand() % 255);
    }
    archive_key = hash_memory(key.key, 256) & 0x0FFFFFFFU;
    memcpy(key.signature, "8hr48uky,8ugi8ewra4g8d5vbf5hb5s6", 32);
    chain_crypt(archive_key, key.signature, sizeof(key.signature), true);

    /* 第二阶段逐文件加密并写入数据区，全程只保留一个固定大小缓冲区。 */
    for (index = 0; index < list.count; ++index) {
        FILE *input = _wfopen(list.items[index].full_path, L"rb");
        uint32_t file_key[64];
        OBFUSCATION_CONTEXT obfuscation;
        uint64_t offset;
        uint32_t length = (uint32_t)list.items[index].size;
        uint32_t name_length = (uint32_t)wcslen(list.items[index].relative_path);
        if (input == NULL || !tell_position(output, &offset)) {
            if (input != NULL) fclose(input);
            goto cleanup;
        }
        /* 首项 key 文件使用模式 1，其余文件使用依赖公共密钥的模式 2。 */
        if (index == 0) {
            if (!derive_common_key(input, length, common_key)) {
                fclose(input);
                goto cleanup;
            }
            create_file_key1(file_key, 64, KEY_FILE_NAME, 36, length, archive_key);
            entries[index].is_obfuscated = 1;
        }
        else {
            create_file_key2(file_key, 64, list.items[index].relative_path,
                             name_length, length, archive_key);
            entries[index].is_obfuscated = 2;
        }
        obfuscation_init(&obfuscation, entries[index].is_obfuscated, true, file_key, common_key);
        entries[index].offset = offset;
        entries[index].length = length;
        entries[index].original_length = length;
        if (!stream_pack_file(output, input, length, &obfuscation, &entries[index].hash)) {
            fclose(input);
            goto cleanup;
        }
        fclose(input);
        wprintf(L"%ls\n", list.items[index].relative_path);
    }

    /* 数据区结束位置即条目表的 64 位偏移；磁盘结构大小仍与旧格式一致。 */
    {
        uint64_t table_offset;
        if (!tell_position(output, &table_offset)) {
            goto cleanup;
        }
        head.entry_offset = table_offset;
    }
    /* 条目表按“名称长度、加密名称、PACKENTRY”顺序连续写入。 */
    for (index = 0; index < list.count; ++index) {
        size_t name_length = wcslen(list.items[index].relative_path);
        uint16_t disk_length = (uint16_t)name_length;
        wchar_t *encrypted_name = duplicate_wide(list.items[index].relative_path);
        if (encrypted_name == NULL) {
            goto cleanup;
        }
        name_crypt(archive_key, encrypted_name, disk_length);
        if (!write_exact(output, &disk_length, sizeof(disk_length)) ||
            !write_exact(output, encrypted_name, name_length * sizeof(wchar_t)) ||
            !write_exact(output, &entries[index], sizeof(entries[index]))) {
            free(encrypted_name);
            goto cleanup;
        }
        free(encrypted_name);
    }

    /* 文件尾依次写哈希区、密钥块和总头，保持 FilePack 3.1 格式不变。 */
    memcpy(hash.signature, "HashVer1.4", 10);
    hash.table_size = 256;
    hash.file_count = (uint32_t)list.count;
    hash.index_size = (uint32_t)(list.count * sizeof(uint32_t));
    hash.data_size = (uint32_t)hash_data.length;
    hash.safety_data_size = sizeof(uint32_t);
    hash.string_hash_version = 0;
    key.hash_size = (uint32_t)(sizeof(PACKHASH) + hash_data.length);
    chain_crypt(0x0428U, hash_data.data, hash_data.length, true);
    if (!write_exact(output, &hash, sizeof(hash)) ||
        !write_exact(output, hash_data.data, hash_data.length) ||
        !write_exact(output, &key, sizeof(key)) ||
        !write_exact(output, &head, sizeof(head)) ||
        fflush(output) != 0 || fclose(output) != 0) {
        output = NULL;
        goto cleanup;
    }
    output = NULL;
    /* 刷盘和关闭全部成功后，才原子替换用户指定的 PACK。 */
    if (!MoveFileExW(temporary_path, output_full,
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        goto cleanup;
    }
    result = true;

cleanup:
    if (output != NULL) {
        fclose(output);
    }
    if (!result && temporary_path != NULL) {
        _wremove(temporary_path);
    }
    free(temporary_path);
    free(output_full);
    free(root);
    free(entries);
    free(hash_data.data);
    list_free(&list);
    return result ? 0 : -1;
}

/* 解析命令行并分派 enpack 或 unpack 操作。 */
int wmain(int argc, wchar_t **argv)
{
    _wsetlocale(LC_ALL, L"");
    if (argc == 4 && wcscmp(argv[1], L"enpack") == 0) {
        return file_pack(argv[2], argv[3]);
    }
    if (argc == 4 && wcscmp(argv[1], L"unpack") == 0) {
        return file_unpack(argv[2], argv[3]);
    }
    wprintf(L"FilePack 3.1 v2\n\n");
    wprintf(L"Pack:   filepack31 enpack <input-directory> <output.pack>\n");
    wprintf(L"Unpack: filepack31 unpack <input.pack> <output-directory>\n");
    return argc == 1 ? 0 : -1;
}
