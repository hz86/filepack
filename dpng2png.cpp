#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

/*
 * 使用 Visual Studio x86 或 x64 Developer Command Prompt 编译：
 *   cl /nologo /std:c++17 /O2 /W4 /WX /MT /EHsc /utf-8 \
 *      dpng2png.cpp /Fe:dpng2png.exe
 */

#include <windows.h>
#include <objidl.h>
#include <gdiplus.h>

#include <algorithm>
#include <clocale>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <limits>
#include <memory>
#include <new>
#include <string>
#include <vector>

#pragma comment(lib, "Gdiplus.lib")
#pragma comment(lib, "Ole32.lib")

namespace {

constexpr std::uint64_t kMaximumSignedFileOffset =
    static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());

/* DPNG 磁盘结构必须保持 1 字节对齐，避免编译器插入填充字节。 */
#pragma pack(push, 1)
struct DpngHeader {
    unsigned char signature[4]; /* 固定签名 "DPNG"。 */
    std::uint32_t unknown1;     /* 原格式保留字段。 */
    std::uint32_t entry_count;  /* 后续图块数量。 */
    std::uint32_t width;        /* 最终合成图宽度。 */
    std::uint32_t height;       /* 最终合成图高度。 */
};

struct DpngEntry {
    std::uint32_t offset_x; /* 图块在最终画布上的横坐标。 */
    std::uint32_t offset_y; /* 图块在最终画布上的纵坐标。 */
    std::uint32_t width;    /* 图块绘制宽度。 */
    std::uint32_t height;   /* 图块绘制高度。 */
    std::uint32_t length;   /* 紧随本结构的内嵌图片字节数。 */
    std::uint32_t unknown1; /* 原格式保留字段。 */
    std::uint32_t unknown2; /* 原格式保留字段。 */
};
#pragma pack(pop)

static_assert(sizeof(DpngHeader) == 20, "DPNG header layout changed");
static_assert(sizeof(DpngEntry) == 28, "DPNG entry layout changed");
static_assert(sizeof(wchar_t) == 2, "This program requires Windows UTF-16 wchar_t");

/* 自动关闭 Win32 HANDLE。 */
class UniqueHandle final {
public:
    UniqueHandle() noexcept = default;
    explicit UniqueHandle(HANDLE handle) noexcept : handle_(handle) {}

    ~UniqueHandle()
    {
        reset();
    }

    UniqueHandle(const UniqueHandle &) = delete;
    UniqueHandle &operator=(const UniqueHandle &) = delete;

    UniqueHandle(UniqueHandle &&other) noexcept : handle_(other.release()) {}

    UniqueHandle &operator=(UniqueHandle &&other) noexcept
    {
        if (this != &other) {
            reset(other.release());
        }
        return *this;
    }

    HANDLE get() const noexcept
    {
        return handle_;
    }

    bool valid() const noexcept
    {
        return handle_ != INVALID_HANDLE_VALUE && handle_ != nullptr;
    }

    HANDLE release() noexcept
    {
        HANDLE result = handle_;
        handle_ = INVALID_HANDLE_VALUE;
        return result;
    }

    void reset(HANDLE replacement = INVALID_HANDLE_VALUE) noexcept
    {
        if (valid()) {
            CloseHandle(handle_);
        }
        handle_ = replacement;
    }

private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
};

/* 自动关闭 FindFirstFileW 返回的枚举句柄。 */
class UniqueFindHandle final {
public:
    explicit UniqueFindHandle(HANDLE handle) noexcept : handle_(handle) {}

    ~UniqueFindHandle()
    {
        if (handle_ != INVALID_HANDLE_VALUE) {
            FindClose(handle_);
        }
    }

    UniqueFindHandle(const UniqueFindHandle &) = delete;
    UniqueFindHandle &operator=(const UniqueFindHandle &) = delete;

private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
};

/* 在进程生命周期内启动和关闭 GDI+。 */
class GdiplusSession final {
public:
    GdiplusSession()
    {
        Gdiplus::GdiplusStartupInput input;
        status_ = Gdiplus::GdiplusStartup(&token_, &input, nullptr);
    }

    ~GdiplusSession()
    {
        if (status_ == Gdiplus::Ok) {
            Gdiplus::GdiplusShutdown(token_);
        }
    }

    GdiplusSession(const GdiplusSession &) = delete;
    GdiplusSession &operator=(const GdiplusSession &) = delete;

    bool valid() const noexcept
    {
        return status_ == Gdiplus::Ok;
    }

    Gdiplus::Status status() const noexcept
    {
        return status_;
    }

private:
    ULONG_PTR token_ = 0;
    Gdiplus::Status status_ = Gdiplus::GenericError;
};

/*
 * 基于 Win32 文件句柄实现 IStream。
 * 输入模式可以把一个大文件中的指定区间暴露为从零开始的独立流；输出模式
 * 直接把 GDI+ 编码结果写入文件，避免 x86 下为整张 PNG 申请连续内存。
 */
class HandleStream final : public IStream {
public:
    static HRESULT CreateInputRange(HANDLE source, std::uint64_t base,
                                    std::uint64_t length, IStream **result)
    {
        HANDLE duplicate = INVALID_HANDLE_VALUE;
        if (result == nullptr) {
            return E_POINTER;
        }
        *result = nullptr;
        if (base > kMaximumSignedFileOffset ||
            length > kMaximumSignedFileOffset - base) {
            return STG_E_INVALIDFUNCTION;
        }
        if (!DuplicateHandle(GetCurrentProcess(), source, GetCurrentProcess(),
                             &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
            return HRESULT_FROM_WIN32(GetLastError());
        }
        HandleStream *stream = new (std::nothrow)
            HandleStream(duplicate, base, length, false, true);
        if (stream == nullptr) {
            CloseHandle(duplicate);
            return E_OUTOFMEMORY;
        }
        *result = stream;
        return S_OK;
    }

    static HRESULT CreateOutput(HANDLE file, IStream **result)
    {
        if (result == nullptr) {
            CloseHandle(file);
            return E_POINTER;
        }
        *result = nullptr;
        HandleStream *stream = new (std::nothrow)
            HandleStream(file, 0, 0, true, false);
        if (stream == nullptr) {
            CloseHandle(file);
            return E_OUTOFMEMORY;
        }
        *result = stream;
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void **object) override
    {
        if (object == nullptr) {
            return E_POINTER;
        }
        *object = nullptr;
        if (IsEqualIID(iid, IID_IUnknown) ||
            IsEqualIID(iid, IID_ISequentialStream) ||
            IsEqualIID(iid, IID_IStream)) {
            *object = static_cast<IStream *>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override
    {
        return static_cast<ULONG>(InterlockedIncrement(&reference_count_));
    }

    ULONG STDMETHODCALLTYPE Release() override
    {
        const LONG count = InterlockedDecrement(&reference_count_);
        if (count == 0) {
            delete this;
        }
        return static_cast<ULONG>(count);
    }

    HRESULT STDMETHODCALLTYPE Read(void *buffer, ULONG requested,
                                   ULONG *bytes_read) override
    {
        if (bytes_read != nullptr) {
            *bytes_read = 0;
        }
        if (requested != 0 && buffer == nullptr) {
            return STG_E_INVALIDPOINTER;
        }

        const std::uint64_t available =
            position_ < length_ ? length_ - position_ : 0;
        const ULONG target = available < requested
                                 ? static_cast<ULONG>(available)
                                 : requested;
        if (target == 0) {
            return requested == 0 ? S_OK : S_FALSE;
        }
        HRESULT status = seek_physical(position_);
        if (FAILED(status)) {
            return status;
        }

        ULONG total = 0;
        auto *destination = static_cast<unsigned char *>(buffer);
        while (total < target) {
            DWORD amount = 0;
            if (!ReadFile(handle_, destination + total, target - total,
                          &amount, nullptr)) {
                return HRESULT_FROM_WIN32(GetLastError());
            }
            if (amount == 0) {
                break;
            }
            total += amount;
        }
        position_ += total;
        if (bytes_read != nullptr) {
            *bytes_read = total;
        }
        return total == requested ? S_OK : S_FALSE;
    }

    HRESULT STDMETHODCALLTYPE Write(const void *buffer, ULONG requested,
                                    ULONG *bytes_written) override
    {
        if (bytes_written != nullptr) {
            *bytes_written = 0;
        }
        if (!writable_) {
            return STG_E_ACCESSDENIED;
        }
        if (requested != 0 && buffer == nullptr) {
            return STG_E_INVALIDPOINTER;
        }
        if (position_ > kMaximumSignedFileOffset - requested ||
            base_ > kMaximumSignedFileOffset - (position_ + requested)) {
            return STG_E_MEDIUMFULL;
        }
        HRESULT status = seek_physical(position_);
        if (FAILED(status)) {
            return status;
        }

        ULONG total = 0;
        const auto *source = static_cast<const unsigned char *>(buffer);
        while (total < requested) {
            DWORD amount = 0;
            if (!WriteFile(handle_, source + total, requested - total,
                           &amount, nullptr)) {
                return HRESULT_FROM_WIN32(GetLastError());
            }
            if (amount == 0) {
                return STG_E_MEDIUMFULL;
            }
            total += amount;
        }
        position_ += total;
        if (position_ > length_) {
            length_ = position_;
        }
        if (bytes_written != nullptr) {
            *bytes_written = total;
        }
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE Seek(LARGE_INTEGER movement, DWORD origin,
                                   ULARGE_INTEGER *new_position) override
    {
        std::uint64_t starting_position;
        switch (origin) {
        case STREAM_SEEK_SET:
            starting_position = 0;
            break;
        case STREAM_SEEK_CUR:
            starting_position = position_;
            break;
        case STREAM_SEEK_END:
            starting_position = length_;
            break;
        default:
            return STG_E_INVALIDFUNCTION;
        }

        std::uint64_t candidate;
        if (movement.QuadPart < 0) {
            const std::uint64_t distance =
                static_cast<std::uint64_t>(-(movement.QuadPart + 1)) + 1;
            if (distance > starting_position) {
                return STG_E_INVALIDFUNCTION;
            }
            candidate = starting_position - distance;
        }
        else {
            const std::uint64_t distance =
                static_cast<std::uint64_t>(movement.QuadPart);
            if (distance > kMaximumSignedFileOffset - starting_position) {
                return STG_E_INVALIDFUNCTION;
            }
            candidate = starting_position + distance;
        }
        if (bounded_ && candidate > length_) {
            return STG_E_INVALIDFUNCTION;
        }
        if (base_ > kMaximumSignedFileOffset - candidate) {
            return STG_E_INVALIDFUNCTION;
        }
        position_ = candidate;
        if (new_position != nullptr) {
            new_position->QuadPart = candidate;
        }
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE SetSize(ULARGE_INTEGER new_size) override
    {
        if (!writable_) {
            return STG_E_ACCESSDENIED;
        }
        if (new_size.QuadPart > kMaximumSignedFileOffset - base_) {
            return STG_E_MEDIUMFULL;
        }
        LARGE_INTEGER position;
        position.QuadPart = static_cast<LONGLONG>(base_ + new_size.QuadPart);
        if (!SetFilePointerEx(handle_, position, nullptr, FILE_BEGIN) ||
            !SetEndOfFile(handle_)) {
            return HRESULT_FROM_WIN32(GetLastError());
        }
        length_ = new_size.QuadPart;
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE CopyTo(IStream *destination, ULARGE_INTEGER requested,
                                     ULARGE_INTEGER *bytes_read,
                                     ULARGE_INTEGER *bytes_written) override
    {
        if (destination == nullptr) {
            return STG_E_INVALIDPOINTER;
        }
        if (bytes_read != nullptr) {
            bytes_read->QuadPart = 0;
        }
        if (bytes_written != nullptr) {
            bytes_written->QuadPart = 0;
        }

        unsigned char buffer[4U * 1024U];
        std::uint64_t total_read = 0;
        std::uint64_t total_written = 0;
        while (total_read < requested.QuadPart) {
            const std::uint64_t remaining = requested.QuadPart - total_read;
            const ULONG amount = remaining < sizeof(buffer)
                                     ? static_cast<ULONG>(remaining)
                                     : static_cast<ULONG>(sizeof(buffer));
            ULONG read_now = 0;
            HRESULT status = Read(buffer, amount, &read_now);
            if (FAILED(status)) {
                return status;
            }
            if (read_now == 0) {
                break;
            }
            ULONG written_now = 0;
            status = destination->Write(buffer, read_now, &written_now);
            total_read += read_now;
            total_written += written_now;
            if (FAILED(status) || written_now != read_now) {
                return FAILED(status) ? status : STG_E_MEDIUMFULL;
            }
        }
        if (bytes_read != nullptr) {
            bytes_read->QuadPart = total_read;
        }
        if (bytes_written != nullptr) {
            bytes_written->QuadPart = total_written;
        }
        return total_read == requested.QuadPart ? S_OK : S_FALSE;
    }

    HRESULT STDMETHODCALLTYPE Commit(DWORD) override
    {
        if (!writable_) {
            return S_OK;
        }
        return FlushFileBuffers(handle_)
                   ? S_OK
                   : HRESULT_FROM_WIN32(GetLastError());
    }

    HRESULT STDMETHODCALLTYPE Revert() override
    {
        return E_NOTIMPL;
    }

    HRESULT STDMETHODCALLTYPE LockRegion(ULARGE_INTEGER, ULARGE_INTEGER,
                                         DWORD) override
    {
        return STG_E_INVALIDFUNCTION;
    }

    HRESULT STDMETHODCALLTYPE UnlockRegion(ULARGE_INTEGER, ULARGE_INTEGER,
                                           DWORD) override
    {
        return STG_E_INVALIDFUNCTION;
    }

    HRESULT STDMETHODCALLTYPE Stat(STATSTG *statistics, DWORD flags) override
    {
        if (statistics == nullptr) {
            return STG_E_INVALIDPOINTER;
        }
        std::memset(statistics, 0, sizeof(*statistics));
        statistics->type = STGTY_STREAM;
        statistics->cbSize.QuadPart = length_;
        statistics->grfMode = writable_ ? STGM_READWRITE : STGM_READ;
        if ((flags & STATFLAG_NONAME) == 0) {
            statistics->pwcsName = nullptr;
        }
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE Clone(IStream **) override
    {
        return E_NOTIMPL;
    }

private:
    HandleStream(HANDLE handle, std::uint64_t base, std::uint64_t length,
                 bool writable, bool bounded) noexcept
        : handle_(handle), base_(base), length_(length), writable_(writable),
          bounded_(bounded)
    {
    }

    ~HandleStream()
    {
        if (handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
        }
    }

    HRESULT seek_physical(std::uint64_t logical_position)
    {
        if (logical_position > kMaximumSignedFileOffset ||
            base_ > kMaximumSignedFileOffset - logical_position) {
            return STG_E_INVALIDFUNCTION;
        }
        LARGE_INTEGER position;
        position.QuadPart = static_cast<LONGLONG>(base_ + logical_position);
        return SetFilePointerEx(handle_, position, nullptr, FILE_BEGIN)
                   ? S_OK
                   : HRESULT_FROM_WIN32(GetLastError());
    }

    LONG reference_count_ = 1;
    HANDLE handle_ = INVALID_HANDLE_VALUE;
    std::uint64_t base_ = 0;
    std::uint64_t length_ = 0;
    std::uint64_t position_ = 0;
    bool writable_ = false;
    bool bounded_ = false;
};

enum class ConversionResult {
    converted,
    not_dpng,
    failed
};

/* 输出包含 Win32 错误码的统一错误信息。 */
void print_windows_error(const wchar_t *operation, const std::wstring &path,
                         DWORD error)
{
    std::fwprintf(stderr, L"%ls：%ls（Windows 错误 %lu）\n",
                  operation, path.c_str(), static_cast<unsigned long>(error));
}

/* 将路径规范化为绝对路径。 */
bool get_full_path(const std::wstring &path, std::wstring *result)
{
    const DWORD needed = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
    if (needed == 0) {
        return false;
    }
    std::vector<wchar_t> buffer(static_cast<std::size_t>(needed) + 1U);
    const DWORD written = GetFullPathNameW(path.c_str(),
                                           static_cast<DWORD>(buffer.size()),
                                           buffer.data(), nullptr);
    if (written == 0 || written >= buffer.size()) {
        return false;
    }
    result->assign(buffer.data(), written);
    return true;
}

/* 拼接 Windows 路径。 */
std::wstring join_path(const std::wstring &left, const std::wstring &right)
{
    if (left.empty()) {
        return right;
    }
    if (left.back() == L'\\' || left.back() == L'/') {
        return left + right;
    }
    return left + L'\\' + right;
}

/* 逐级创建目录，并拒绝把已有文件或目录重解析点当作普通目录使用。 */
bool ensure_directory_tree(const std::wstring &directory)
{
    if (directory.empty()) {
        return true;
    }
    std::wstring copy = directory;
    while (copy.size() > 3U &&
           (copy.back() == L'\\' || copy.back() == L'/')) {
        copy.pop_back();
    }

    std::size_t start = 0;
    if (copy.size() >= 3U && copy[1] == L':' &&
        (copy[2] == L'\\' || copy[2] == L'/')) {
        start = 3;
    }
    else if (copy.size() >= 2U && copy[0] == L'\\' && copy[1] == L'\\') {
        const std::size_t server_end = copy.find(L'\\', 2);
        const std::size_t share_end = server_end == std::wstring::npos
                                          ? std::wstring::npos
                                          : copy.find(L'\\', server_end + 1U);
        start = share_end == std::wstring::npos ? copy.size() : share_end + 1U;
    }

    for (std::size_t index = start; index <= copy.size(); ++index) {
        if (index != copy.size() && copy[index] != L'\\' && copy[index] != L'/') {
            continue;
        }
        const wchar_t saved = copy[index];
        copy[index] = L'\0';
        const DWORD attributes = GetFileAttributesW(copy.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES) {
            if (!CreateDirectoryW(copy.c_str(), nullptr) &&
                GetLastError() != ERROR_ALREADY_EXISTS) {
                copy[index] = saved;
                return false;
            }
        }
        else if ((attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
                 (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
            copy[index] = saved;
            return false;
        }
        copy[index] = saved;
    }
    return true;
}

/* 确保输出文件的父目录存在。 */
bool ensure_parent_directory(const std::wstring &file_path)
{
    const std::size_t separator = file_path.find_last_of(L"\\/");
    if (separator == std::wstring::npos) {
        return true;
    }
    return ensure_directory_tree(file_path.substr(0, separator));
}

/* 获取 Win32 文件的 64 位长度。 */
bool get_file_size(HANDLE file, std::uint64_t *size)
{
    LARGE_INTEGER value;
    if (!GetFileSizeEx(file, &value) || value.QuadPart < 0) {
        return false;
    }
    *size = static_cast<std::uint64_t>(value.QuadPart);
    return true;
}

/* 从 64 位绝对位置精确读取一段固定大小数据。 */
bool read_exact_at(HANDLE file, std::uint64_t position, void *data,
                   std::size_t length)
{
    if (position > kMaximumSignedFileOffset ||
        length > kMaximumSignedFileOffset - position) {
        return false;
    }
    LARGE_INTEGER offset;
    offset.QuadPart = static_cast<LONGLONG>(position);
    if (!SetFilePointerEx(file, offset, nullptr, FILE_BEGIN)) {
        return false;
    }

    auto *output = static_cast<unsigned char *>(data);
    std::size_t total = 0;
    while (total < length) {
        const std::size_t remaining = length - total;
        const DWORD amount = remaining > MAXDWORD
                                 ? MAXDWORD
                                 : static_cast<DWORD>(remaining);
        DWORD read_now = 0;
        if (!ReadFile(file, output + total, amount, &read_now, nullptr) ||
            read_now == 0) {
            return false;
        }
        total += read_now;
    }
    return true;
}

/* 查找 GDI+ 中指定 MIME 类型的编码器。 */
bool find_encoder(const wchar_t *mime_type, CLSID *encoder)
{
    UINT count = 0;
    UINT size = 0;
    if (Gdiplus::GetImageEncodersSize(&count, &size) != Gdiplus::Ok ||
        count == 0 || size == 0) {
        return false;
    }
    std::vector<unsigned char> storage(size);
    auto *codecs = reinterpret_cast<Gdiplus::ImageCodecInfo *>(storage.data());
    if (Gdiplus::GetImageEncoders(count, size, codecs) != Gdiplus::Ok) {
        return false;
    }
    for (UINT index = 0; index < count; ++index) {
        if (codecs[index].MimeType != nullptr &&
            std::wcscmp(codecs[index].MimeType, mime_type) == 0) {
            *encoder = codecs[index].Clsid;
            return true;
        }
    }
    return false;
}

/* 使用 CREATE_NEW 原子创建临时输出，避免名称检查与文件创建之间的竞争。 */
bool create_temporary_output(const std::wstring &final_path,
                             std::wstring *temporary_path,
                             IStream **stream)
{
    const DWORD process_id = GetCurrentProcessId();
    const ULONGLONG tick = GetTickCount64();
    for (unsigned int attempt = 0; attempt < 1000U; ++attempt) {
        wchar_t suffix[96];
        const int suffix_length = swprintf_s(
            suffix, L".dpng2png.%lu.%llu.%u.tmp",
            static_cast<unsigned long>(process_id),
            static_cast<unsigned long long>(tick), attempt);
        if (suffix_length <= 0) {
            return false;
        }
        std::wstring candidate = final_path + suffix;
        HANDLE output = CreateFileW(candidate.c_str(), GENERIC_READ | GENERIC_WRITE,
                                    0, nullptr, CREATE_NEW,
                                    FILE_ATTRIBUTE_NORMAL, nullptr);
        if (output == INVALID_HANDLE_VALUE) {
            const DWORD error = GetLastError();
            if (error == ERROR_FILE_EXISTS || error == ERROR_ALREADY_EXISTS) {
                continue;
            }
            print_windows_error(L"无法创建临时输出", candidate, error);
            return false;
        }
        const HRESULT status = HandleStream::CreateOutput(output, stream);
        if (FAILED(status)) {
            DeleteFileW(candidate.c_str());
            return false;
        }
        *temporary_path = std::move(candidate);
        return true;
    }
    return false;
}

/* 将位图编码到临时文件，成功后原子替换最终目标。 */
bool save_bitmap_atomic(Gdiplus::Bitmap *bitmap, const std::wstring &output_path,
                        const CLSID &png_encoder)
{
    std::wstring final_path;
    if (!get_full_path(output_path, &final_path) ||
        !ensure_parent_directory(final_path)) {
        std::fwprintf(stderr, L"无法创建输出目录：%ls\n", output_path.c_str());
        return false;
    }

    std::wstring temporary_path;
    IStream *stream = nullptr;
    if (!create_temporary_output(final_path, &temporary_path, &stream)) {
        return false;
    }

    const Gdiplus::Status save_status = bitmap->Save(stream, &png_encoder, nullptr);
    const HRESULT commit_status = save_status == Gdiplus::Ok
                                      ? stream->Commit(STGC_DEFAULT)
                                      : E_FAIL;
    stream->Release();
    if (save_status != Gdiplus::Ok || FAILED(commit_status)) {
        std::fwprintf(stderr, L"PNG 编码或写入失败：%ls（GDI+ 状态 %d）\n",
                      output_path.c_str(), static_cast<int>(save_status));
        DeleteFileW(temporary_path.c_str());
        return false;
    }
    if (!MoveFileExW(temporary_path.c_str(), final_path.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        const DWORD error = GetLastError();
        print_windows_error(L"无法安装最终 PNG", final_path, error);
        DeleteFileW(temporary_path.c_str());
        return false;
    }
    return true;
}

/* 检查图块矩形能安全转换为 GDI+ 使用的有符号 INT。 */
bool validate_rectangle(const DpngEntry &entry)
{
    constexpr std::uint32_t maximum =
        static_cast<std::uint32_t>(std::numeric_limits<INT>::max());
    return entry.offset_x <= maximum && entry.offset_y <= maximum &&
           entry.width <= maximum && entry.height <= maximum &&
           entry.width <= maximum - entry.offset_x &&
           entry.height <= maximum - entry.offset_y;
}

/*
 * 将一个 DPNG 转换为标准 PNG。
 * 图块数据通过受限 IStream 直接从源文件解码，单个文件可以跨越 2 GiB 偏移。
 */
ConversionResult convert_dpng_file(const std::wstring &input_path,
                                   const std::wstring &output_path,
                                   const CLSID &png_encoder)
{
    UniqueHandle input(CreateFileW(input_path.c_str(), GENERIC_READ,
                                   FILE_SHARE_READ | FILE_SHARE_DELETE,
                                   nullptr, OPEN_EXISTING,
                                   FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!input.valid()) {
        print_windows_error(L"无法打开输入文件", input_path, GetLastError());
        return ConversionResult::failed;
    }

    std::uint64_t file_size = 0;
    if (!get_file_size(input.get(), &file_size)) {
        print_windows_error(L"无法读取文件长度", input_path, GetLastError());
        return ConversionResult::failed;
    }
    if (file_size < 4U) {
        return ConversionResult::not_dpng;
    }

    unsigned char signature[4];
    if (!read_exact_at(input.get(), 0, signature, sizeof(signature))) {
        std::fwprintf(stderr, L"无法读取文件签名：%ls\n", input_path.c_str());
        return ConversionResult::failed;
    }
    if (std::memcmp(signature, "DPNG", sizeof(signature)) != 0) {
        return ConversionResult::not_dpng;
    }
    if (file_size < sizeof(DpngHeader)) {
        std::fwprintf(stderr, L"DPNG 文件头被截断：%ls\n", input_path.c_str());
        return ConversionResult::failed;
    }

    DpngHeader header{};
    if (!read_exact_at(input.get(), 0, &header, sizeof(header))) {
        std::fwprintf(stderr, L"无法读取 DPNG 文件头：%ls\n", input_path.c_str());
        return ConversionResult::failed;
    }
    constexpr std::uint32_t maximum_dimension =
        static_cast<std::uint32_t>(std::numeric_limits<INT>::max());
    if (header.width == 0 || header.height == 0 ||
        header.width > maximum_dimension || header.height > maximum_dimension ||
        header.entry_count >
            (file_size - sizeof(DpngHeader)) / sizeof(DpngEntry)) {
        std::fwprintf(stderr, L"DPNG 尺寸或条目数量无效：%ls\n", input_path.c_str());
        return ConversionResult::failed;
    }

    auto bitmap = std::make_unique<Gdiplus::Bitmap>(
        static_cast<INT>(header.width), static_cast<INT>(header.height),
        PixelFormat32bppARGB);
    if (bitmap->GetLastStatus() != Gdiplus::Ok) {
        std::fwprintf(stderr, L"无法分配 DPNG 画布：%ls\n", input_path.c_str());
        return ConversionResult::failed;
    }
    auto graphics = std::make_unique<Gdiplus::Graphics>(bitmap.get());
    if (graphics->GetLastStatus() != Gdiplus::Ok ||
        graphics->Clear(Gdiplus::Color(0, 0, 0, 0)) != Gdiplus::Ok) {
        std::fwprintf(stderr, L"无法初始化 DPNG 画布：%ls\n", input_path.c_str());
        return ConversionResult::failed;
    }

    std::uint64_t position = sizeof(DpngHeader);
    for (std::uint32_t index = 0; index < header.entry_count; ++index) {
        if (position > file_size || sizeof(DpngEntry) > file_size - position) {
            std::fwprintf(stderr, L"DPNG 条目表被截断：%ls（条目 %u）\n",
                          input_path.c_str(), index);
            return ConversionResult::failed;
        }
        DpngEntry entry{};
        if (!read_exact_at(input.get(), position, &entry, sizeof(entry))) {
            std::fwprintf(stderr, L"无法读取 DPNG 条目：%ls（条目 %u）\n",
                          input_path.c_str(), index);
            return ConversionResult::failed;
        }
        position += sizeof(entry);
        if (entry.length > file_size - position || !validate_rectangle(entry)) {
            std::fwprintf(stderr, L"DPNG 图块范围无效：%ls（条目 %u）\n",
                          input_path.c_str(), index);
            return ConversionResult::failed;
        }

        IStream *entry_stream = nullptr;
        const HRESULT stream_status = HandleStream::CreateInputRange(
            input.get(), position, entry.length, &entry_stream);
        if (FAILED(stream_status)) {
            std::fwprintf(stderr, L"无法创建 DPNG 图块流：%ls（条目 %u）\n",
                          input_path.c_str(), index);
            return ConversionResult::failed;
        }

        const Gdiplus::Rect destination(
            static_cast<INT>(entry.offset_x), static_cast<INT>(entry.offset_y),
            static_cast<INT>(entry.width), static_cast<INT>(entry.height));
        Gdiplus::Status image_status = Gdiplus::GenericError;
        Gdiplus::Status draw_status = Gdiplus::GenericError;
        {
            Gdiplus::Image image(entry_stream);
            image_status = image.GetLastStatus();
            if (image_status == Gdiplus::Ok) {
                draw_status = graphics->DrawImage(&image, destination);
            }
        }
        entry_stream->Release();
        if (image_status != Gdiplus::Ok) {
            std::fwprintf(stderr, L"DPNG 内嵌图片无效：%ls（条目 %u）\n",
                          input_path.c_str(), index);
            return ConversionResult::failed;
        }
        if (draw_status != Gdiplus::Ok) {
            std::fwprintf(stderr, L"DPNG 图块绘制失败：%ls（条目 %u）\n",
                          input_path.c_str(), index);
            return ConversionResult::failed;
        }
        position += entry.length;
    }

    /* 保存位图之前销毁 Graphics，避免 GDI+ 将仍在绘制的位图判定为忙碌。 */
    graphics.reset();
    /* 图块已经完全绘制，保存前关闭输入句柄，允许 -a 安全覆盖原文件。 */
    input.reset();
    return save_bitmap_atomic(bitmap.get(), output_path, png_encoder)
               ? ConversionResult::converted
               : ConversionResult::failed;
}

/* 判断文件扩展名是否为 .png，不区分大小写。 */
bool has_png_extension(const std::wstring &name)
{
    const std::size_t dot = name.find_last_of(L'.');
    return dot != std::wstring::npos &&
           _wcsicmp(name.c_str() + dot, L".png") == 0;
}

/* 递归枚举 PNG 文件；所有重解析点都被跳过，避免越过指定目录。 */
bool enumerate_png_files(const std::wstring &directory,
                         std::vector<std::wstring> *files)
{
    const std::wstring pattern = join_path(directory, L"*");
    WIN32_FIND_DATAW data{};
    HANDLE raw_handle = FindFirstFileW(pattern.c_str(), &data);
    if (raw_handle == INVALID_HANDLE_VALUE) {
        const DWORD error = GetLastError();
        return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
    }
    UniqueFindHandle handle(raw_handle);

    bool success = true;
    for (;;) {
        if (std::wcscmp(data.cFileName, L".") != 0 &&
            std::wcscmp(data.cFileName, L"..") != 0) {
            const std::wstring path = join_path(directory, data.cFileName);
            if ((data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0) {
                if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
                    if (!enumerate_png_files(path, files)) {
                        success = false;
                        break;
                    }
                }
                else if (has_png_extension(data.cFileName)) {
                    files->push_back(path);
                }
            }
        }
        if (!FindNextFileW(raw_handle, &data)) {
            if (GetLastError() != ERROR_NO_MORE_FILES) {
                success = false;
            }
            break;
        }
    }
    return success;
}

/* 转换单个文件。 */
int convert_one(const std::wstring &input, const std::wstring &output,
                const CLSID &png_encoder)
{
    const ConversionResult result = convert_dpng_file(input, output, png_encoder);
    if (result == ConversionResult::converted) {
        std::wprintf(L"转换完成：%ls -> %ls\n", input.c_str(), output.c_str());
        return 0;
    }
    if (result == ConversionResult::not_dpng) {
        std::fwprintf(stderr, L"输入文件不是 DPNG：%ls\n", input.c_str());
    }
    return 1;
}

/* 批量转换目录中的 DPNG .png 文件，普通 PNG 保持不变。 */
int convert_all(const std::wstring &input_directory, const CLSID &png_encoder)
{
    std::wstring root;
    if (!get_full_path(input_directory, &root)) {
        std::fwprintf(stderr, L"输入目录无效：%ls\n", input_directory.c_str());
        return 1;
    }
    const DWORD attributes = GetFileAttributesW(root.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES ||
        (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
        (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        std::fwprintf(stderr, L"输入目录不存在或不安全：%ls\n", root.c_str());
        return 1;
    }

    std::vector<std::wstring> files;
    if (!enumerate_png_files(root, &files)) {
        std::fwprintf(stderr, L"枚举输入目录失败：%ls\n", root.c_str());
        return 1;
    }
    std::sort(files.begin(), files.end(),
              [](const std::wstring &left, const std::wstring &right) {
                  return _wcsicmp(left.c_str(), right.c_str()) < 0;
              });

    std::size_t converted = 0;
    std::size_t skipped = 0;
    std::size_t failed = 0;
    for (const std::wstring &path : files) {
        std::wprintf(L"处理：%ls\n", path.c_str());
        const ConversionResult result = convert_dpng_file(path, path, png_encoder);
        if (result == ConversionResult::converted) {
            ++converted;
        }
        else if (result == ConversionResult::not_dpng) {
            ++skipped;
        }
        else {
            ++failed;
        }
    }
    std::wprintf(L"批量完成：转换 %zu，跳过普通 PNG %zu，失败 %zu\n",
                 converted, skipped, failed);
    return failed == 0 ? 0 : 1;
}

void print_help()
{
    std::wprintf(L"DPNG to PNG v2\n\n");
    std::wprintf(L"单文件：dpng2png -f <输入文件> <输出 PNG>\n");
    std::wprintf(L"批量：  dpng2png -a <输入目录>\n");
    std::wprintf(L"批量模式递归扫描 *.png，并原子覆盖其中的 DPNG 文件。\n");
}

} // namespace

int wmain(int argc, wchar_t **argv)
{
    if (std::setlocale(LC_ALL, ".UTF-8") == nullptr) {
        std::setlocale(LC_ALL, "");
    }
    if (!((argc == 4 && std::wcscmp(argv[1], L"-f") == 0) ||
          (argc == 3 && std::wcscmp(argv[1], L"-a") == 0))) {
        print_help();
        return argc == 1 ? 0 : 1;
    }

    try {
        GdiplusSession gdiplus;
        if (!gdiplus.valid()) {
            std::fwprintf(stderr, L"GDI+ 初始化失败（状态 %d）。\n",
                          static_cast<int>(gdiplus.status()));
            return 1;
        }
        CLSID png_encoder{};
        if (!find_encoder(L"image/png", &png_encoder)) {
            std::fwprintf(stderr, L"系统中未找到 PNG 编码器。\n");
            return 1;
        }
        if (argc == 4) {
            return convert_one(argv[2], argv[3], png_encoder);
        }
        return convert_all(argv[2], png_encoder);
    }
    catch (const std::bad_alloc &) {
        std::fwprintf(stderr, L"内存分配失败。\n");
        return 1;
    }
    catch (...) {
        std::fwprintf(stderr, L"发生未处理的转换错误。\n");
        return 1;
    }
}
