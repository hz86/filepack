//by 銀の契约者
//github https://github.com/hz86/filepack

#include <io.h>
#include <tchar.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <locale.h>

#include <Windows.h>
#include <Shlwapi.h>
#include <gdiplus.h>
using namespace Gdiplus;

#pragma comment(lib, "Gdiplus.lib") 
#pragma comment(lib, "Shlwapi.lib") 

typedef struct DPNGHEAD {
	unsigned char signature[4];
	unsigned int  unknown1;
	unsigned int  entry_count;
	unsigned int  width;
	unsigned int  height;
} DPNGHEAD;

typedef struct DPNGENTRY {
	unsigned int offset_x;
	unsigned int offset_y;
	unsigned int width;
	unsigned int height;
	unsigned int length;
	unsigned int unknown1;
	unsigned int unknown2;
} DPNGENTRY;

//读入文件
static unsigned char * get_file(wchar_t *file, unsigned int *len)
{
	unsigned char *ret = NULL;
	FILE *fp = _wfopen(file, L"rb");
	if (fp)
	{
		fseek(fp, 0, SEEK_END);
		unsigned int fplen = ftell(fp);

		fseek(fp, 0, SEEK_SET);
		ret = (unsigned char *)malloc(fplen);
		fread(ret, 1, fplen, fp);

		*len = fplen;
		fclose(fp);
	}

	return ret;
}

//写出文件
static void put_file(wchar_t *file, unsigned char *data, unsigned int len)
{
	wchar_t dir[1024];
	wchar_t *pos = file;

	while (1)
	{
		pos = wcschr(pos, '\\');
		if (NULL == pos)
		{
			break;
		}

		wcsncpy(dir, file, pos - file);
		dir[pos - file] = 0;
		_wmkdir(dir);
		pos++;
	}

	FILE *fp = _wfopen(file, L"wb");
	fwrite(data, 1, len, fp);
	fclose(fp);
}

//GDI+ 
static int GetEncoderClsid(const WCHAR* format, CLSID* pClsid)
{
	UINT  num = 0;          // number of image encoders
	UINT  size = 0;         // size of the image encoder array in bytes

	ImageCodecInfo* pImageCodecInfo = NULL;

	GetImageEncodersSize(&num, &size);
	if (size == 0)
		return -1;  // Failure

	pImageCodecInfo = (ImageCodecInfo*)(malloc(size));
	if (pImageCodecInfo == NULL)
		return -1;  // Failure

	GetImageEncoders(num, size, pImageCodecInfo);

	for (UINT j = 0; j < num; ++j)
	{
		if (wcscmp(pImageCodecInfo[j].MimeType, format) == 0)
		{
			*pClsid = pImageCodecInfo[j].Clsid;
			free(pImageCodecInfo);
			return j;  // Success
		}
	}

	free(pImageCodecInfo);
	return -1;  // Failure
}

//转换
static int dpng_to_png(unsigned char *in, unsigned int len, unsigned char **out, unsigned int *outlen)
{
	int ret = -1;
	ULONG_PTR gdiplusToken;
	GdiplusStartupInput gdiplusStartupInput;
	GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

	unsigned int pos = 0;
	DPNGHEAD *dpng = (DPNGHEAD *)(in + pos);
	if (0 == memcmp(dpng->signature, "DPNG", 4))
	{
		Bitmap* bitmap = new Bitmap(dpng->width, dpng->height, PixelFormat32bppARGB);
		Graphics *graphics = new Graphics(bitmap);

		pos += sizeof(DPNGHEAD);
		for (unsigned int i = 0; i < dpng->entry_count; i++)
		{
			DPNGENTRY *entry = (DPNGENTRY *)(in + pos);
			pos += sizeof(DPNGENTRY);

			//wchar_t file[1024];
			//swprintf(file, L"%d.png", i);
			//put_file(file, in + pos, entry->length);

			IStream *entry_stream = SHCreateMemStream(in + pos, entry->length);
			Image* image = new Image(entry_stream);
			pos += entry->length;

			Rect rect;
			rect.X = entry->offset_x;
			rect.Y = entry->offset_y;
			rect.Width = entry->width;
			rect.Height = entry->height;
			graphics->DrawImage(image, rect);

			delete image;
			entry_stream->Release();
		}

		delete graphics;

		CLSID format;
		GetEncoderClsid(L"image/png", &format);
		IStream *out_stream = SHCreateMemStream(NULL, 0);
		bitmap->Save(out_stream, &format);

		ULARGE_INTEGER stream_len;
		LARGE_INTEGER stream_pos = { 0 };
		out_stream->Seek(stream_pos, STREAM_SEEK_END, &stream_len);
		out_stream->Seek(stream_pos, STREAM_SEEK_SET, NULL);

		ULONG readlen;
		*out = (unsigned char *)malloc(stream_len.LowPart);
		out_stream->Read(*out, stream_len.LowPart, &readlen);
		*outlen = readlen;

		out_stream->Release();
		delete bitmap;
		ret = 0;
	}

	GdiplusShutdown(gdiplusToken);
	return ret;
}

//通配符比较
int match_with_asterisk(wchar_t* str1, wchar_t* pattern)
{
	if (str1 == NULL) {
		return -1;
	}

	if (pattern == NULL) {
		return -1;
	}

	int len1 = wcslen(str1);
	int len2 = wcslen(pattern);
	int p1 = 0, p2 = 0;

	//用于分段标记,'*'分隔的字符串
	int mark = 0;
	
	while (p1 < len1 && p2 < len2)
	{
		if (pattern[p2] == '?')
		{
			p1++; p2++;
			continue;
		}
		if (pattern[p2] == '*')
		{
			/*如果当前是*号，则mark前面一部分已经获得匹配，
			*从当前点开始继续下一个块的匹配
			*/
			p2++;
			mark = p2;
			continue;
		}
		if (str1[p1] != pattern[p2])
		{
			if (p1 == 0 && p2 == 0)
			{
				/*
				* 如果是首字符，特殊处理，不相同即匹配失败
				*/
				return -1;
			}
			/*
			* pattern: ...*bdef*...
			*       ^
			*       mark
			*        ^
			*        p2
			*       ^
			*       new p2
			* str1:.....bdcf...
			*       ^
			*       p1
			*      ^
			*     new p1
			* 如上示意图所示，在比到e和c处不想等
			* p2返回到mark处，
			* p1需要返回到下一个位置。
			* 因为*前已经获得匹配，所以mark打标之前的不需要再比较
			*/
			p1 -= p2 - mark - 1;
			p2 = mark;
			continue;
		}
		/*
		* 此处处理相等的情况
		*/
		p1++;
		p2++;
	}
	if (p2 == len2)
	{
		if (p1 == len1)
		{
			/*
			* 两个字符串都结束了，说明模式匹配成功
			*/
			return 0;
		}
		if (pattern[p2 - 1] == '*')
		{
			/*
			* str1还没有结束，但pattern的最后一个字符是*，所以匹配成功
			*
			*/
			return 0;
		}
	}
	while (p2 < len2)
	{
		/*
		* pattern多出的字符只要有一个不是*,匹配失败
		*
		*/
		if (pattern[p2] != '*') {
			return -1;
		}
		p2++;
	}

	return -1;
}

//枚举文件
static void enum_file(wchar_t *in_path, wchar_t *findname, wchar_t **out_filename[], int *out_size)
{
	wchar_t filename[1024];
	wcscat(wcscpy(filename, in_path), L"\\*");

	struct _wfinddata64_t data;
	intptr_t handle = _wfindfirst64(filename, &data);
	if (-1 != handle)
	{
		do
		{
			if (0 == wcscmp(L".", data.name) || 0 == wcscmp(L"..", data.name)) {
				continue;
			}

			if (_A_SUBDIR == (data.attrib & _A_SUBDIR)) {
				wcscat(wcscat(wcscpy(filename, in_path), L"\\"), data.name);
				enum_file(filename, findname, out_filename, out_size);
			}
			else
			{
				if (0 == match_with_asterisk(data.name, findname))
				{
					if (NULL == *out_filename) {
						*out_filename = (wchar_t **)malloc(sizeof(wchar_t *) * (*out_size + 1));
					}
					else {
						*out_filename = (wchar_t **)realloc(*out_filename, sizeof(wchar_t *) * (*out_size + 1));
					}

					(*out_filename)[*out_size] = (wchar_t *)malloc(wcslen(in_path) * 2 + 2 + wcslen(data.name) * 2 + 2);
					wcscat(wcscat(wcscpy((*out_filename)[*out_size], in_path), L"\\"), data.name);
					(*out_size)++;
				}
			}
		}
		while (0 == _tfindnext64(handle, &data));
		_findclose(handle);
	}
}

int wmain(int argc, wchar_t* argv[])
{
	_wsetlocale(LC_ALL, L"chs");

	if (1 == argc)
	{
		wprintf(L"美少女万華鏡 罪と罰の少女 [dpng to png] tool\r\n\r\n");

		wprintf(L"help \r\n");
		wprintf(L"dpng2png -f in.png out.png #转换单个文件\r\n");
		wprintf(L"dpng2png -a ./path         #批量转换并覆盖原文件\r\n");
	}
	else if (3 == argc)
	{
		if (0 == wcscmp(L"-a", argv[1]))
		{
			int len = 0;
			wchar_t **arr = NULL;
			enum_file(argv[2], L"*.png", &arr, &len);

			if (arr)
			{
				for (int i = 0; i < len; i++)
				{
					wprintf(L"%s\r\n", arr[i] + wcslen(argv[2]));

					unsigned int datalen;
					unsigned char *data = get_file(arr[i], &datalen);

					unsigned char *out;
					unsigned int outlen;
					if (-1 != dpng_to_png(data, len, &out, &outlen))
					{
						put_file(arr[i], out, outlen);
						free(out);
					}

					free(data);
				}

				for (int i = 0; i < len; i++) {
					free(arr[i]);
				}

				free(arr);
			}
		}
	}
	else if (4 == argc)
	{
		if (0 == wcscmp(L"-f", argv[1]))
		{
			unsigned int len;
			unsigned char *data = get_file(argv[2], &len);

			unsigned char *out;
			unsigned int outlen;
			if (-1 != dpng_to_png(data, len, &out, &outlen))
			{
				put_file(argv[3], out, outlen);
				free(out);
			}

			free(data);
		}
	}

	return 0;
}

