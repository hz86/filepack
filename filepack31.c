//by 銀の契约者
//github https://github.com/hz86/filepack

#include <io.h>
#include <tchar.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <mmintrin.h>
#include <direct.h>
#include <locale.h>
#include <time.h>

typedef struct PACKHEAD {
	unsigned char signature[16];
	unsigned int  entry_count;
	unsigned int  entry_offset;
	unsigned int  unknown1;
} PACKHEAD;

typedef struct PACKKEY {
	unsigned char signature[32];
	unsigned int  hash_size;
	unsigned char key[1024];
} PACKKEY;

typedef struct PACKHASH {
	unsigned char signature[16];
	unsigned int  table_size;
	unsigned int  file_count;
	unsigned int  index_size;
	unsigned int  data_size;
	unsigned int  is_compressed;
	unsigned char unknown1[32];
} PACKHASH;

typedef struct PACKENTRY {
	unsigned int offset;
	unsigned int unknown1;
	unsigned int length;
	unsigned int original_length;
	unsigned int is_compressed;
	unsigned int is_obfuscated;
	unsigned int hash;
} PACKENTRY;

////////////反编译出来的代码-开始//////////////////

//计算hash
static unsigned int sub_4E2578_gethash(unsigned char *data, unsigned int len)
{
	unsigned int result;
	__m64 *v3;
	unsigned int v4;
	__m64 v5;
	__m64 v6;
	__m64 v7;
	__m64 v8;
	__m64 v9;

	if (len >= 8)
	{
		v3 = (__m64 *)data;
		v4 = len >> 3;
		v5.m64_u64 = 0i64;
		v6.m64_u64 = 0i64;
		v7 = _mm_cvtsi32_si64(0xA35793A7);
		v8 = _m_punpckldq(v7, v7);
		do
		{
			v6 = _m_paddw(v6, v8);
			v9 = _m_paddw(v5, _m_pxor(*v3, v6));
			v5 = _m_por(_m_pslld(v9, _mm_cvtsi32_si64(3u)), _m_psrld(v9, _mm_cvtsi32_si64(29u)));
			++v3;
			--v4;
		} while (v4);
		result = _mm_cvtsi64_si32(_m_pmaddwd(v5, _m_psrlq(v5, _mm_cvtsi32_si64(32u))));
		_m_empty();
	}
	else
	{
		result = 0;
	}

	return result;
}

//解密算法
static void sub_4E182C_uncrypt(unsigned int key, unsigned char *data, unsigned int len)
{
	unsigned int v2;
	__m64 *v3;
	__m64 v4;
	__m64 v5;
	__m64 v6;
	__m64 v7;
	__m64 v8;
	__m64 v9;

	if (len >> 3)
	{
		v2 = len >> 3;
		v3 = (__m64 *)data;
		v4 = _mm_cvtsi32_si64(0xA73C5F9D);
		v5 = _m_punpckldq(v4, v4);
		v6 = _mm_cvtsi32_si64(0xCE24F523);
		v7 = _m_punpckldq(v6, v6);
		v8 = _mm_cvtsi32_si64((key + len) ^ 0xFEC9753E);
		v9 = _m_punpckldq(v8, v8);
		do
		{
			v5 = _m_pxor(_m_paddd(v5, v7), v9);
			v9 = _m_pxor(*v3, v5);
			*v3 = v9;
			++v3;
			--v2;
		} while (v2);
		_m_empty();
	}
}

//加密算法
static void sub_4E182C_encrypt(unsigned int key, unsigned char *data, unsigned int len)
{
	unsigned int v2;
	__m64 *v3;
	__m64 v4;
	__m64 v5;
	__m64 v6;
	__m64 v7;
	__m64 v8;
	__m64 v9;
	__m64 v10;

	if (len >> 3)
	{
		v2 = len >> 3;
		v3 = (__m64 *)data;
		v4 = _mm_cvtsi32_si64(0xA73C5F9D);
		v5 = _m_punpckldq(v4, v4);
		v6 = _mm_cvtsi32_si64(0xCE24F523);
		v7 = _m_punpckldq(v6, v6);
		v8 = _mm_cvtsi32_si64((key + len) ^ 0xFEC9753E);
		v9 = _m_punpckldq(v8, v8);
		do
		{
			v5 = _m_pxor(_m_paddd(v5, v7), v9);
			v9 = _m_pxor(*v3, v5);

			v10 = *v3;
			*v3 = v9;
			v9 = v10;

			++v3;
			--v2;
		} while (v2);
		_m_empty();
	}
}

//加密/解密算法
static void sub_4E11C3_crypt(unsigned int key, unsigned char *data, unsigned int len)
{
	key = key ^ ((key >> 0x10) & 0x0FFFF);
	key = (key ^ (len ^ 0x3E13) ^ (len * len)) & 0x0FFFF;
	if ((int)(len - 1) >= 0)
	{
		unsigned int v1 = 0;
		unsigned int v2 = key;
		unsigned short *v3 = (unsigned short *)data;
		do {
			v2 = (v1 + (v2 << 3) + key) & 0xffff;
			*v3 = *v3 ^ v2;
			v3++;
			++v1;
			--len;
		} while (len);
	}
}

//创建key
static void sub_4E8E28_createkey(unsigned int *outkey, unsigned int keylen, unsigned int key)
{
	unsigned int v4;
	unsigned int v5;
	unsigned int *v6;

	v4 = key;
	v5 = keylen;
	v6 = outkey;
	do
	{
		v4 = (2381452337u * (unsigned __int64)(v4 ^ 0x8DF21431) >> 32) + -1913514959 * (v4 ^ 0x8DF21431);
		*v6 = v4;
		++v6;
		--v5;
	} while (v5);
}

//创建key
static void sub_4E8E64_createkey(unsigned int *outkey, unsigned int keylen, unsigned short *name, unsigned int namelen, unsigned int datalen, unsigned int key)
{
	unsigned int v3;
	unsigned int v4;
	unsigned int v5;
	unsigned int v6;
	unsigned int v7;
	unsigned int v10;

	v3 = 8779058;
	v4 = 3405377;

	v5 = namelen;
	if ((int)(v5 - 1) >= 0)
	{
		v6 = v5;
		v7 = 0;
		do
		{
			v3 += *(unsigned short *)((unsigned char *)name + 2 * (v7 + 1) - 2) << (v7 & 7);
			v4 ^= v3;
			++v7;
			--v6;
		} while (v6);
	}

	v10 = (key ^ (7 * (datalen & 0xFFFFFF) + datalen + v3 + (v3 ^ datalen ^ 0x8F32DC))) + v4;
	sub_4E8E28_createkey(outkey, keylen, 9 * (v10 & 0xFFFFFF));
}

//解密算法
static void sub_4E9014_uncrypt(unsigned char *data, unsigned int datalen, unsigned int *key)
{
	unsigned int v3;
	unsigned int v4;
	__m64 *v5;
	__m64 v6;
	__m64 v7;
	__m64 v8;
	unsigned char *v10;
	unsigned int v11;
	__m64 *v13;
	int v15;

	v15 = datalen >> 3;
	if (v15)
	{
		v10 = (unsigned char *)key;
		v13 = (__m64 *)data;
		v3 = v15;
		v11 = *(unsigned int *)&v10[52];
		v4 = 8 * (v11 & 0xF);
		v5 = v13;
		v6 = *(__m64 *)&v10[24];
		do
		{
			v7 = _m_paddd(_m_pxor(v6, *(__m64 *)&v10[v4]), *(__m64 *)&v10[v4]);
			v8 = _m_pxor(*v5, v7);

			*v5 = v8;
			v6 = _m_paddw(_m_pslld(_m_pxor(_m_paddb(v7, v8), v8), _mm_cvtsi32_si64(1u)), v8);
			++v5;

			v4 = (v4 + 8) & 0x7F;
			--v3;
		} while (v3);
		_m_empty();
	}
}

//加密算法
static void sub_4E9014_encrypt(unsigned char *data, unsigned int datalen, unsigned int *key)
{
	unsigned int v3;
	unsigned int v4;
	__m64 *v5;
	__m64 v6;
	__m64 v7;
	__m64 v8;
	unsigned char *v10;
	unsigned int v11;
	__m64 *v13;
	int v15;
	__m64 v16;

	v15 = datalen >> 3;
	if (v15)
	{
		v10 = (unsigned char *)key;
		v13 = (__m64 *)data;
		v3 = v15;
		v11 = *(unsigned int *)&v10[52];
		v4 = 8 * (v11 & 0xF);
		v5 = v13;
		v6 = *(__m64 *)&v10[24];
		do
		{
			v7 = _m_paddd(_m_pxor(v6, *(__m64 *)&v10[v4]), *(__m64 *)&v10[v4]);
			v8 = _m_pxor(*v5, v7);

			v16 = *v5;
			*v5 = v8;
			++v5;

			v6 = _m_paddw(_m_pslld(_m_pxor(_m_paddb(v7, v16), v16), _mm_cvtsi32_si64(1u)), v16);
			v4 = (v4 + 8) & 0x7F;
			--v3;
		} while (v3);
		_m_empty();
	}
}

//创建key
static void sub_4E90FC_createkey(unsigned int *outkey, unsigned int keylen, unsigned int key)
{
	unsigned int v4;
	unsigned int v5;
	unsigned int *v6;

	v4 = key;
	v5 = keylen;
	v6 = outkey;
	do
	{
		v4 = (2323117171u * (unsigned __int64)(v4 ^ 0x8A77F473) >> 32) + -1971850125 * (v4 ^ 0x8A77F473);
		*v6 = v4;
		++v6;
		--v5;
	} while (v5);
}

//创建key
static void sub_4E9138_createkey(unsigned int *outkey, unsigned int keylen, unsigned short *name, unsigned int namelen, unsigned int datalen, unsigned int key)
{
	unsigned int v3;
	unsigned int v4;
	unsigned int v5;
	unsigned int v6;
	unsigned int v7;
	unsigned int v10;

	v3 = 8845282;
	v4 = 4470769;

	v5 = namelen;
	if ((int)(v5 - 1) >= 0)
	{
		v6 = v5;
		v7 = 0;
		do
		{
			v3 += *(unsigned short *)((unsigned char *)name + 2 * (v7 + 1) - 2) << (v7 & 7);
			v4 ^= v3;
			++v7;
			--v6;
		} while (v6);
	}

	v10 = (v4 + (key ^ (13 * (datalen & 0xFFFFFF) + datalen + v3 + (v3 ^ datalen ^ 0x56E213))));
	sub_4E90FC_createkey(outkey, keylen, 13 * (v10 & 0xFFFFFF));
}

//解密算法
static void sub_4E936D_uncrypt(unsigned char *data, unsigned int datalen, unsigned int *key, unsigned int *key2)
{
	unsigned int v2;
	unsigned int v3;
	unsigned char *v5;
	__m64 *v4;
	__m64 v6;
	__m64 v7;
	__m64 v8;
	__m64 v9;
	unsigned char *v11;
	unsigned int v13;
	unsigned char *v14;
	__m64 *v16;
	unsigned int v18;

	v18 = datalen >> 3;
	if (v18)
	{
		v11 = (unsigned char *)key;
		v16 = (__m64 *)data;
		v14 = (unsigned char *)key2;

		v13 = *(unsigned int *)&v11[32];
		v2 = v18;
		v3 = 8 * (v13 & 0xD);
		v4 = v16;
		v5 = v14;
		v6 = *(__m64 *)&v11[24];
		do
		{
			v7 = _m_pxor(*(__m64 *)&v11[8 * (v3 & 0xF)], *(__m64 *)&v5[8 * (v3 & 0x7F)]);
			v8 = _m_paddd(_m_pxor(v6, v7), v7);
			v9 = _m_pxor(*v4, v8);

			*v4 = v9;
			v6 = _m_paddw(_m_pslld(_m_pxor(_m_paddb(v8, v9), v9), _mm_cvtsi32_si64(1u)), v9);
			++v4;

			v3 = (v3 + 1) & 0x7F;
			--v2;
		} while (v2);
		_m_empty();
	}
}

//加密算法
static void sub_4E936D_encrypt(unsigned char *data, unsigned int datalen, unsigned int *key, unsigned int *key2)
{
	unsigned int v2;
	unsigned int v3;
	unsigned char *v5;
	__m64 *v4;
	__m64 v6;
	__m64 v7;
	__m64 v8;
	__m64 v9;
	unsigned char *v11;
	unsigned int v13;
	unsigned char *v14;
	__m64 *v16;
	unsigned int v18;
	__m64 v19;

	v18 = datalen >> 3;
	if (v18)
	{
		v11 = (unsigned char *)key;
		v16 = (__m64 *)data;
		v14 = (unsigned char *)key2;

		v13 = *(unsigned int *)&v11[32];
		v2 = v18;
		v3 = 8 * (v13 & 0xD);
		v4 = v16;
		v5 = v14;
		v6 = *(__m64 *)&v11[24];
		do
		{
			v7 = _m_pxor(*(__m64 *)&v11[8 * (v3 & 0xF)], *(__m64 *)&v5[8 * (v3 & 0x7F)]);
			v8 = _m_paddd(_m_pxor(v6, v7), v7);
			v9 = _m_pxor(*v4, v8);

			v19 = *v4;
			*v4 = v9;
			++v4;

			v6 = _m_paddw(_m_pslld(_m_pxor(_m_paddb(v8, v19), v19), _mm_cvtsi32_si64(1u)), v19);
			v3 = (v3 + 1) & 0x7F;
			--v2;
		} while (v2);
		_m_empty();
	}
}

//创建key
static void sub_4E9ECC_createkey(unsigned int *outkey, unsigned char *data, unsigned int datalen)
{
	unsigned int v4;
	unsigned int *v5;
	unsigned int v6;
	unsigned int v8;
	unsigned char *v9;
	unsigned int v10;
	unsigned char v11;
	unsigned int v13;

	v5 = outkey;
	v6 = 0;
	do
	{
		if (v6 % 3)
		{
			v4 = (v6 + 7) * -((int)v6 + 3);
			*v5 = v4;
		}
		else
		{
			v4 = (v6 + 7) * (v6 + 3);
			*v5 = v4;
		}
		++v5;
		++v6;
	}
	while (v6 != 256);

	v8 = *(unsigned char *)(data + 49) % 0x49u + 128;
	v13 = *(unsigned char *)(data + 79) % 7u + 7;
	v9 = (unsigned char *)outkey;
	v10 = 1024;
	do
	{
		v8 = (unsigned int)(v13 + v8) % datalen;
		v11 = *(unsigned char *)(v8 + data);
		*v9++ ^= v11;
		--v10;
	} while (v10);
}

//计算hash
int sub_4E3178_get_hash(wchar_t *name, unsigned int namelen)
{
	unsigned int v2;
	unsigned int v3;
	unsigned int v4;
	unsigned char *v10;

	v2 = 0;
	v3 = namelen;
	v10 = (unsigned char *)name;
	if (v3 > 0)
	{
		v4 = 1;
		do
		{
			v2 = ((*(unsigned short *)(v10 + 2 * v4 - 2) << (v4 & 7)) + v2) & 0x3FFFFFFF;
			++v4;
			--v3;
		} while (v3);
	}

	return v2;
}

//得到hashver-data位置
int sub_4E760C_getpos(int hash, int count)
{
	unsigned int v3;
	int v4;

	v3 = hash;
	v4 = (unsigned short)v3 + (v3 >> 8) + (v3 >> 16);
	return v4 % count;
}

////////////反编译出来的代码-结束//////////////////


////////////来自 exfp3 部分代码-开始//////////////////
static const unsigned char BPE_FLAG_SHORT_LENGTH = 0x01;

typedef struct bpe_hdr_t {
	unsigned char signature[4]; // "1PC\xFF"
	unsigned int  flags;
	unsigned int  original_length;
} bpe_hdr_t;

typedef struct bpe_pair_t {
	unsigned char left;
	unsigned char right;
} bpe_pair_t;

// byte pair encoding algorithm
static void unbpe(unsigned char* buff, unsigned int len,
	unsigned char* out_buff, unsigned int out_len)
{
	unsigned char* end = buff + len;

	bpe_hdr_t* hdr = (bpe_hdr_t*)buff;
	buff += sizeof(*hdr);

	bpe_pair_t    table[256];
	unsigned char stack[4096];
	unsigned int stack_len = 0;

	while (buff < end)
	{
		// Read/expand literal table
		for (unsigned int i = 0; i < 256;)
		{
			unsigned int c = *buff++;

			// Range of literals
			if (c > 127)
			{
				for (c -= 127; c > 0; c--, i++) {
					table[i].left = (unsigned char)i;
				}
			}

			// Pairs of {left, right} unless left is a literal
			for (c++; c > 0 && i < 256; c--, i++)
			{
				table[i].left = *buff++;
				if (i != table[i].left) {
					table[i].right = *buff++;
				}
			}
		}

		unsigned int block_len = 0;

		// This optional int length is the only difference from the BPE reference
		// implementation...
		if (hdr->flags & BPE_FLAG_SHORT_LENGTH) {
			block_len = *(unsigned short*)buff;
			buff += sizeof(unsigned short);
		}
		else {
			block_len = *(unsigned int *)buff;
			buff += sizeof(unsigned int);
		}

		// Decompress block
		while (block_len || stack_len)
		{
			unsigned char c = 0;

			if (stack_len) {
				c = stack[--stack_len];
			}
			else {
				c = *buff++;
				block_len--;
			}

			if (c == table[c].left) {
				*out_buff++ = c;
			}
			else {
				stack[stack_len++] = table[c].right;
				stack[stack_len++] = table[c].left;
			}
		}
	}
}

////////////来自 exfp3 部分代码-结束//////////////////

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

//链表成员
typedef struct _MLIST_ENTRY {
	struct _MLIST_ENTRY *back;
	struct _MLIST_ENTRY *next;
} MLIST_ENTRY;

//链表头
typedef struct _MLIST_HEADER {
	MLIST_ENTRY *head;
	int depth;
} MLIST_HEADER;

//链表初始化
void mlist_head_init(MLIST_HEADER *list_head)
{
	list_head->depth = 0;
	list_head->head = NULL;
}

//压入成员
int mlist_entry_push(MLIST_HEADER *list_head, MLIST_ENTRY *list_entry, int way)
{
	if (NULL == list_head->head) {
		list_entry->next = list_entry->back = list_entry;
		list_head->head = list_entry;
	}
	else
	{
		if (way < 0)
		{
			list_head->head->back->next = list_entry;
			list_entry->back = list_head->head->back;
			list_entry->next = list_head->head;
			list_head->head->back = list_entry;
			list_head->head = list_entry;
		}
		else
		{
			list_head->head->back->next = list_entry;
			list_entry->back = list_head->head->back;
			list_entry->next = list_head->head;
			list_head->head->back = list_entry;
		}
	}

	return ++list_head->depth;
}

//弹出成员
MLIST_ENTRY * mlist_entry_pop(MLIST_HEADER *list_head, int way)
{
	MLIST_ENTRY *ret = NULL;
	if (list_head->depth > 0)
	{
		if (way < 0)
		{
			ret = list_head->head;
			ret->back->next = ret->next;
			ret->next->back = ret->back;
			list_head->head = ret->next;
		}
		else
		{
			ret = list_head->head->back;
			ret->back->next = ret->next;
			list_head->head->back = ret->back;
		}

		--list_head->depth;
		if (0 == list_head->depth) {
			list_head->head = NULL;
		}
	}

	return ret;
}

//清空
MLIST_ENTRY * mlist_flush(MLIST_HEADER *list_head)
{
	MLIST_ENTRY *head;
	list_head->depth = 0;
	head = list_head->head;
	list_head->head = NULL;
	return head;
}

////////////下面是 解包 / 打包代码 //////////////////

//解包
static int file_unpack(wchar_t *in_file, wchar_t *out_path)
{
	wprintf(L"unpack file %s...\r\n", in_file);
	FILE *fp = _wfopen(in_file, L"rb");
	if (fp)
	{
		fseek(fp, 0, SEEK_END);
		unsigned int fplen = ftell(fp);

		PACKHEAD pack_head;
		fseek(fp, fplen - sizeof(pack_head), SEEK_SET);
		fread(&pack_head, 1, sizeof(pack_head), fp);
		if (0 == memcmp(pack_head.signature, "FilePackVer3.1\x00\x00", 16))
		{
			PACKKEY pack_key;
			fseek(fp, fplen - sizeof(pack_key) - sizeof(pack_head), SEEK_SET);
			fread(&pack_key, 1, sizeof(pack_key), fp);

			PACKHASH *pack_hash = (PACKHASH *)malloc(pack_key.hash_size);
			fseek(fp, fplen - sizeof(pack_key) - sizeof(pack_head) - pack_key.hash_size, SEEK_SET);
			fread(pack_hash, 1, pack_key.hash_size, fp);

			//解密hash结构内的数据
			unsigned int hash_datalen = pack_hash->data_size;
			unsigned char *hash_data = (unsigned char *)pack_hash + sizeof(PACKHASH);
			sub_4E182C_uncrypt(0x0428, hash_data, hash_datalen);

			//解压hash_data
			if (pack_hash->is_compressed)
			{
				unsigned int temp_len = ((bpe_hdr_t *)hash_data)->original_length;
				unsigned char *temp = (unsigned char *)malloc(temp_len);
				unbpe(hash_data, hash_datalen, temp, temp_len);

				free(hash_data);
				hash_datalen = temp_len;
				hash_data = temp;
			}

			//根据key算出解密用的值
			int key = sub_4E2578_gethash(pack_key.key, 256) & 0x0FFFFFFF;
			sub_4E182C_uncrypt(key, pack_key.signature, sizeof(pack_key.signature)); //解密
			if (0 == strncmp((char *)pack_key.signature, "8hr48uky,8ugi8ewra4g8d5vbf5hb5s6", 32))
			{
				unsigned int commkey[256];
				fseek(fp, pack_head.entry_offset, SEEK_SET);
				for (unsigned int i = 0; i < pack_head.entry_count; i++)
				{
					//取得文件名
					unsigned short namelen;
					fread(&namelen, 1, sizeof(namelen), fp);
					wchar_t *name = (wchar_t *)malloc(namelen * 2 + 2);
					fread(name, 1, namelen * 2, fp);
					name[namelen] = 0;

					//取文件信息
					PACKENTRY entry;
					fread(&entry, 1, sizeof(entry), fp);

					//解密文件名
					sub_4E11C3_crypt(key, (unsigned char *)name, namelen);
					wprintf(L"%s...", name);

					unsigned int cur_pos = ftell(fp);
					fseek(fp, entry.offset, SEEK_SET);

					//读取文件
					unsigned int datalen = entry.length;
					unsigned char *data = (unsigned char *)malloc(datalen);
					fread(data, 1, datalen, fp);

					//校验
					if (entry.hash == sub_4E2578_gethash(data, datalen))
					{
						if (entry.is_obfuscated > 0)
						{
							if (1 == entry.is_obfuscated)
							{
								//解密算法1
								unsigned int filekey[64];
								sub_4E8E64_createkey(filekey, 64, (unsigned short *)name, namelen, datalen, key);
								sub_4E9014_uncrypt(data, datalen, filekey);

								//特殊文件 pack_keyfile_kfueheish15538fa9or.key 算出一个key
								if (0 == wcsncmp(L"pack_keyfile_kfueheish15538fa9or.key", name, namelen)) {
									sub_4E9ECC_createkey(commkey, data, datalen);
								}
							}
							else if (2 == entry.is_obfuscated)
							{
								//解密算法2
								unsigned int filekey[64];
								sub_4E9138_createkey(filekey, 64, (unsigned short *)name, namelen, datalen, key);
								sub_4E936D_uncrypt(data, datalen, filekey, commkey);
							}
						}

						if (entry.is_compressed > 0)
						{
							//解压
							unsigned char *newdata = (unsigned char *)malloc(entry.original_length);
							unbpe(data, datalen, newdata, entry.original_length);
							datalen = entry.original_length;
							free(data); data = newdata;
						}

						//输出文件
						wchar_t filename[1024];
						wcscat(wcscat(wcscpy(filename, out_path), L"\\"), name);
						put_file(filename, data, datalen);
						wprintf(L"ok\r\n");
					}
					else
					{
						wprintf(L"err\r\n");
					}

					free(data);
					fseek(fp, cur_pos, SEEK_SET);
					free(name);
				}
			}

			free(pack_hash);
		}

		fclose(fp);
	}

	wprintf(L"unpack file end\r\n");
	return 0;
}

//打包时使用
typedef struct FILENAME_ENTRY {
	MLIST_ENTRY entry;
	wchar_t		*name;
	int			namelen;
	int			index;
	int			hash;
} FILENAME_ENTRY;

//打包
static void file_pack(wchar_t *in_path, wchar_t *out_file)
{
	wprintf(L"pack file %s...\r\n", out_file);
	FILE *fp = _wfopen(out_file, L"wb");
	if (fp)
	{
		PACKHEAD pack_head;
		memset(&pack_head, 0, sizeof(pack_head));
		memcpy(pack_head.signature, "FilePackVer3.1", 14);

		PACKKEY pack_key;
		memset(&pack_key, 0, sizeof(pack_key));

		//随机key
		srand((unsigned int)time(0));
		for (int i = 0; i < 256; i++) {
			pack_key.key[i] = rand() % 255;
		}

		//key头标识
		int key = sub_4E2578_gethash(pack_key.key, 256) & 0x0FFFFFFF;
		memcpy(pack_key.signature, "8hr48uky,8ugi8ewra4g8d5vbf5hb5s6", 32);
		sub_4E182C_encrypt(key, pack_key.signature, sizeof(pack_key.signature)); //加密

		int len = 0;
		wchar_t **arr = NULL;
		enum_file(in_path, L"*.*", &arr, &len);

		if (arr)
		{
			int i = 0, j = 0;
			wchar_t **arr2 = (wchar_t **)malloc(len * sizeof(wchar_t *));
			for (i = 0; i < len; i++)
			{
				if (0 == wcscmp(arr[i] + wcslen(in_path) + 1, L"pack_keyfile_kfueheish15538fa9or.key")) {
					arr2[j++] = arr[i];
					break;
				}
			}
			for (i = 0; i < len; i++)
			{
				if (0 != wcscmp(arr[i] + wcslen(in_path) + 1, L"pack_keyfile_kfueheish15538fa9or.key")) {
					arr2[j++] = arr[i];
				}
			}

			//数量
			int count = 256; 
			MLIST_HEADER *list = (MLIST_HEADER *)malloc(count * sizeof(MLIST_HEADER));
			for (i = 0; i < count; i++) mlist_head_init(&list[i]);
			
			//文件名hash
			for (i = 0; i < len; i++)
			{
				FILENAME_ENTRY *entry = (FILENAME_ENTRY *)malloc(sizeof(FILENAME_ENTRY));

				entry->name = arr2[i] + wcslen(in_path) + 1;
				entry->namelen = (unsigned int)wcslen(entry->name);
				entry->hash = sub_4E3178_get_hash(entry->name, entry->namelen);
				entry->index = i;

				j = sub_4E760C_getpos(entry->hash, count);
				mlist_entry_push(&list[j], (MLIST_ENTRY *)entry, 1);
			}

			//生成 hash-data
			int hashdata_offset = 0;
			unsigned char *hashdata = (unsigned char *)malloc(hashdata_offset);
			for (i = 0; i < count; i++)
			{
				hashdata = (unsigned char *)realloc(hashdata, hashdata_offset + sizeof(int));
				*(unsigned int *)(hashdata + hashdata_offset) = list[i].depth;
				hashdata_offset += sizeof(int);

				while (1)
				{
					FILENAME_ENTRY *entry = (FILENAME_ENTRY *)mlist_entry_pop(&list[i], -1);
					if (!entry) break;

					hashdata = (unsigned char *)realloc(hashdata, hashdata_offset + sizeof(short) + entry->namelen * 2 + sizeof(long long) + sizeof(int));
					*(unsigned short *)(hashdata + hashdata_offset) = (unsigned short)entry->namelen;
					hashdata_offset += sizeof(short);

					memcpy(hashdata + hashdata_offset, entry->name, entry->namelen * 2);
					hashdata_offset += entry->namelen * 2;

					*(unsigned long long *)(hashdata + hashdata_offset) = entry->index * sizeof(int);
					hashdata_offset += sizeof(long long);

					*(unsigned int *)(hashdata + hashdata_offset) = entry->hash;
					hashdata_offset += sizeof(int);

					free(entry);
				}
			}

			//索引
			hashdata = (unsigned char *)realloc(hashdata, hashdata_offset + sizeof(int) * len);
			for (i = 0; i < len; i++)
			{
				*(unsigned int *)(hashdata + hashdata_offset + i * sizeof(int)) = i;
			}

			hashdata_offset += sizeof(int) * len;
			free(list);

			//加密hashdata
			sub_4E182C_encrypt(0x0428, hashdata, hashdata_offset);

			PACKHASH pack_hash;
			memset(&pack_hash, 0, sizeof(pack_hash));
			memcpy(pack_hash.signature, "HashVer1.4", 10);

			pack_hash.table_size = count;
			pack_hash.file_count = len;
			pack_hash.index_size = len * 4;
			pack_hash.data_size = hashdata_offset;
			pack_hash.is_compressed = 0;

			pack_head.entry_count = len;
			pack_key.hash_size = pack_hash.data_size + sizeof(pack_hash);

			PACKENTRY *entry = (PACKENTRY *)malloc(sizeof(PACKENTRY) * pack_head.entry_count);
			unsigned int commkey[256];

			//文件数据
			for (i = 0; i < len; i++)
			{
				//输出文件名
				wprintf(L"%s\r\n", arr2[i] + wcslen(in_path) + 1);

				//读文件
				unsigned int flen = 0;
				unsigned char *fdata = get_file(arr2[i], &flen);
				memset(&entry[i], 0, sizeof(entry[i]));
				unsigned int filekey[64];

				if (0 == i)
				{
					sub_4E9ECC_createkey(commkey, fdata, flen);
					sub_4E8E64_createkey(filekey, 64, (unsigned short *)L"pack_keyfile_kfueheish15538fa9or.key", 36, flen, key);
					sub_4E9014_encrypt(fdata, flen, filekey);
					entry[i].is_obfuscated = 1;
				}
				else
				{
					wchar_t *name = arr2[i] + wcslen(in_path) + 1;
					sub_4E9138_createkey(filekey, 64, (unsigned short *)name, wcslen(name), flen, key);
					sub_4E936D_encrypt(fdata, flen, filekey, commkey);
					entry[i].is_obfuscated = 2;
				}
				
				entry[i].offset = ftell(fp);
				entry[i].hash = sub_4E2578_gethash(fdata, flen);
				entry[i].length = entry[i].original_length = flen;
				entry[i].is_compressed = 0;
				
				fwrite(fdata, 1, flen, fp);
				free(fdata);
			}

			//文件信息
			pack_head.entry_offset = ftell(fp);
			for (int i = 0; i < len; i++)
			{
				wchar_t *name = arr2[i] + wcslen(in_path) + 1;
				unsigned short namelen = (unsigned short)wcslen(name);

				sub_4E11C3_crypt(key, (unsigned char *)name, namelen);
				fwrite(&namelen, 1, sizeof(namelen), fp);
				fwrite(name, 1, namelen * 2, fp);
				sub_4E11C3_crypt(key, (unsigned char *)name, namelen);

				fwrite(&entry[i], 1, sizeof(entry[i]), fp);
			}

			//hashver
			fwrite(&pack_hash, 1, sizeof(pack_hash), fp);
			fwrite(hashdata, 1, hashdata_offset, fp);
			
			//key
			fwrite(&pack_key, 1, sizeof(pack_key), fp);

			//头
			fwrite(&pack_head, 1, sizeof(pack_head), fp);

			//释放内存
			free(entry);
			free(hashdata);

			for (i = 0; i < len; i++) {
				free(arr[i]);
			}

			free(arr2);
			free(arr);
		}

		fclose(fp);
	}

	wprintf(L"pack file end\r\n");
}

int _tmain(int argc, TCHAR* argv[])
{
	_wsetlocale(LC_ALL, L"chs");
	
	if (1 == argc)
	{
		wprintf(L"美少女万華鏡 罪と罰の少女 [filepack 3.1] enpack / unpack tool\r\n\r\n");

		wprintf(L"help \r\n");
		wprintf(L"filepack31 enpack ./data0 ./data0.pack\r\n");
		wprintf(L"filepack31 unpack ./data0.pack ./data0\r\n");
	}
	else if(4 == argc)
	{
		if (0 == wcscmp(L"enpack", argv[1])) {
			file_pack(argv[2], argv[3]);
		}
		else if (0 == wcscmp(L"unpack", argv[1])) {
			file_unpack(argv[2], argv[3]);
		}
	}
	
    return 0;
}
