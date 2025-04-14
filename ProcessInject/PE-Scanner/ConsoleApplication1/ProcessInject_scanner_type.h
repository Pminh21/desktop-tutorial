#pragma once
#include <Windows.h>

#define ELEMENT_LIST_SEPARATOR ';'

namespace PrcessInject_scanner {
	
	// trạng thái trả về nếu scan bị lỗi
	const DWORD ERROR_SCAN_FAILURE = static_cast<DWORD>(-1);

	enum struct  t_output_filter
	{
		OUT_FULL = 0, // DUMP tất cả
		OUT_NO_DUMPS, // không dumps file fe đã bị chỉnh sửa, lưu lại báo cáo
		OUT_NO_DIR, // không dump cái gì
		OUT_FILTERS_COUNT
	};

	// Flags mô tả những gì được report

	enum struct t_results_filter
	{
		SHOW_NONE = 0, // Không report module
		SHOW_ERROR = 1, // report error
		SHOW_NOT_SUSPICIOUS = 3, // report NOT SUSPICIOUS
		SHOW_SUSPICIOUS = 4, // report SUSPICIOUS
		SHOW_SUSPICIOUS_AND_ERROR = SHOW_SUSPICIOUS | SHOW_ERROR,
		SHOW_SUCCESSFULL = SHOW_NOT_SUSPICIOUS | SHOW_SUSPICIOUS,
		SHOW_ALL = SHOW_ERROR | SHOW_NOT_SUSPICIOUS | SHOW_SUSPICIOUS,
	};

	enum struct t_shellcode_mode
	{
		SHELLCODE_NONE	= 0, // không detect shell code
		SHELLCODE_PATTERNS, // detect shellcodes bởi patterns
		SHELLCODE_STATS, // detect shellcodes bởi stats
		SHELLCODE_PATTERNS_OR_STATS, // detect patterns hoặc stats
		SHELLCODE_PATTERNS_AND_STATS, // detect patterns và stats
		SHELLCODE_COUNT
	};

	enum struct t_obfusc_mode
	{
		OBFSC_NONE = 0, // không phát hiện được obfuscated 
		OBFSC_STRONG_ENC, // phát hiện vùng bị mã hoá bởi thuật toán mã hoá mạnh (RSA,DES,...)
		OBFUSC_WEAK_ENC, // phát hiện vùng bị mã hoá bởi thuật toán mã hoá yếu (XOR,...)
		OBFUSC_ANY, // phát hiện cả vùng bị mã hoá mạnh và mã hoá yếu
		OBFUSC_COUNT
	};

	enum struct t_dump_mode
	{
		PE_DUMP_AUTO = 0, 
		PE_DUMP_VIRTUAL,
		PE_DUMP_UNMAP,
		PE_DUMP_REALIGN,
		PE_DUMP_MODES_COUNT
	};


}