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
		/* Dump trạng thái bộ nhớ nguyên trạng của module, không biến đổi.
		Kết quả là một bản sao chính xác của module như nó tồn tại trong bộ nhớ ảo.
   		Giữ nguyên tất cả các sửa đổi, patch, hook, shellcode, v.v.
   		Thích hợp cho phân tích chi tiết nhưng file dump thường không thể chạy trực tiếp. */
		PE_DUMP_UNMAP,
		/* Chuyển đổi module từ cấu trúc bộ nhớ ảo về định dạng file PE thô.
		Sử dụng thông tin header của các section raw để tái cấu trúc file.
		Cố gắng khôi phục lại cấu trúc file PE ban đầu từ bộ nhớ.
		Có thể tạo được file PE có khả năng chạy được nhưng một số sửa đổi có thể bị mất.*/
		PE_DUMP_REALIGN,
		/* Phương pháp nâng cao để tạo file PE từ bộ nhớ.
		Căn chỉnh lại header của các section nguyên bản để khớp với cấu trúc trong bộ nhớ.
		Đặc biệt hữu ích cho các module đã bị giải nén (unpacked) trong bộ nhớ.
		Cố gắng tạo file PE có thể thực thi được mà vẫn giữ được các đặc điểm đã biến đổi.
		Lý tưởng cho việc phân tích malware sử dụng packer như UPX.*/
		PE_DUMP_MODES_COUNT
	};

	enum struct t_imprec_mode
	{
		PE_IMPREC_NONE = 0,
		PE_IMPREC_AUTO,
		PE_IMPREC_UNERASE,
		PE_IMPREC_REBUILD0,
		PE_IMPREC_REBUILD1,
		PE_IMPREC_REBUILD2,
		PE_IMPREC_MODES_COUNT
	};

	enum struct t_iat_scan_mode
	{
		PE_IATS_NONE = 0,
		PE_IAT_CLEAN_SYS_FILTRERED,
		PE_IAT_ALL_SYS_FILTERED,
		PE_IAT_UNFILTERED,
		PE_IAT_MODES_COUNT,
	};

	enum struct t_dotnet_policy
	{
		PE_DNET_NONE = 0,
		PE_DNET_SKIP_MAPPING = 1, // bỏ qua sự không khớp mapping trong module .net
		PE_DNET_SKIP_SHC, // bỏ qua shellcodes (trong tat ca module process quản lý)
		PE_DNET_SKIP_HOOK, // bỏ qua hooked (trong tat ca module process quản lý)
		PE_DNET_SKIP_ALL, // bỏ qua tất cả mapping, hooks, shellcode trong module process quản lý
		PE_DNET_SKIP_COUNT
	};

	enum struct t_data_scan_mode
	{
		PE_DATA_NO_SCAN = 0,
		PE_DATA_SCAN_DOTNET, // scan data .net apllication
		PE_DATA_SCAN_NO_DEP, //	scan data no dep hoac .net apllication
		PE_DATA_SCAN_ALWAYS, // scan vo dieu kien
		PE_DATA_SCAN_INACCESSIBLE, // scan data vo dieu kien, va cac trang khong the truy cap duoc
		PE_DATA_SCAN_INACCESSIBLE, // scan cac trang khong the truy cap duoc
		PE_DATA_COUNT
	};

	enum struct t_json_level
	{
		JSON_BASIC = 0, // BASIC
		JSON_DETAILS = 1, //
	};
}