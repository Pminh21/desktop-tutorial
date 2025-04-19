#pragma once

#include <Windows.h>

#include <Include/ProcessInject_scanner_type.h>

#ifndef PROINJECT_STATIC_LIB
	#ifdef PROINJECT_EXPORT
		#define PROINJECT_API _declspec(dllexport)
		#else
			#define PROINJECT_API _declspec(dllimport)
	#endif // PROINJECT_EXPORT
	#else
		#define PROINJECT_API
#endif // PROINJECT_STATIC_LIB

#define PROINJECT_API_FUNC PROINJECT_API  __cdecl

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus
void PROINJECT_API_FUNC PROINJECT_help(void);

#ifdef __cplusplus
typedef ProcessInject_scanner::t_report PROINJECT_report;
typedef ProcessInject_scanner::t_params PROINJECT_params;
typedef ProcessInject_scanner::t_report_type PROINJECT_report_type;
#else
typedef t_report PROINJECT_report;
typedef t_params PROINJECT_params;
typedef :t_report_type PROINJECT_report_type;
#endif //__cplusplus

// PROINJECT_scan theo cấu trúc struct của t_params. trả về báo cáo dạng t_report
PROINJECT_report PROINJECT_API_FUNC PROINJECT_scan(IN const PROINJECT_params &args);

// PROINJECT_scan theo cấu trúc struct của t_params. trả về báo cáo dạng t_report, Cho phép cung cấp buffer để nhận báo cáo đầy đủ dạng JSON.
PROINJECT_report PROINJECT_API_FUNC PROINJECT_scan_ex(IN const PROINJECT_params &args, IN const PROINJECT_report_type report_type, OUT char* json_buf, IN size_t json_buf_size, OUT size_t *buf_needed_size );

#ifdef  __cplusplus
};
#endif //  __cplusplus
