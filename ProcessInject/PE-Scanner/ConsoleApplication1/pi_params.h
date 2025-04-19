#pragma once

#include <include/ProcessInject_api.h>

#include <string>
#include <set>

#define TIME_UNDEFINED LONGLONG(-1)
#define PROINJECT_DEFAULT_DIR "Process_inject.dumps"

enum t_cache_mode
{
	CACHE_DISABLED = 0,  // disable cache
	CACHE_AUTO,			// tự động phát hiện cache được bật
	CACHE_ENABLE,		// cache luôn bật
	CACHE_MODES_COUNT
};

// tham số truyền vào công cụ

typedef struct pi_params
{
public:
	std::string out_dir;
	bool unique_dir;
	bool loop_scanning;
	bool etw_scan;
	bool suspend_suspicious;
	bool kill_suspicious;
	bool quiet;
	bool log;
	bool json_output;
	LONGLONG ptimes;
	t_cache_mode cache_mode;
	std::set<std::wstring> names_list;
	std::set<long> pids_list;
	std::set<std::wstring> ignored_names_list;
	ProcessInject_scanner::t_params ProcessInject_args;

	void init();
	pi_params& operator=(const pi_params& other);
}t_pi_params;