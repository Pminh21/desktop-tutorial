#include "pi_params.h"

void pi_params::init()
{
	// kh?i t?o l?i proinjject params
	memset(&ProcessInject_args, 0 ,sizeof(ProcessInject_scanner::t_params));
	out_dir = PROINJECT_DEFAULT_DIR;
	cache_mode = CACHE_AUTO;
	ProcessInject_args.quiet = true;
	ProcessInject_args.no_hooks = true;
	ProcessInject_args.results_filter = ProcessInject_scanner::t_results_filter::SHOW_SUSPICIOUS;
	loop_scanning = false;
	etw_scan = false;
	suspend_suspicious = false;
	kill_suspicious = false;
	quiet = true;
	log = false;
	json_output = false;
	unique_dir = false;
	ptimes = TIME_UNDEFINED;
}

pi_params& pi_params::operator=(const pi_params& other)
{
	// TODO: insert return statement here
}
