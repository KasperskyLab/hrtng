#include <idc.idc>
//This script is designed to work in batch mode
//$idapath/idat -A -Sdump_strings.idc $1

static main()
{
  auto flags = get_inf_attr(INF_GENFLAGS);
  flags = flags & ~INFFL_AUTO;        // disable Autoanalysis
  set_inf_attr(INF_GENFLAGS, flags);
	//these functions are provided by hrtng plugin
  dump_strings();
  dump_names();
  dump_comments();
  
  qexit(0);                           // exit to OS, error code 0 - success
}
