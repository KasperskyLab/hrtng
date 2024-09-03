
#ifdef _MSC_VER
#pragma warning(disable:4244; disable:4267; disable:4146; disable:4018)
#endif //_MSC_VER
#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wswitch"
#pragma GCC diagnostic ignored "-Wpedantic"
#pragma GCC diagnostic ignored "-Wvarargs"
#ifdef __MAC__
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif // __MAC__
#pragma GCC diagnostic push

//temporary fix for gcc 13.1.1 and IDA81
#include <cstdint>
#endif // __GNUC__
