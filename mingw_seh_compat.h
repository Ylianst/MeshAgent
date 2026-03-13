/* MinGW SEH compatibility — stubs for __try/__except used only for crash logging */
#if defined(__GNUC__) && !defined(_MSC_VER)
#  define __try           if (1)
#  define __except(x)     else if (0)
#  define __finally
#  define __leave         do {} while (0)
#  ifndef GetExceptionCode
#    define GetExceptionCode()          ((DWORD)0)
#  endif
#  ifndef GetExceptionInformation
#    define GetExceptionInformation()   NULL
#  endif
#  ifndef EXCEPTION_EXECUTE_HANDLER
#    define EXCEPTION_EXECUTE_HANDLER  1
#  endif
#endif
