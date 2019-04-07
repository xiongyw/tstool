

# this is for preprocessor
CPPFLAGS = $(addprefix -I ,$(include_dirs))
#
# source file level debug flags
#
CPPFLAGS += -DHAVE_CONFIG_H   # autotools compatible

# this is for make to find include files when checking dependencies. really needed?
#vpath %.h $(include_dirs)


# --------------------------------------
# compiler options
# --------------------------------------
# [-x c]: sources in C language
#CFLAGS := -x c 
# [-c]: compile only
CFLAGS = -c 

# [-Wall]: enable all warnings
CFLAGS += -Wall 
# [-Wstrict-prototypes]: warn if a function is declared or defined without specifying the argument types
CFLAGS += -Wstrict-prototypes 
# [-Winline]: warn if a function can not be inlined and it was declared as inline.
CFLAGS += -Winline 
# [-Wundef]: warn whenever an identifier which is not a macro is encountered in an ¡®#if¡¯
#   directive, outside of ¡®defined¡¯. Such identifiers are replaced with zero.
CFLAGS += -Wundef 

# [-g]: produce debug info, should be turn off for release build
#CFLAGS += -g  
# [-ggdb]: produce debugging information for use by GDB. 
#CFLAGS += -ggdb
# [-O2]: Optimize even more than [-O] or [-O1]. better turn it off for debug build.
#CFLAGS += -O2



#########################################################
# options used for linking: 
#########################################################
# libs/objs used for linking:
#LD_LIBS := 
