# ---------------------------------------------------------------------------------------
# non-recursive make project 
#
# created(bruin, 2011-11-28)
# last updated: 2015-06-09
#
# reference: 
#   [1] http://oreilly.com/catalog/make3/book/index.csp "Managing Projects with GNU Make", 3rd, Robert Mecklenburg
#   [2] http://aegis.sf.net/auug97.pdf "Recursive Make Considered Harmful", Peter Miller
# ---------------------------------------------------------------------------------------


# --------------------------------------
# assumptions and goals
# --------------------------------------
# assumptions:
#   1. only use GNU Make under Linux environment (can support Windows if toolchain and gmake.exe
#      are available for Windows)
#   2. source files may have the same name (in different directories)
#   3. source tree is clean, i.e., no extra sources, no local makefiles.
#   4. source are either C or C++ with the following suffix: .h, .c, .cpp
#   5. 3rd party release is in the form of binary archives (.a) and appropriate headers (.h)
# 
# goals:
#   1. non-recursive
#   2. separating output from source tree
#   3. dependency generation
#   4. override built-in rules
#   5. using 'local.mk' in subdirectories to override root Makefile
#   6. misc: support jobs, help, silent/verbose, etc
# --------------------------------------

# --------------------------------------------------------------------
# variable naming conventions ([1] pp41-42)
# --------------------------------------------------------------------
# - variables representing constants a user might want to customize
#   on the command line or in the environ are written in all uppercase, 
#   with underscore as word-separator. e.g., OUT_ROOT
# - variables that appear only in makefile are all lowercase with words
#   separated by underscore. e.g., module_src
# - macro/function names are all small case with words separated 
#   by dash. e.g., compile-rules
# - both varialbes and macro/function calls are referenced by parenthesis: $()
# --------------------------------------------------------------------

# --------------------------------------------------------------------
# how it works (overview)
# --------------------------------------------------------------------
# 1. "module.mak":
#    - lists all module directories into a simple variable "modules";
#    - lists all include directories into a simple variable "include_dirs".
# 2. macro "all-module-rules" takes "modules" variable, and: 
#    - scans all source files under each module, excluding sources 
#      specified in local makefile of each module, resulting in a simple
#      variable "sources" which lists all source files;
#    - gives a library name for each module, resulting in a simple variable 
#      "libraries" which lists all libraries;
#    - creates rules for generating each library.
# 3. macro "compile-rule" takes "sources", and:
#    - generates compiling rules for each source file, the command part
#      of the rule (rule recipe) generates both obj and depend file, the
#      latter is -included if already generated
# 
# so roughly:
#
# 1. module.mak -> $(modules), $(include_dirs)  
# 2. $(modules) -> $(sources), $(libraries)
# 3. $(sources) -> rules for generating $(objects) & $(depends)
# 
# note that $(objects) and $(depends) are recursive variables, meaning
# that they are not expanded until it's used (in the second phase after
# the depend graph are built).
# --------------------------------------------------------------------



# --------------------------------------
# Remove all built-in rules.
# --------------------------------------
#
#.SUFFIXES:
#
#ifeq ($(filter "r",$(MAKEFLAGS)),)
#	MAKEFLAGS += r
#endif
# --------------------------------------


### -------------------------------------------------------------
### --         determine the build platform           
### -------------------------------------------------------------
ifdef ComSpec
	WINDOWS := 1
else
	ifeq ($(shell uname), Linux)
		LINUX := 1
	else
	    $(error Host platform is not supported!)   
	endif
endif


### -------------------------------------------------------------
### --   compiler and other tools
### -------------------------------------------------------------

ifdef WINDOWS
	$(error Host platform is not supported!)   
else
	CC     := gcc
	CP     := cp
	MD     := mkdir -p
	RM     := rm -rf
	ECHO   := echo
endif

### -------------------------------------------------------------
### --  verbose: make V=1 xxx
### -------------------------------------------------------------
ifndef V
	QUIET := @
endif

# --------------------------------------
# these are simple variables
# --------------------------------------

#
# use absolute paths
#
# PKG_ROOT is use to "mask out" the relative path of each source file;
# The relative path of each source is appended to OUT_ROOT to form 
# the absolute path for it's corresponding object file.
#
PKG_ROOT   := $(shell pwd)/..
OUT_ROOT   := $(shell pwd)/out
ifeq "$(MAKECMDGOALS)" "debug"
  OUT_ROOT := $(OUT_ROOT)/debug
endif

executable := $(OUT_ROOT)/tstool
sources    :=
libraries  := 


# ##########################################
# these are macros, usually no customization
# ##########################################
include macros.mak


# --------------------------------------
# all sources and include directories
# --------------------------------------
include modules.mak  

# --------------------------------------
# compiling & linking options
# --------------------------------------
include options.mak



# --------------------------------------
# output directories
# --------------------------------------
ifdef WINDOWS
	out_dirs := $(subst /,\,$(addprefix $(OUT_ROOT)/,$(patsubst $(PKG_ROOT)/%,%,$(modules))))
else
	out_dirs := $(addprefix $(OUT_ROOT)/,$(patsubst $(PKG_ROOT)/%,%,$(modules)))
endif




# --------------------------------------
# these are recursive variables
# --------------------------------------
objects = $(call srcs-to-objs, $(sources),$(OUT_ROOT),$(PKG_ROOT))
depends = $(patsubst %.o,%.d,$(objects))



# This is to prevent gmake treats the first target (appears when
# generate module rules) as the default target
all:

# --------------------------------------
# here goes the bulk part of our rules! 
# --------------------------------------
$(call all-module-rules,$(modules),$(OUT_ROOT),$(PKG_ROOT),sources,libraries,local.mak)
$(call compile-rules,$(sources),$(OUT_ROOT),$(PKG_ROOT))




# --------------------------------------
#  targets, arranged in top-down order
# --------------------------------------


#
# Tells make that the following targets do not represent files
# (and make treats phony targets as always out of date).
#
.PHONY: all debug clean help


#
# There is no command for this phony target, thus this phony target 
# just serves as an improvement of "User Interface" ([1] p15)
#
all: CFLAGS += -O2
all: $(out_dirs) $(executable)

debug: CFLAGS += -O0 -g -ggdb
debug: $(out_dirs) $(executable)


$(out_dirs):
	$(MD) $@

$(executable): $(objects)
	$(info #)
	$(info # Linking $@ ...)
	$(info #)
	$(QUIET)$(CC) $^ -o $@


#
# rules for $(objects) are generated above
#

clean:
ifdef WINDOWS
	$(RM) $(subst /,\,$(OUT_ROOT))
else
	$(RM) $(OUT_ROOT)
endif	

help:
	@$(ECHO) "targets available:"
	@$(ECHO) "    help          print help info"
	@$(ECHO) "    all           build app, this is the default target"
	@$(ECHO) "    clean         clean the build"



#
# ([1] pp56-57): make will try to include the $(depends) the 1st time;
# if not available, it will continoue (w/ warning because of '-' sign).
# Then if it notices there are rules for generating $(depends), so it will:
#  - evaluates those rules to get $(depends) generated, and
#  - starts from scratch by rereading the whole makefiles again.
#
# However, restarting make is not necessary ([1] pp150-152). So:
#  - $(depends) are generated at the same time as $(objects), 
#  - no rules for $(depends)
# thus make cannot find rules for $(depends), which will only be read
# by make the next time invoked.
#
ifneq "$(MAKECMDGOALS)" "clean"
  -include $(depends)
endif
