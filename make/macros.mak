# ------------------------------------------------------------------------
# these are user defined macros, which only use parameters to
# pass in input data, for making it as modular as possible. ([1] pp86-87)
#
# so usually these macros need no customization.
# ------------------------------------------------------------------------

# get objects path from sources path
# $(call srcs-to-objs,abs_srcs,out_root,pkg_root)
define srcs-to-objs 
    $(addprefix $2/, \
    $(patsubst $3/%,%,\
    $(patsubst %.cpp,%.o,$(filter %.cpp,$1)) \
    $(patsubst %.c,%.o,$(filter %.c,$1))     \
    $(patsubst %.S,%.o,$(filter %.S,$1)))) 
endef

# --------------------------------------
# $(call module-to-lib,module_path,out_root,pkg_root)
define module-to-lib
    $(addprefix $2/,$(patsubst $3/%,%/$(notdir $1).a,$1))
endef
    
# --------------------------------------
# generate rules for each module in the module list
# $(call all-module-rules,module_dir_list,out_root,pkg_root,src_name,lib_name,local_mak)
define all-module-rules
    $(eval $(foreach module,$1,$(call one-module-rules,$(module),$2,$3,$4,$5,$6)))
endef

# Insert (by eval) rules for each source of a module, and add the source
# and module lib to specified variable.
#
# If there is a 'local.mk' under the module directory, also
# read that (-include), and the 'local.mk' can define 'local_exclude"
# to list names of source files to be excluded in the compilation.
#
# Notes about $$ ([1] p84): the argument to eval is expanded twice: once when make 
# prepares the argument list for eval, and once again by eval.
#
# If using a single eval call to encapsulate multiple lines, the temp variables are
# expanded at arguments preparation time "at once" (not sequentially), so if there are
# dependencies among those temp variables, the result will be not expected.
#
# The solution are, depending on the use case:
#  - calling eval separately for each line/rule
#  - not use temp variables
#  - defer the expansion by using double dollars $$
#
# $(call one-module-rules,module_root_path,out_root,pkg_root,src_name,lib_name,local_mak)
define one-module-rules
    $(eval -include $1/$6)
    $(eval module_src := $(wildcard $1/*.c) $(wildcard $1/*.cpp) $(wildcard $1/*.S))
    $(eval local_exclude := $(addprefix $1/,$(local_exclude)))
    $(eval module_src := $(filter-out $(local_exclude),$(module_src)))
    $(eval module_obj := $(call srcs-to-objs,$(module_src),$2,$3))
    $(eval module_lib := $(call module-to-lib,$1,$2,$3))

	$(eval    
           $4 += $(module_src)
           $5 += $(module_lib)

           $(module_lib): $(module_obj)
	           $(QUIET)$(AR) rv $$@ $$^
     )
endef


# --------------------------------------
# $(call compile-rules,src_list,out_root,pkg_root)
define compile-rules
    $(eval $(foreach f,$1,$(call one-compile-rule,$(call srcs-to-objs,$(f),$2,$3),$(f))))
endef

# generate rules for each source file. 
# Note: we choose the "The Hard Way" ([1] pp144-148) to separate the depends/objects from the source,
#   this way we do not rely on gmake's built-in rules, but explicitly specify rules for each of our
#   source; also note that the dependencies are generated at the same time when objects are generated,
#   i.e., in "Tromey's Way" ([1], pp150-154, with small variance). 
#   the net result is that we do not have pattern rules but all explicit rules which are auto-generated.
#
# Also note that $(CC), $(CFLAGS) and $(CPPFLAGS) expansion are deferred by $$ ([1], p84). This allow altering them
#   in the scenario when used as target-specfic variables ([1], p50). 
#
# $(call one-compile-rule,obj,src)
define one-compile-rule
    $(eval #tmp_obj := $1
           #tmp_src := $2
           #tmp_dep := $(patsubst %.o,%.d,$1)

           $1: $2
	           $$(info #)
	           $$(info # Building $1 ... )
	           $$(QUIET)$$(CC) -MM  -MF $(patsubst %.o,%.d,$1) -MP -MT $$@ $$(CFLAGS) $$(CPPFLAGS) $$<
	           $$(QUIET)$$(CC) $$(CFLAGS) $$(CPPFLAGS) -o $$@ $$<
     )
endef
