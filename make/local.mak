#
# this is a template for local makefile to put
# under each module's folder, for excluding some
# sources from compiling/linking
#
# note that the variable name "local_exclude" is 
# hard-coded and referenced by "marco.mak"
#
local_exclude := shell.c
local_exclude += misc.c
