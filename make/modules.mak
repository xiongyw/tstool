#
# Note: 'modules' contains a list of absolute directory 
# paths, all the source files under that directory is
# considered belongs to that module 
#

#-----------------------------------------
#  modules, a simple variable
#-----------------------------------------
modules := $(PKG_ROOT)/src
#modules += 




#-----------------------------------------
# include_dirs, a simple variable
#-----------------------------------------

include_dirs := $(modules)
include_dirs += $(PKG_ROOT)   # config.h
