APPNAME=app_hello_driver

INCDIR += -I./
LIBS +=

ifeq ('$(ARCH)', 'arm')
    BINDIR=./build/bin-arm
    OBJSDIR:=./build/objs-arm
else
    BINDIR=./build/bin
    OBJSDIR:=./build/objs
endif


#-include ./widgets/widgets.mk


CPPSRCS+=
CSRCS+= app_hello_driver.c

OBJS:= $(patsubst %.cpp, $(OBJSDIR)/%.o, $(CPPSRCS))
OBJS+= $(patsubst %.c, $(OBJSDIR)/%.o, $(CSRCS))

ifeq ('$(ARCH)', 'arm')
    CFLAGS += -DLINUX -DEGL_API_FB -DFREESCALE=1 -DDEBUG -D_DEBUG -D_GNU_SOURCE  -mfloat-abi=softfp -mfpu=neon -march=armv7-a -fPIC -O3 -fno-strict-aliasing -fno-optimize-sibling-calls  -g
    CFLAGS += -DQT_BUILD -DOPENGL_ES_2_0 -DFBT_USE_GZ_FILE=1
    LDFLAGS += -L$(ROOTFS)/usr/lib -L$(ROOTFS)/usr/local/lib -mfloat-abi=softfp -mfpu=neon -march=armv7-a
    INCDIR += -I$(ROOTFS)/usr/include -I$(ROOTFS)/usr/local/include -I$(ROOTFS)/usr/local/include/freetype2
    LIBS += -lGAL
    INSTALLDIR:= $(ROOTFS)/usr/sbin
    INSTALL_IMAGES_DIR:= $(ROOTFS)/opt/carmeter
    CC=$(CROSS_COMPILE)gcc
    CXX=$(CROSS_COMPILE)g++
else
    CFLAGS += -DUSE_EGL_X11  -DDEBUG -D_DEBUG -D_GNU_SOURCE -fPIC -O3 -fno-strict-aliasing -fno-optimize-sibling-calls -Wall -g
    CFLAGS += -DQT_BUILD -DOPENGL_ES_2_0 -DFBT_USE_GZ_FILE=1
    CFLAGS += -DDBG_FREESCALE
    ifeq ('$(LAPTOP)', 'yes')
        CFLAGS += -DSCREEN_RES_X=1366 -DSCREEN_RES_Y=600
    else
        CFLAGS += -DSCREEN_RES_X=1920 -DSCREEN_RES_Y=720
    endif
    INCDIR += -I/usr/include -I/usr/include/freetype2
    INSTALLDIR:= /usr/sbin
    INSTALL_IMAGES_DIR:= /opt/carmeter
    LIBS+= -lX11
    CC=gcc
    CXX=g++
endif



#MAKE
default: all
all: $(BINDIR)/$(APPNAME)

$(OBJSDIR)/%.o: %.c $(HDRS)
	@echo " [CC]   $@"
	@mkdir -p $(shell dirname $@)
	@$(CC) -c $< -o $@ $(CFLAGS) ${INCDIR}

$(OBJSDIR)/%.o: %.cpp $(HDRS)
	@echo " [CXX]  $@"
	@mkdir -p $(shell dirname $@)
	@$(CXX) -c $< -o $@ $(CFLAGS) ${INCDIR} -std=gnu++0x

$(BINDIR)/$(APPNAME) : $(OBJS)
	@echo " [LINK] $@"
	@mkdir -p $(shell dirname $@)
	@$(CXX) $(OBJS) -o $@ $(LDFLAGS) ${LIBS}

clean:
	@echo "rm -rf $(BINDIR)/$(APPNAME) $(OBJS)"
	@rm -rf $(BINDIR)/$(APPNAME) $(OBJS)

cleanall:
	@echo "rm -rf ./build/bin* ./build/objs*"
	@rm -rf ./build/bin* ./build/objs*
	
install: all
	mkdir -p $(ROOTFS)/opt/driver
	cp -rf $(BINDIR)/$(APPNAME) $(ROOTFS)/opt/driver 

