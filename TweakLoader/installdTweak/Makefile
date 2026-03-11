TARGET := iphone:clang:18.4:15.0
ARCHS = arm64 arm64e
FINALPACKAGE = 1
STRIP = 0
GO_EASY_ON_ME = 1

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = installdTweak

installdTweak_FILES = installdTweak.m
installdTweak_CFLAGS = -fobjc-arc
installdTweak_INSTALL_PATH = /usr/local/lib

include $(THEOS_MAKE_PATH)/library.mk
