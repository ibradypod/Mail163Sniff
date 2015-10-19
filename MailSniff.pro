TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.c \
    mail_sniff.c \
    ungzip.c \
    urldecode.c \
    http_parser.c

HEADERS += \
    mail_sniff.h \
    ungzip.h \
    urldecode.h \
    http_parser.h

LIBS += -lpcre \
        -lpcap \
        -lz\
        -lnids
