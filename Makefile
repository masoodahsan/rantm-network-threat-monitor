CC ?= gcc
CPPFLAGS += -Iinclude -D_DEFAULT_SOURCE
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic
LDLIBS += -lpcap

SOURCES = src/main.c src/config.c src/utils.c src/parser.c src/profiler.c \
          src/baseline.c src/risk_engine.c src/detector.c src/capture.c \
          src/packet_handler.c src/logger.c src/statistics.c src/cli.c
OBJECTS = $(SOURCES:.c=.o)
TARGET = rantm

.PHONY: all clean debug test
all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) -o $@ $(LDLIBS)

src/%.o: src/%.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

debug: CFLAGS = -std=c11 -g3 -O0 -Wall -Wextra -Wpedantic -fsanitize=address,undefined
debug: clean $(TARGET)

tests/test_risk_engine: tests/test_risk_engine.c src/risk_engine.c src/baseline.c src/config.c src/utils.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@

tests/test_parser: tests/test_parser.c src/parser.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@ $(LDLIBS)

test: tests/test_risk_engine tests/test_parser
	./tests/test_risk_engine
	./tests/test_parser

clean:
	rm -f $(OBJECTS) $(TARGET) tests/test_risk_engine tests/test_parser
