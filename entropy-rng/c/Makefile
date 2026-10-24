CC      ?= cc
CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -Wall -Wextra -Wpedantic -Wshadow
LDLIBS   = -lm -lpthread

all: erng test_erng

liberng.a: entropy_rng.o
	$(AR) rcs $@ $^

entropy_rng.o: entropy_rng.c entropy_rng.h erng_internal.h

erng: erng_cli.c liberng.a
	$(CC) $(CFLAGS) -o $@ $< liberng.a $(LDLIBS)

test_erng: test_erng.c liberng.a
	$(CC) $(CFLAGS) -o $@ $< liberng.a $(LDLIBS)

check: test_erng
	./test_erng

# AddressSanitizer + UndefinedBehaviorSanitizer build of the tests
asan:
	$(CC) -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -std=c11 -Wall -Wextra \
	    -o test_erng_asan test_erng.c entropy_rng.c $(LDLIBS)
	./test_erng_asan

clean:
	rm -f *.o *.a erng test_erng test_erng_asan

.PHONY: all check asan clean
