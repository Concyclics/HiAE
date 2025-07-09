# HiAE Makefile
# High-Throughput Authenticated Encryption Algorithm

# Compiler and flags
CC = cc

# Detect architecture and set appropriate flags
ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
    # x86-64 flags - enable AES-NI
    CFLAGS = -O3 -march=native -maes -I code
else ifeq ($(ARCH),aarch64)
    # ARM64 flags - enable crypto extensions
    CFLAGS = -O3 -march=native+crypto -I code
else ifeq ($(ARCH),arm64)
    # ARM64 flags (macOS naming) - enable crypto extensions
    CFLAGS = -O3 -march=native+crypto -I code
else
    $(error Unsupported architecture: $(ARCH). HiAE requires x86-64 with AES-NI or ARM64 with crypto extensions)
endif

LDFLAGS = 

# Source files
SOURCES = code/HiAE.c
HEADERS = code/HiAE.h

# Output directory for binaries
BINDIR = bin

# Target executables
TARGETS = $(BINDIR)/perf_test $(BINDIR)/func_test $(BINDIR)/test_vectors $(BINDIR)/HiAE-MAC $(BINDIR)/HiAE-File-AEAD

# Default target
all: $(BINDIR) $(TARGETS)

# Create bin directory
$(BINDIR):
	@mkdir -p $(BINDIR)

# Performance test
$(BINDIR)/perf_test: $(SOURCES) $(HEADERS) test/performance_test.c
	@echo "Building performance test..."
	$(CC) $(CFLAGS) $(SOURCES) test/performance_test.c -o $@ $(LDFLAGS)

# Functional test
$(BINDIR)/func_test: $(SOURCES) $(HEADERS) test/function_test.c
	@echo "Building functional test..."
	$(CC) $(CFLAGS) $(SOURCES) test/function_test.c -o $@ $(LDFLAGS)

# Test vectors validation
$(BINDIR)/test_vectors: $(SOURCES) $(HEADERS) test/test_vectors_ietf.c
	@echo "Building test vectors validation..."
	$(CC) $(CFLAGS) $(SOURCES) test/test_vectors_ietf.c -o $@ $(LDFLAGS)

# HiAE-MAC application
$(BINDIR)/HiAE-MAC: $(SOURCES) $(HEADERS) app/HiAE-MAC.c
	@echo "Building HiAE-MAC application..."
	$(CC) $(CFLAGS) $(SOURCES) app/HiAE-MAC.c -o $@ $(LDFLAGS)

# HiAE-File-AEAD application
$(BINDIR)/HiAE-File-AEAD: $(SOURCES) $(HEADERS) app/HiAE-File-AEAD.c
	@echo "Building HiAE-File-AEAD application..."
	$(CC) $(CFLAGS) $(SOURCES) app/HiAE-File-AEAD.c -o $@ $(LDFLAGS)

# Test targets
test: $(BINDIR)/func_test $(BINDIR)/test_vectors
	@echo "Running functional tests..."
	./$(BINDIR)/func_test
	@echo ""
	@echo "Running test vector validation..."
	./$(BINDIR)/test_vectors

test-vectors: $(BINDIR)/test_vectors
	@echo "Running test vector validation..."
	./$(BINDIR)/test_vectors

benchmark: $(BINDIR)/perf_test
	@echo "Running performance benchmark..."
	./$(BINDIR)/perf_test

# Clean target
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BINDIR)
	@rm -f perf_test func_test HiAE-MAC HiAE-File-AEAD

# Help target
help:
	@echo "HiAE Makefile targets:"
	@echo "  make all              - Build all targets (default)"
	@echo "  make test             - Build and run all tests"
	@echo "  make test-vectors     - Build and run test vector validation"
	@echo "  make benchmark        - Build and run performance benchmark"
	@echo "  make perf_test        - Build performance test only"
	@echo "  make func_test        - Build functional test only"
	@echo "  make test_vectors     - Build test vectors validation only"
	@echo "  make HiAE-MAC         - Build HiAE-MAC application"
	@echo "  make HiAE-File-AEAD   - Build file AEAD application"
	@echo "  make clean            - Remove all build artifacts"
	@echo "  make help             - Show this help message"

# Individual target shortcuts
perf_test: $(BINDIR)/perf_test
func_test: $(BINDIR)/func_test
test_vectors: $(BINDIR)/test_vectors
HiAE-MAC: $(BINDIR)/HiAE-MAC
HiAE-File-AEAD: $(BINDIR)/HiAE-File-AEAD

# Phony targets
.PHONY: all test test-vectors benchmark clean help perf_test func_test test_vectors HiAE-MAC HiAE-File-AEAD
