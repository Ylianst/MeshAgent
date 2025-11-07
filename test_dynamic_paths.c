/*
 * Test program for dynamic KVM path generation
 * Compile: gcc -o test_dynamic_paths test_dynamic_paths.c -framework CommonCrypto
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <CommonCrypto/CommonDigest.h>
#include <libgen.h>

// Generate 8-character hex hash from input string using SHA-256
static void generate_hash(const char *input, char *output_hash)
{
	unsigned char digest[CC_SHA256_DIGEST_LENGTH];
	CC_SHA256(input, (CC_LONG)strlen(input), digest);

	// Use first 4 bytes (8 hex chars) of SHA-256
	snprintf(output_hash, 9, "%02x%02x%02x%02x",
		digest[0], digest[1], digest[2], digest[3]);
}

// Test path generation
void test_path_generation(const char *binary_path)
{
	char resolved_path[PATH_MAX];
	char binary_name[256];
	char hash[9];
	char *base_name;
	char socket_path[PATH_MAX];
	char queue_dir[PATH_MAX];
	char signal_file[PATH_MAX];

	printf("\n=== Testing: %s ===\n", binary_path);

	// Simulate realpath (just use the input as-is for testing)
	strncpy(resolved_path, binary_path, sizeof(resolved_path) - 1);
	resolved_path[sizeof(resolved_path) - 1] = '\0';

	// Extract binary name (basename)
	// Note: basename() may modify input, so use a copy
	char path_copy[PATH_MAX];
	strncpy(path_copy, resolved_path, sizeof(path_copy) - 1);
	base_name = basename(path_copy);
	strncpy(binary_name, base_name, sizeof(binary_name) - 1);
	binary_name[sizeof(binary_name) - 1] = '\0';

	// Generate hash from full resolved path
	generate_hash(resolved_path, hash);

	// Build dynamic paths
	snprintf(socket_path, PATH_MAX, "/tmp/%s-%s-kvm.sock", binary_name, hash);
	snprintf(queue_dir, PATH_MAX, "/var/run/%s-%s", binary_name, hash);
	snprintf(signal_file, PATH_MAX, "%s/session-active", queue_dir);

	printf("  Binary name: %s\n", binary_name);
	printf("  Hash: %s\n", hash);
	printf("  Socket: %s\n", socket_path);
	printf("  Queue: %s\n", queue_dir);
	printf("  Signal: %s\n", signal_file);
}

int main(int argc, char **argv)
{
	printf("Dynamic KVM Path Generation Test\n");
	printf("=================================\n");

	// Test the example paths you provided
	test_path_generation("/opt/tacticalmesh/meshagent");
	test_path_generation("/opt/tacticalmesh/tacticalmesh");
	test_path_generation("/usr/local/mesh_services/meshagent/meshagent");

	// Test with any additional paths provided as arguments
	for (int i = 1; i < argc; i++)
	{
		test_path_generation(argv[i]);
	}

	return 0;
}
