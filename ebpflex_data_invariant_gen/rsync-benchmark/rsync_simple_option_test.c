/*
 * Simplified rsync option parser test without popt dependency
 * This program simulates option parsing behavior for Daikon analysis
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

/* Option flags structure */
typedef struct {
    int verbose;
    int quiet;
    int archive;
    int recursive;
    int preserve_links;
    int preserve_perms;
    int preserve_times;
    int preserve_owner;
    int preserve_group;
    int preserve_devices;
    int delete_mode;
    int delete_before;
    int delete_during;
    int delete_after;
    int force;
    int dry_run;
    int checksum;
    int size_only;
    int one_file_system;
    int whole_file;
    int backup;
    int update;
    int inplace;
    int append;
    int dirs;
    int compress;
    int numeric_ids;
    int cvs_exclude;
    int progress;
    int itemize_changes;
    int human_readable;
    int relative_paths;
    int no_implied_dirs;
    int list_only;
    char *backup_dir;
    char *backup_suffix;
    char *exclude_pattern;
    char *include_pattern;
    char *filter_rule;
    char *files_from;
    char *log_file;
    char *password_file;
    int timeout;
    int port;
    int block_size;
    int max_delete;
} rsync_options;

/* Initialize options with defaults */
void init_options(rsync_options *opts) {
    memset(opts, 0, sizeof(rsync_options));
    opts->whole_file = -1;  /* -1 means auto */
    opts->relative_paths = -1;
    opts->port = 873;  /* Default rsync port */
    opts->block_size = 700;  /* Default block size */
    opts->max_delete = -1;  /* No limit */
}

/* Parse a single short option */
int parse_short_option(char opt, rsync_options *opts) {
    switch (opt) {
        case 'v': opts->verbose++; return 1;
        case 'q': opts->quiet++; return 1;
        case 'a': /* Archive mode */
            opts->archive = 1;
            opts->recursive = 1;
            opts->preserve_links = 1;
            opts->preserve_perms = 1;
            opts->preserve_times = 1;
            opts->preserve_group = 1;
            opts->preserve_owner = 1;
            opts->preserve_devices = 1;
            return 1;
        case 'r': opts->recursive = 1; return 1;
        case 'l': opts->preserve_links = 1; return 1;
        case 'p': opts->preserve_perms = 1; return 1;
        case 't': opts->preserve_times = 1; return 1;
        case 'o': opts->preserve_owner = 1; return 1;
        case 'g': opts->preserve_group = 1; return 1;
        case 'D': opts->preserve_devices = 1; return 1;
        case 'x': opts->one_file_system = 1; return 1;
        case 'b': opts->backup = 1; return 1;
        case 'u': opts->update = 1; return 1;
        case 'c': opts->checksum = 1; return 1;
        case 'n': opts->dry_run = 1; return 1;
        case 'W': opts->whole_file = 1; return 1;
        case 'C': opts->cvs_exclude = 1; return 1;
        case 'z': opts->compress = 1; return 1;
        case 'h': opts->human_readable = 1; return 1;
        case 'P': /* --partial --progress */
            opts->progress = 1;
            return 1;
        case 'i': opts->itemize_changes = 1; return 1;
        case 'R': opts->relative_paths = 1; return 1;
        case 'd': opts->dirs = 1; return 1;
        default:
            return 0;  /* Unknown option */
    }
}

/* Parse a long option */
int parse_long_option(const char *opt, const char *arg, rsync_options *opts) {
    if (strcmp(opt, "verbose") == 0) {
        opts->verbose++;
        return 1;
    } else if (strcmp(opt, "quiet") == 0) {
        opts->quiet++;
        return 1;
    } else if (strcmp(opt, "archive") == 0) {
        opts->archive = 1;
        opts->recursive = 1;
        opts->preserve_links = 1;
        opts->preserve_perms = 1;
        opts->preserve_times = 1;
        opts->preserve_group = 1;
        opts->preserve_owner = 1;
        opts->preserve_devices = 1;
        return 1;
    } else if (strcmp(opt, "recursive") == 0) {
        opts->recursive = 1;
        return 1;
    } else if (strcmp(opt, "no-recursive") == 0 || strcmp(opt, "no-r") == 0) {
        opts->recursive = 0;
        return 1;
    } else if (strcmp(opt, "delete") == 0) {
        opts->delete_mode = 1;
        return 1;
    } else if (strcmp(opt, "delete-before") == 0) {
        opts->delete_mode = 1;
        opts->delete_before = 1;
        return 1;
    } else if (strcmp(opt, "delete-during") == 0 || strcmp(opt, "del") == 0) {
        opts->delete_mode = 1;
        opts->delete_during = 1;
        return 1;
    } else if (strcmp(opt, "delete-after") == 0) {
        opts->delete_mode = 1;
        opts->delete_after = 1;
        return 1;
    } else if (strcmp(opt, "force") == 0) {
        opts->force = 1;
        return 1;
    } else if (strcmp(opt, "dry-run") == 0) {
        opts->dry_run = 1;
        return 1;
    } else if (strcmp(opt, "backup") == 0) {
        opts->backup = 1;
        return 1;
    } else if (strcmp(opt, "backup-dir") == 0 && arg) {
        opts->backup = 1;  /* Implies backup */
        opts->backup_dir = strdup(arg);
        return 2;  /* Consumed argument */
    } else if (strcmp(opt, "suffix") == 0 && arg) {
        opts->backup_suffix = strdup(arg);
        return 2;
    } else if (strcmp(opt, "exclude") == 0 && arg) {
        opts->exclude_pattern = strdup(arg);
        return 2;
    } else if (strcmp(opt, "include") == 0 && arg) {
        opts->include_pattern = strdup(arg);
        return 2;
    } else if (strcmp(opt, "filter") == 0 && arg) {
        opts->filter_rule = strdup(arg);
        return 2;
    } else if (strcmp(opt, "files-from") == 0 && arg) {
        opts->files_from = strdup(arg);
        return 2;
    } else if (strcmp(opt, "timeout") == 0 && arg) {
        opts->timeout = atoi(arg);
        return 2;
    } else if (strcmp(opt, "port") == 0 && arg) {
        opts->port = atoi(arg);
        return 2;
    } else if (strcmp(opt, "checksum") == 0) {
        opts->checksum = 1;
        return 1;
    } else if (strcmp(opt, "size-only") == 0) {
        opts->size_only = 1;
        return 1;
    } else if (strcmp(opt, "one-file-system") == 0) {
        opts->one_file_system = 1;
        return 1;
    } else if (strcmp(opt, "update") == 0) {
        opts->update = 1;
        return 1;
    } else if (strcmp(opt, "inplace") == 0) {
        opts->inplace = 1;
        return 1;
    } else if (strcmp(opt, "append") == 0) {
        opts->append = 1;
        return 1;
    } else if (strcmp(opt, "progress") == 0) {
        opts->progress = 1;
        return 1;
    } else if (strcmp(opt, "no-progress") == 0) {
        opts->progress = 0;
        return 1;
    } else if (strcmp(opt, "itemize-changes") == 0) {
        opts->itemize_changes = 1;
        return 1;
    } else if (strcmp(opt, "compress") == 0) {
        opts->compress = 1;
        return 1;
    } else if (strcmp(opt, "no-compress") == 0) {
        opts->compress = 0;
        return 1;
    } else if (strcmp(opt, "numeric-ids") == 0) {
        opts->numeric_ids = 1;
        return 1;
    } else if (strcmp(opt, "cvs-exclude") == 0) {
        opts->cvs_exclude = 1;
        return 1;
    } else if (strcmp(opt, "whole-file") == 0) {
        opts->whole_file = 1;
        return 1;
    } else if (strcmp(opt, "no-whole-file") == 0) {
        opts->whole_file = 0;
        return 1;
    } else if (strcmp(opt, "relative") == 0) {
        opts->relative_paths = 1;
        return 1;
    } else if (strcmp(opt, "no-relative") == 0) {
        opts->relative_paths = 0;
        return 1;
    } else if (strcmp(opt, "dirs") == 0) {
        opts->dirs = 1;
        return 1;
    } else if (strcmp(opt, "no-dirs") == 0) {
        opts->dirs = 0;
        return 1;
    } else if (strcmp(opt, "links") == 0) {
        opts->preserve_links = 1;
        return 1;
    } else if (strcmp(opt, "no-links") == 0) {
        opts->preserve_links = 0;
        return 1;
    } else if (strcmp(opt, "perms") == 0) {
        opts->preserve_perms = 1;
        return 1;
    } else if (strcmp(opt, "no-perms") == 0) {
        opts->preserve_perms = 0;
        return 1;
    } else if (strcmp(opt, "times") == 0) {
        opts->preserve_times = 1;
        return 1;
    } else if (strcmp(opt, "no-times") == 0) {
        opts->preserve_times = 0;
        return 1;
    } else if (strcmp(opt, "list-only") == 0) {
        opts->list_only = 1;
        return 1;
    } else if (strcmp(opt, "max-delete") == 0 && arg) {
        opts->max_delete = atoi(arg);
        return 2;
    } else if (strcmp(opt, "block-size") == 0 && arg) {
        opts->block_size = atoi(arg);
        return 2;
    } else if (strcmp(opt, "log-file") == 0 && arg) {
        opts->log_file = strdup(arg);
        return 2;
    } else if (strcmp(opt, "password-file") == 0 && arg) {
        opts->password_file = strdup(arg);
        return 2;
    } else if (strcmp(opt, "no-implied-dirs") == 0) {
        opts->no_implied_dirs = 1;
        return 1;
    } else if (strcmp(opt, "human-readable") == 0) {
        opts->human_readable = 1;
        return 1;
    }
    
    return 0;  /* Unknown option */
}

/* Parse command line arguments */
int parse_arguments(int argc, char *argv[], rsync_options *opts) {
    int i = 1;  /* Skip program name */
    int non_option_count = 0;
    
    while (i < argc) {
        char *arg = argv[i];
        
        if (arg[0] == '-' && arg[1] != '\0') {
            if (arg[1] == '-') {
                /* Long option */
                char *opt = arg + 2;
                char *equals = strchr(opt, '=');
                char *value = NULL;
                
                if (equals) {
                    *equals = '\0';
                    value = equals + 1;
                } else if (i + 1 < argc && argv[i + 1][0] != '-') {
                    value = argv[i + 1];
                }
                
                int consumed = parse_long_option(opt, value, opts);
                if (consumed == 0) {
                    fprintf(stderr, "Unknown option: --%s\n", opt);
                    return -1;
                }
                i += consumed;
            } else {
                /* Short option(s) */
                char *p = arg + 1;
                while (*p) {
                    if (!parse_short_option(*p, opts)) {
                        fprintf(stderr, "Unknown option: -%c\n", *p);
                        return -1;
                    }
                    p++;
                }
                i++;
            }
        } else {
            /* Non-option argument (source/destination) */
            non_option_count++;
            i++;
        }
    }
    
    return non_option_count;
}

/* Validate option combinations */
int validate_options(rsync_options *opts) {
    /* Check for conflicting delete options */
    int delete_count = 0;
    if (opts->delete_before) delete_count++;
    if (opts->delete_during) delete_count++;
    if (opts->delete_after) delete_count++;
    
    if (delete_count > 1) {
        fprintf(stderr, "Conflicting delete options specified\n");
        return 0;
    }
    
    /* Backup dir implies backup mode */
    if (opts->backup_dir && !opts->backup) {
        opts->backup = 1;
    }
    
    /* Set default backup suffix if needed */
    if (opts->backup && !opts->backup_suffix) {
        opts->backup_suffix = strdup("~");
    }
    
    /* Validate port number */
    if (opts->port < 0 || opts->port > 65535) {
        fprintf(stderr, "Invalid port number: %d\n", opts->port);
        return 0;
    }
    
    /* Validate timeout */
    if (opts->timeout < 0) {
        fprintf(stderr, "Invalid timeout value: %d\n", opts->timeout);
        return 0;
    }
    
    /* Validate block size */
    if (opts->block_size < 0) {
        fprintf(stderr, "Invalid block size: %d\n", opts->block_size);
        return 0;
    }
    
    /* Check for incompatible options */
    if (opts->whole_file && opts->inplace) {
        fprintf(stderr, "Warning: --inplace is incompatible with --whole-file\n");
    }
    
    if (opts->append && opts->inplace) {
        fprintf(stderr, "Warning: --append is incompatible with --inplace\n");
    }
    
    return 1;  /* Valid */
}

/* Print current options */
void print_options(rsync_options *opts) {
    printf("Current options:\n");
    printf("  verbose: %d\n", opts->verbose);
    printf("  quiet: %d\n", opts->quiet);
    printf("  archive: %d\n", opts->archive);
    printf("  recursive: %d\n", opts->recursive);
    printf("  preserve_links: %d\n", opts->preserve_links);
    printf("  preserve_perms: %d\n", opts->preserve_perms);
    printf("  preserve_times: %d\n", opts->preserve_times);
    printf("  preserve_owner: %d\n", opts->preserve_owner);
    printf("  preserve_group: %d\n", opts->preserve_group);
    printf("  preserve_devices: %d\n", opts->preserve_devices);
    printf("  delete_mode: %d\n", opts->delete_mode);
    printf("  delete_before: %d\n", opts->delete_before);
    printf("  delete_during: %d\n", opts->delete_during);
    printf("  delete_after: %d\n", opts->delete_after);
    printf("  force: %d\n", opts->force);
    printf("  dry_run: %d\n", opts->dry_run);
    printf("  checksum: %d\n", opts->checksum);
    printf("  size_only: %d\n", opts->size_only);
    printf("  backup: %d\n", opts->backup);
    printf("  update: %d\n", opts->update);
    printf("  whole_file: %d\n", opts->whole_file);
    printf("  compress: %d\n", opts->compress);
    printf("  port: %d\n", opts->port);
    printf("  timeout: %d\n", opts->timeout);
    printf("  block_size: %d\n", opts->block_size);
    printf("  max_delete: %d\n", opts->max_delete);
    if (opts->backup_dir) printf("  backup_dir: %s\n", opts->backup_dir);
    if (opts->backup_suffix) printf("  backup_suffix: %s\n", opts->backup_suffix);
    if (opts->files_from) printf("  files_from: %s\n", opts->files_from);
}

/* Free allocated memory */
void free_options(rsync_options *opts) {
    if (opts->backup_dir) free(opts->backup_dir);
    if (opts->backup_suffix) free(opts->backup_suffix);
    if (opts->exclude_pattern) free(opts->exclude_pattern);
    if (opts->include_pattern) free(opts->include_pattern);
    if (opts->filter_rule) free(opts->filter_rule);
    if (opts->files_from) free(opts->files_from);
    if (opts->log_file) free(opts->log_file);
    if (opts->password_file) free(opts->password_file);
}

/* Test various option combinations */
void test_option_combinations() {
    rsync_options opts;
    
    printf("Testing various option combinations...\n\n");
    
    /* Test 1: Archive mode */
    printf("Test 1: -av (archive + verbose)\n");
    char *test1[] = {"rsync", "-av", "src/", "dest/", NULL};
    init_options(&opts);
    parse_arguments(4, test1, &opts);
    validate_options(&opts);
    printf("  Archive sets: recursive=%d, preserve_links=%d, preserve_perms=%d\n",
           opts.recursive, opts.preserve_links, opts.preserve_perms);
    free_options(&opts);
    
    /* Test 2: Delete options */
    printf("\nTest 2: --delete --delete-before\n");
    char *test2[] = {"rsync", "--delete", "--delete-before", "src/", "dest/"};
    init_options(&opts);
    parse_arguments(5, test2, &opts);
    validate_options(&opts);
    printf("  Delete mode: %d, delete_before: %d\n", opts.delete_mode, opts.delete_before);
    free_options(&opts);
    
    /* Test 3: Backup options */
    printf("\nTest 3: --backup --backup-dir=backup --suffix=.old\n");
    char *test3[] = {"rsync", "--backup", "--backup-dir=backup", "--suffix=.old", "src/", "dest/"};
    init_options(&opts);
    parse_arguments(6, test3, &opts);
    validate_options(&opts);
    printf("  Backup: %d, backup_dir: %s, suffix: %s\n", 
           opts.backup, opts.backup_dir, opts.backup_suffix);
    free_options(&opts);
    
    /* Test 4: Mixed short options */
    printf("\nTest 4: -rlptgoDxvz\n");
    char *test4[] = {"rsync", "-rlptgoDxvz", "src/", "dest/"};
    init_options(&opts);
    parse_arguments(4, test4, &opts);
    validate_options(&opts);
    printf("  Recursive: %d, links: %d, compress: %d, verbose: %d\n",
           opts.recursive, opts.preserve_links, opts.compress, opts.verbose);
    free_options(&opts);
    
    /* Test 5: Complex combination */
    printf("\nTest 5: Complex combination with filters\n");
    char *test5[] = {"rsync", "-av", "--delete-after", "--exclude=*.tmp", 
                     "--include=*.c", "--timeout=300", "--port=8873", "src/", "dest/"};
    init_options(&opts);
    parse_arguments(9, test5, &opts);
    validate_options(&opts);
    printf("  Archive: %d, delete_after: %d, timeout: %d, port: %d\n",
           opts.archive, opts.delete_after, opts.timeout, opts.port);
    printf("  Exclude: %s, Include: %s\n", 
           opts.exclude_pattern ? opts.exclude_pattern : "(null)",
           opts.include_pattern ? opts.include_pattern : "(null)");
    free_options(&opts);
    
    /* Test 6: Numeric options */
    printf("\nTest 6: Numeric options\n");
    char *test6[] = {"rsync", "--max-delete=100", "--block-size=2048", "src/", "dest/"};
    init_options(&opts);
    parse_arguments(5, test6, &opts);
    validate_options(&opts);
    printf("  Max delete: %d, block size: %d\n", opts.max_delete, opts.block_size);
    free_options(&opts);
    
    /* Test 7: Invalid combinations */
    printf("\nTest 7: Invalid combination --delete-before --delete-after\n");
    char *test7[] = {"rsync", "--delete-before", "--delete-after", "src/", "dest/"};
    init_options(&opts);
    parse_arguments(5, test7, &opts);
    if (!validate_options(&opts)) {
        printf("  Validation failed as expected\n");
    }
    free_options(&opts);
    
    /* Test 8: Option negation */
    printf("\nTest 8: Option negation --recursive --no-recursive\n");
    char *test8[] = {"rsync", "--recursive", "--no-recursive", "src/", "dest/"};
    init_options(&opts);
    parse_arguments(5, test8, &opts);
    validate_options(&opts);
    printf("  Recursive: %d (should be 0)\n", opts.recursive);
    free_options(&opts);
}

/* Main function */
int main(int argc, char *argv[]) {
    rsync_options opts;
    
    printf("Rsync Option Parser Test\n");
    printf("========================\n\n");
    
    if (argc > 1) {
        /* Parse command line arguments */
        init_options(&opts);
        int non_options = parse_arguments(argc, argv, &opts);
        
        if (non_options < 0) {
            fprintf(stderr, "Error parsing arguments\n");
            return 1;
        }
        
        printf("Parsed %d non-option arguments\n", non_options);
        
        if (!validate_options(&opts)) {
            fprintf(stderr, "Invalid option combination\n");
            free_options(&opts);
            return 1;
        }
        
        print_options(&opts);
        free_options(&opts);
    } else {
        /* Run test suite */
        test_option_combinations();
    }
    
    printf("\nDone.\n");
    return 0;
}