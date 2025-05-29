/*
 * Simplified test program for rsync option parser
 * This program exercises the core option parsing functionality
 * to enable Daikon invariant detection
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <popt.h>

/* Simplified option variables */
int verbose = 0;
int quiet = 0;
int archive_mode = 0;
int recurse = 0;
int preserve_links = 0;
int preserve_perms = 0;
int preserve_times = 0;
int preserve_uid = 0;
int preserve_gid = 0;
int preserve_devices = 0;
int preserve_specials = 0;
int delete_mode = 0;
int delete_during = 0;
int delete_before = 0;
int delete_after = 0;
int force_delete = 0;
int numeric_ids = 0;
int checksum_mode = 0;
int size_only = 0;
int one_file_system = 0;
int cvs_exclude = 0;
int dry_run = 0;
int whole_file = -1;
int no_whole_file = 0;
int relative_paths = -1;
int backup_mode = 0;
int update_only = 0;
int inplace = 0;
int append_mode = 0;
int dirs_mode = 0;
int keep_dirlinks = 0;
int copy_dirlinks = 0;
int copy_links = 0;
int copy_unsafe_links = 0;
int safe_symlinks = 0;
int preserve_executability = 0;
int preserve_xattrs = 0;
int preserve_acls = 0;
int list_only = 0;

char *backup_suffix = NULL;
char *backup_dir = NULL;
char *compare_dest = NULL;
char *copy_dest = NULL;
char *link_dest = NULL;
char *config_file = NULL;
char *log_file = NULL;
char *password_file = NULL;
char *filter_str = NULL;
char *exclude_str = NULL;
char *include_str = NULL;
char *files_from = NULL;
int port = 0;
int protocol_version = 0;
int io_timeout = 0;

/* Option IDs for non-shortopt options */
enum {
    OPT_VERSION = 1000,
    OPT_DAEMON,
    OPT_SENDER,
    OPT_EXCLUDE,
    OPT_EXCLUDE_FROM,
    OPT_INCLUDE,
    OPT_INCLUDE_FROM,
    OPT_FILTER,
    OPT_COMPARE_DEST,
    OPT_COPY_DEST,
    OPT_LINK_DEST,
    OPT_HELP,
    OPT_BACKUP_DIR,
    OPT_SUFFIX,
    OPT_READ_BATCH,
    OPT_WRITE_BATCH,
    OPT_FILES_FROM,
    OPT_NUMERIC_IDS,
    OPT_TIMEOUT,
    OPT_PROTOCOL,
    OPT_PASSWORD_FILE,
    OPT_CONFIG,
    OPT_PORT,
    OPT_LOG_FILE,
    OPT_DELETE_BEFORE,
    OPT_DELETE_DURING,
    OPT_DELETE_AFTER,
    OPT_DELETE_EXCLUDED,
    OPT_FORCE,
    OPT_PARTIAL,
    OPT_DELAY_UPDATES,
    OPT_PRUNE_EMPTY_DIRS,
    OPT_ITEMIZE_CHANGES,
    OPT_NO_RECURSE,
    OPT_NO_RELATIVE,
    OPT_NO_IMPLIED_DIRS
};

/* Simplified option table - subset of rsync options */
static struct poptOption long_options[] = {
    /* longName, shortName, argInfo, arg, val, descrip, argDesc */
    {"verbose",         'v', POPT_ARG_NONE,   &verbose, 0, "increase verbosity", NULL},
    {"quiet",           'q', POPT_ARG_NONE,   &quiet, 0, "suppress non-error messages", NULL},
    {"archive",         'a', POPT_ARG_NONE,   0, 'a', "archive mode", NULL},
    {"recursive",       'r', POPT_ARG_VAL,    &recurse, 1, "recurse into directories", NULL},
    {"no-recursive",     0,  POPT_ARG_VAL,    &recurse, 0, "don't recurse", NULL},
    {"no-r",             0,  POPT_ARG_VAL,    &recurse, 0, NULL, NULL},
    {"dirs",            'd', POPT_ARG_VAL,    &dirs_mode, 1, "transfer directories", NULL},
    {"no-dirs",          0,  POPT_ARG_VAL,    &dirs_mode, 0, NULL, NULL},
    {"no-d",             0,  POPT_ARG_VAL,    &dirs_mode, 0, NULL, NULL},
    {"links",           'l', POPT_ARG_VAL,    &preserve_links, 1, "copy symlinks as symlinks", NULL},
    {"no-links",         0,  POPT_ARG_VAL,    &preserve_links, 0, NULL, NULL},
    {"no-l",             0,  POPT_ARG_VAL,    &preserve_links, 0, NULL, NULL},
    {"copy-links",      'L', POPT_ARG_VAL,    &copy_links, 1, "transform symlinks to referent", NULL},
    {"no-copy-links",    0,  POPT_ARG_VAL,    &copy_links, 0, NULL, NULL},
    {"no-L",             0,  POPT_ARG_VAL,    &copy_links, 0, NULL, NULL},
    {"perms",           'p', POPT_ARG_VAL,    &preserve_perms, 1, "preserve permissions", NULL},
    {"no-perms",         0,  POPT_ARG_VAL,    &preserve_perms, 0, NULL, NULL},
    {"no-p",             0,  POPT_ARG_VAL,    &preserve_perms, 0, NULL, NULL},
    {"times",           't', POPT_ARG_VAL,    &preserve_times, 1, "preserve times", NULL},
    {"no-times",         0,  POPT_ARG_VAL,    &preserve_times, 0, NULL, NULL},
    {"no-t",             0,  POPT_ARG_VAL,    &preserve_times, 0, NULL, NULL},
    {"owner",           'o', POPT_ARG_VAL,    &preserve_uid, 1, "preserve owner", NULL},
    {"no-owner",         0,  POPT_ARG_VAL,    &preserve_uid, 0, NULL, NULL},
    {"no-o",             0,  POPT_ARG_VAL,    &preserve_uid, 0, NULL, NULL},
    {"group",           'g', POPT_ARG_VAL,    &preserve_gid, 1, "preserve group", NULL},
    {"no-group",         0,  POPT_ARG_VAL,    &preserve_gid, 0, NULL, NULL},
    {"no-g",             0,  POPT_ARG_VAL,    &preserve_gid, 0, NULL, NULL},
    {"devices",         'D', POPT_ARG_VAL,    &preserve_devices, 1, "preserve device files", NULL},
    {"no-devices",       0,  POPT_ARG_VAL,    &preserve_devices, 0, NULL, NULL},
    {"no-D",             0,  POPT_ARG_VAL,    &preserve_devices, 0, NULL, NULL},
    {"specials",         0,  POPT_ARG_VAL,    &preserve_specials, 1, "preserve special files", NULL},
    {"no-specials",      0,  POPT_ARG_VAL,    &preserve_specials, 0, NULL, NULL},
    {"acls",            'A', POPT_ARG_VAL,    &preserve_acls, 1, "preserve ACLs", NULL},
    {"no-acls",          0,  POPT_ARG_VAL,    &preserve_acls, 0, NULL, NULL},
    {"no-A",             0,  POPT_ARG_VAL,    &preserve_acls, 0, NULL, NULL},
    {"xattrs",          'X', POPT_ARG_VAL,    &preserve_xattrs, 1, "preserve extended attributes", NULL},
    {"no-xattrs",        0,  POPT_ARG_VAL,    &preserve_xattrs, 0, NULL, NULL},
    {"no-X",             0,  POPT_ARG_VAL,    &preserve_xattrs, 0, NULL, NULL},
    {"backup",          'b', POPT_ARG_VAL,    &backup_mode, 1, "make backups", NULL},
    {"no-backup",        0,  POPT_ARG_VAL,    &backup_mode, 0, NULL, NULL},
    {"backup-dir",       0,  POPT_ARG_STRING, &backup_dir, OPT_BACKUP_DIR, "backup dir", "DIR"},
    {"suffix",           0,  POPT_ARG_STRING, &backup_suffix, OPT_SUFFIX, "backup suffix", "SUFFIX"},
    {"update",          'u', POPT_ARG_VAL,    &update_only, 1, "skip newer files", NULL},
    {"no-update",        0,  POPT_ARG_VAL,    &update_only, 0, NULL, NULL},
    {"no-u",             0,  POPT_ARG_VAL,    &update_only, 0, NULL, NULL},
    {"inplace",          0,  POPT_ARG_VAL,    &inplace, 1, "update destination files in-place", NULL},
    {"no-inplace",       0,  POPT_ARG_VAL,    &inplace, 0, NULL, NULL},
    {"append",           0,  POPT_ARG_VAL,    &append_mode, 1, "append data", NULL},
    {"no-append",        0,  POPT_ARG_VAL,    &append_mode, 0, NULL, NULL},
    {"del",              0,  POPT_ARG_VAL,    &delete_during, 1, "delete during transfer", NULL},
    {"delete",           0,  POPT_ARG_VAL,    &delete_mode, 1, "delete extraneous files", NULL},
    {"delete-before",    0,  POPT_ARG_NONE,   &delete_before, OPT_DELETE_BEFORE, "receiver deletes before transfer", NULL},
    {"delete-during",    0,  POPT_ARG_VAL,    &delete_during, 1, NULL, NULL},
    {"delete-after",     0,  POPT_ARG_NONE,   &delete_after, OPT_DELETE_AFTER, "receiver deletes after transfer", NULL},
    {"force",            0,  POPT_ARG_VAL,    &force_delete, 1, "force deletion", NULL},
    {"no-force",         0,  POPT_ARG_VAL,    &force_delete, 0, NULL, NULL},
    {"numeric-ids",      0,  POPT_ARG_VAL,    &numeric_ids, 1, "don't map uid/gid", NULL},
    {"checksum",        'c', POPT_ARG_VAL,    &checksum_mode, 1, "skip based on checksum", NULL},
    {"no-checksum",      0,  POPT_ARG_VAL,    &checksum_mode, 0, NULL, NULL},
    {"no-c",             0,  POPT_ARG_VAL,    &checksum_mode, 0, NULL, NULL},
    {"size-only",        0,  POPT_ARG_VAL,    &size_only, 1, "skip files that match in size", NULL},
    {"no-size-only",     0,  POPT_ARG_VAL,    &size_only, 0, NULL, NULL},
    {"one-file-system", 'x', POPT_ARG_VAL,    &one_file_system, 1, "don't cross filesystem boundaries", NULL},
    {"no-x",             0,  POPT_ARG_VAL,    &one_file_system, 0, NULL, NULL},
    {"cvs-exclude",     'C', POPT_ARG_VAL,    &cvs_exclude, 1, "auto-ignore CVS files", NULL},
    {"no-C",             0,  POPT_ARG_VAL,    &cvs_exclude, 0, NULL, NULL},
    {"whole-file",      'W', POPT_ARG_VAL,    &whole_file, 1, "copy files whole", NULL},
    {"no-whole-file",    0,  POPT_ARG_VAL,    &whole_file, 0, NULL, NULL},
    {"no-W",             0,  POPT_ARG_VAL,    &whole_file, 0, NULL, NULL},
    {"relative",        'R', POPT_ARG_VAL,    &relative_paths, 1, "use relative path names", NULL},
    {"no-relative",      0,  POPT_ARG_VAL,    &relative_paths, 0, NULL, NULL},
    {"no-R",             0,  POPT_ARG_VAL,    &relative_paths, 0, NULL, NULL},
    {"dry-run",         'n', POPT_ARG_VAL,    &dry_run, 1, "show what would have been transferred", NULL},
    {"list-only",        0,  POPT_ARG_VAL,    &list_only, 1, "list files instead of copying", NULL},
    {"exclude",          0,  POPT_ARG_STRING, &exclude_str, OPT_EXCLUDE, "exclude pattern", "PATTERN"},
    {"include",          0,  POPT_ARG_STRING, &include_str, OPT_INCLUDE, "include pattern", "PATTERN"},
    {"filter",          'f', POPT_ARG_STRING, &filter_str, OPT_FILTER, "filter rules", "RULE"},
    {"files-from",       0,  POPT_ARG_STRING, &files_from, OPT_FILES_FROM, "read list from file", "FILE"},
    {"timeout",          0,  POPT_ARG_INT,    &io_timeout, OPT_TIMEOUT, "timeout in seconds", "SECS"},
    {"port",             0,  POPT_ARG_INT,    &port, OPT_PORT, "port number", "PORT"},
    {"protocol",         0,  POPT_ARG_INT,    &protocol_version, OPT_PROTOCOL, "protocol version", "NUM"},
    {"password-file",    0,  POPT_ARG_STRING, &password_file, OPT_PASSWORD_FILE, "password file", "FILE"},
    {"log-file",         0,  POPT_ARG_STRING, &log_file, OPT_LOG_FILE, "log file", "FILE"},
    {"config",           0,  POPT_ARG_STRING, &config_file, OPT_CONFIG, "config file", "FILE"},
    {"help",            'h', POPT_ARG_NONE,   0, OPT_HELP, "show help", NULL},
    {"version",          0,  POPT_ARG_NONE,   0, OPT_VERSION, "show version", NULL},
    {NULL, 0, 0, NULL, 0, NULL, NULL}
};

/* Simplified parse_arguments function */
int parse_arguments(int argc, const char **argv)
{
    poptContext pc;
    int opt;
    const char *arg;
    
    /* Initialize popt context */
    pc = poptGetContext("rsync", argc, argv, long_options, 0);
    
    if (!pc) {
        fprintf(stderr, "Failed to initialize option parser\n");
        return 0;
    }
    
    /* Process options */
    while ((opt = poptGetNextOpt(pc)) != -1) {
        /* Handle special options */
        switch (opt) {
        case 'a': /* archive mode */
            /* Set multiple options that archive implies */
            recurse = 1;
            preserve_links = 1;
            preserve_perms = 1;
            preserve_times = 1;
            preserve_gid = 1;
            preserve_uid = 1;
            preserve_devices = 1;
            preserve_specials = 1;
            break;
            
        case OPT_VERSION:
            printf("rsync option parser test version 1.0\n");
            poptFreeContext(pc);
            return 2; /* Special return for version */
            
        case OPT_HELP:
            poptPrintHelp(pc, stdout, 0);
            poptFreeContext(pc);
            return 2; /* Special return for help */
            
        case OPT_DELETE_BEFORE:
            delete_before = 1;
            delete_mode = 1;
            break;
            
        case OPT_DELETE_DURING:
            delete_during = 1;
            delete_mode = 1;
            break;
            
        case OPT_DELETE_AFTER:
            delete_after = 1;
            delete_mode = 1;
            break;
            
        case POPT_ERROR_BADOPT:
            fprintf(stderr, "Unknown option: %s\n", poptBadOption(pc, 0));
            poptFreeContext(pc);
            return 0;
            
        default:
            if (opt < 0) {
                fprintf(stderr, "Option error: %s\n", poptStrerror(opt));
                poptFreeContext(pc);
                return 0;
            }
            break;
        }
    }
    
    /* Get remaining arguments (source and destination) */
    while ((arg = poptGetArg(pc)) != NULL) {
        /* In real rsync, these would be processed as source/dest */
        /* For testing, we just count them */
    }
    
    poptFreeContext(pc);
    return 1; /* Success */
}

/* Option validation function */
int validate_options(void)
{
    /* Check for conflicting options */
    if (delete_before && delete_during) {
        fprintf(stderr, "Cannot use --delete-before and --delete-during together\n");
        return 0;
    }
    
    if (delete_before && delete_after) {
        fprintf(stderr, "Cannot use --delete-before and --delete-after together\n");
        return 0;
    }
    
    if (delete_during && delete_after) {
        fprintf(stderr, "Cannot use --delete-during and --delete-after together\n");
        return 0;
    }
    
    /* Check dependencies */
    if (backup_dir && !backup_mode) {
        /* backup-dir implies backup mode */
        backup_mode = 1;
    }
    
    if (backup_mode && !backup_suffix) {
        backup_suffix = "~"; /* Default suffix */
    }
    
    /* Validate numeric options */
    if (port < 0 || port > 65535) {
        fprintf(stderr, "Invalid port number: %d\n", port);
        return 0;
    }
    
    if (io_timeout < 0) {
        fprintf(stderr, "Invalid timeout value: %d\n", io_timeout);
        return 0;
    }
    
    if (protocol_version < 0) {
        fprintf(stderr, "Invalid protocol version: %d\n", protocol_version);
        return 0;
    }
    
    return 1; /* Valid */
}

/* Print current option state */
void print_options(void)
{
    printf("\nCurrent options:\n");
    printf("  verbose: %d\n", verbose);
    printf("  quiet: %d\n", quiet);
    printf("  archive_mode: %d\n", archive_mode);
    printf("  recurse: %d\n", recurse);
    printf("  preserve_links: %d\n", preserve_links);
    printf("  preserve_perms: %d\n", preserve_perms);
    printf("  preserve_times: %d\n", preserve_times);
    printf("  preserve_uid: %d\n", preserve_uid);
    printf("  preserve_gid: %d\n", preserve_gid);
    printf("  preserve_devices: %d\n", preserve_devices);
    printf("  preserve_specials: %d\n", preserve_specials);
    printf("  delete_mode: %d\n", delete_mode);
    printf("  delete_before: %d\n", delete_before);
    printf("  delete_during: %d\n", delete_during);
    printf("  delete_after: %d\n", delete_after);
    printf("  force_delete: %d\n", force_delete);
    printf("  numeric_ids: %d\n", numeric_ids);
    printf("  checksum_mode: %d\n", checksum_mode);
    printf("  size_only: %d\n", size_only);
    printf("  cvs_exclude: %d\n", cvs_exclude);
    printf("  dry_run: %d\n", dry_run);
    printf("  backup_mode: %d\n", backup_mode);
    printf("  update_only: %d\n", update_only);
    printf("  backup_suffix: %s\n", backup_suffix ? backup_suffix : "(null)");
    printf("  backup_dir: %s\n", backup_dir ? backup_dir : "(null)");
    printf("  files_from: %s\n", files_from ? files_from : "(null)");
    printf("  port: %d\n", port);
    printf("  timeout: %d\n", io_timeout);
}

/* Test various option combinations */
void test_option_combinations(void)
{
    const char *test1[] = {"rsync", "-av", "src/", "dest/", NULL};
    const char *test2[] = {"rsync", "-rlptgoD", "src/", "dest/", NULL};
    const char *test3[] = {"rsync", "--delete", "--force", "src/", "dest/", NULL};
    const char *test4[] = {"rsync", "-avz", "--delete-after", "src/", "dest/", NULL};
    const char *test5[] = {"rsync", "--dry-run", "--itemize-changes", "src/", "dest/", NULL};
    const char *test6[] = {"rsync", "--backup", "--backup-dir=backups", "--suffix=.bak", "src/", "dest/", NULL};
    const char *test7[] = {"rsync", "-av", "--exclude=*.tmp", "--include=*.c", "src/", "dest/", NULL};
    const char *test8[] = {"rsync", "--files-from=list.txt", "--timeout=300", "src/", "dest/", NULL};
    const char *test9[] = {"rsync", "--help", NULL};
    const char *test10[] = {"rsync", "--version", NULL};
    
    printf("Testing option parser with various combinations...\n");
    
    /* Test 1: Archive mode */
    printf("\nTest 1: -av (archive + verbose)\n");
    verbose = quiet = archive_mode = recurse = 0;
    preserve_links = preserve_perms = preserve_times = 0;
    preserve_uid = preserve_gid = preserve_devices = preserve_specials = 0;
    parse_arguments(4, test1);
    validate_options();
    
    /* Test 2: Explicit archive flags */
    printf("\nTest 2: -rlptgoD (explicit archive flags)\n");
    verbose = quiet = archive_mode = recurse = 0;
    preserve_links = preserve_perms = preserve_times = 0;
    preserve_uid = preserve_gid = preserve_devices = preserve_specials = 0;
    parse_arguments(4, test2);
    validate_options();
    
    /* Test 3: Delete options */
    printf("\nTest 3: --delete --force\n");
    delete_mode = delete_before = delete_during = delete_after = force_delete = 0;
    parse_arguments(5, test3);
    validate_options();
    
    /* Test 4: Complex combination */
    printf("\nTest 4: -avz --delete-after\n");
    verbose = quiet = archive_mode = recurse = 0;
    preserve_links = preserve_perms = preserve_times = 0;
    preserve_uid = preserve_gid = preserve_devices = preserve_specials = 0;
    delete_mode = delete_before = delete_during = delete_after = 0;
    parse_arguments(5, test4);
    validate_options();
    
    /* Test 5: Dry run */
    printf("\nTest 5: --dry-run\n");
    dry_run = 0;
    parse_arguments(4, test5);
    validate_options();
    
    /* Test 6: Backup options */
    printf("\nTest 6: --backup --backup-dir --suffix\n");
    backup_mode = 0;
    backup_dir = backup_suffix = NULL;
    parse_arguments(6, test6);
    validate_options();
    
    /* Test 7: Filter options */
    printf("\nTest 7: --exclude --include\n");
    exclude_str = include_str = NULL;
    parse_arguments(6, test7);
    validate_options();
    
    /* Test 8: Files from and timeout */
    printf("\nTest 8: --files-from --timeout\n");
    files_from = NULL;
    io_timeout = 0;
    parse_arguments(5, test8);
    validate_options();
    
    /* Test 9: Help */
    printf("\nTest 9: --help\n");
    parse_arguments(2, test9);
    
    /* Test 10: Version */
    printf("\nTest 10: --version\n");
    parse_arguments(2, test10);
}

int main(int argc, char *argv[])
{
    printf("Rsync Option Parser Test Program\n");
    printf("================================\n\n");
    
    if (argc > 1) {
        /* Parse command line arguments */
        printf("Parsing command line arguments...\n");
        int result = parse_arguments(argc, (const char **)argv);
        
        if (result == 0) {
            fprintf(stderr, "Failed to parse arguments\n");
            return 1;
        } else if (result == 2) {
            /* Help or version was displayed */
            return 0;
        }
        
        /* Validate options */
        if (!validate_options()) {
            fprintf(stderr, "Invalid option combination\n");
            return 1;
        }
        
        /* Print parsed options */
        print_options();
    } else {
        /* Run test suite */
        test_option_combinations();
    }
    
    printf("\nOption parser test completed.\n");
    return 0;
}