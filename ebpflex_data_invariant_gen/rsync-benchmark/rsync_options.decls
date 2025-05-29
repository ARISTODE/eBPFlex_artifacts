input-language C/C++
decl-version 2.0
var-comparability implicit

ppt ..main():::ENTER
  ppt-type enter
  variable argc
    var-kind variable
    rep-type int
    dec-type int
    flags is_param 
    comparability 1
  variable argv
    var-kind variable
    rep-type hashcode
    dec-type char**
    flags is_param 
    comparability 1
  variable argv[..]
    var-kind array
    enclosing-var argv
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 2

ppt ..main():::EXIT0
  ppt-type subexit
  variable argc
    var-kind variable
    rep-type int
    dec-type int
    flags is_param 
    comparability 1
  variable argv
    var-kind variable
    rep-type hashcode
    dec-type char**
    flags is_param 
    comparability 1
  variable argv[..]
    var-kind array
    enclosing-var argv
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 2
  variable return
    var-kind variable
    rep-type int
    dec-type int
    comparability 3

ppt ..test_option_combinations():::ENTER
  ppt-type enter

ppt ..test_option_combinations():::EXIT0
  ppt-type subexit

ppt ..free_options():::ENTER
  ppt-type enter
  variable opts
    var-kind variable
    rep-type hashcode
    dec-type rsync_options*
    flags is_param 
    comparability 1
  variable opts[..]
    var-kind array
    enclosing-var opts
    array 1
    rep-type hashcode[]
    dec-type rsync_options[]
    comparability 2
  variable opts[..].verbose
    var-kind field verbose
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].quiet
    var-kind field quiet
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].archive
    var-kind field archive
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].recursive
    var-kind field recursive
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].preserve_links
    var-kind field preserve_links
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 6
  variable opts[..].preserve_perms
    var-kind field preserve_perms
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 7
  variable opts[..].preserve_times
    var-kind field preserve_times
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 8
  variable opts[..].preserve_owner
    var-kind field preserve_owner
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 9
  variable opts[..].preserve_group
    var-kind field preserve_group
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 10
  variable opts[..].preserve_devices
    var-kind field preserve_devices
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 11
  variable opts[..].delete_mode
    var-kind field delete_mode
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 12
  variable opts[..].delete_before
    var-kind field delete_before
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].delete_during
    var-kind field delete_during
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].delete_after
    var-kind field delete_after
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].force
    var-kind field force
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].dry_run
    var-kind field dry_run
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].checksum
    var-kind field checksum
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].size_only
    var-kind field size_only
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].one_file_system
    var-kind field one_file_system
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].whole_file
    var-kind field whole_file
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 13
  variable opts[..].backup
    var-kind field backup
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 14
  variable opts[..].update
    var-kind field update
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].inplace
    var-kind field inplace
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].append
    var-kind field append
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].dirs
    var-kind field dirs
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].compress
    var-kind field compress
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].numeric_ids
    var-kind field numeric_ids
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].cvs_exclude
    var-kind field cvs_exclude
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].progress
    var-kind field progress
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].itemize_changes
    var-kind field itemize_changes
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].human_readable
    var-kind field human_readable
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].relative_paths
    var-kind field relative_paths
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 15
  variable opts[..].no_implied_dirs
    var-kind field no_implied_dirs
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].list_only
    var-kind field list_only
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].backup_dir
    var-kind field backup_dir
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 16
  variable opts[..].backup_suffix
    var-kind field backup_suffix
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 17
  variable opts[..].exclude_pattern
    var-kind field exclude_pattern
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 18
  variable opts[..].include_pattern
    var-kind field include_pattern
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 19
  variable opts[..].filter_rule
    var-kind field filter_rule
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 20
  variable opts[..].files_from
    var-kind field files_from
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 21
  variable opts[..].log_file
    var-kind field log_file
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 22
  variable opts[..].password_file
    var-kind field password_file
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 23
  variable opts[..].timeout
    var-kind field timeout
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].port
    var-kind field port
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 24
  variable opts[..].block_size
    var-kind field block_size
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 25
  variable opts[..].max_delete
    var-kind field max_delete
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 26

ppt ..free_options():::EXIT0
  ppt-type subexit
  variable opts
    var-kind variable
    rep-type hashcode
    dec-type rsync_options*
    flags is_param 
    comparability 1
  variable opts[..]
    var-kind array
    enclosing-var opts
    array 1
    rep-type hashcode[]
    dec-type rsync_options[]
    comparability 2
  variable opts[..].verbose
    var-kind field verbose
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].quiet
    var-kind field quiet
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].archive
    var-kind field archive
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].recursive
    var-kind field recursive
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].preserve_links
    var-kind field preserve_links
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 6
  variable opts[..].preserve_perms
    var-kind field preserve_perms
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 7
  variable opts[..].preserve_times
    var-kind field preserve_times
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 8
  variable opts[..].preserve_owner
    var-kind field preserve_owner
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 9
  variable opts[..].preserve_group
    var-kind field preserve_group
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 10
  variable opts[..].preserve_devices
    var-kind field preserve_devices
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 11
  variable opts[..].delete_mode
    var-kind field delete_mode
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 12
  variable opts[..].delete_before
    var-kind field delete_before
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].delete_during
    var-kind field delete_during
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].delete_after
    var-kind field delete_after
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].force
    var-kind field force
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].dry_run
    var-kind field dry_run
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].checksum
    var-kind field checksum
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].size_only
    var-kind field size_only
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].one_file_system
    var-kind field one_file_system
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].whole_file
    var-kind field whole_file
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 13
  variable opts[..].backup
    var-kind field backup
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 14
  variable opts[..].update
    var-kind field update
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].inplace
    var-kind field inplace
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].append
    var-kind field append
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].dirs
    var-kind field dirs
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].compress
    var-kind field compress
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].numeric_ids
    var-kind field numeric_ids
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].cvs_exclude
    var-kind field cvs_exclude
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].progress
    var-kind field progress
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].itemize_changes
    var-kind field itemize_changes
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].human_readable
    var-kind field human_readable
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].relative_paths
    var-kind field relative_paths
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 15
  variable opts[..].no_implied_dirs
    var-kind field no_implied_dirs
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].list_only
    var-kind field list_only
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].backup_dir
    var-kind field backup_dir
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 16
  variable opts[..].backup_suffix
    var-kind field backup_suffix
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 17
  variable opts[..].exclude_pattern
    var-kind field exclude_pattern
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 18
  variable opts[..].include_pattern
    var-kind field include_pattern
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 19
  variable opts[..].filter_rule
    var-kind field filter_rule
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 20
  variable opts[..].files_from
    var-kind field files_from
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 21
  variable opts[..].log_file
    var-kind field log_file
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 22
  variable opts[..].password_file
    var-kind field password_file
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 23
  variable opts[..].timeout
    var-kind field timeout
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].port
    var-kind field port
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 24
  variable opts[..].block_size
    var-kind field block_size
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 25
  variable opts[..].max_delete
    var-kind field max_delete
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 26

ppt ..print_options():::ENTER
  ppt-type enter
  variable opts
    var-kind variable
    rep-type hashcode
    dec-type rsync_options*
    flags is_param 
    comparability 1
  variable opts[..]
    var-kind array
    enclosing-var opts
    array 1
    rep-type hashcode[]
    dec-type rsync_options[]
    comparability 2
  variable opts[..].verbose
    var-kind field verbose
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].quiet
    var-kind field quiet
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].archive
    var-kind field archive
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].recursive
    var-kind field recursive
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].preserve_links
    var-kind field preserve_links
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 6
  variable opts[..].preserve_perms
    var-kind field preserve_perms
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 7
  variable opts[..].preserve_times
    var-kind field preserve_times
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 8
  variable opts[..].preserve_owner
    var-kind field preserve_owner
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 9
  variable opts[..].preserve_group
    var-kind field preserve_group
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 10
  variable opts[..].preserve_devices
    var-kind field preserve_devices
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 11
  variable opts[..].delete_mode
    var-kind field delete_mode
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 12
  variable opts[..].delete_before
    var-kind field delete_before
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].delete_during
    var-kind field delete_during
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].delete_after
    var-kind field delete_after
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].force
    var-kind field force
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].dry_run
    var-kind field dry_run
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].checksum
    var-kind field checksum
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].size_only
    var-kind field size_only
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].one_file_system
    var-kind field one_file_system
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].whole_file
    var-kind field whole_file
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 13
  variable opts[..].backup
    var-kind field backup
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 14
  variable opts[..].update
    var-kind field update
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].inplace
    var-kind field inplace
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].append
    var-kind field append
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].dirs
    var-kind field dirs
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].compress
    var-kind field compress
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].numeric_ids
    var-kind field numeric_ids
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].cvs_exclude
    var-kind field cvs_exclude
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].progress
    var-kind field progress
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].itemize_changes
    var-kind field itemize_changes
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].human_readable
    var-kind field human_readable
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].relative_paths
    var-kind field relative_paths
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 15
  variable opts[..].no_implied_dirs
    var-kind field no_implied_dirs
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].list_only
    var-kind field list_only
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].backup_dir
    var-kind field backup_dir
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 16
  variable opts[..].backup_suffix
    var-kind field backup_suffix
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 17
  variable opts[..].exclude_pattern
    var-kind field exclude_pattern
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 18
  variable opts[..].include_pattern
    var-kind field include_pattern
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 19
  variable opts[..].filter_rule
    var-kind field filter_rule
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 20
  variable opts[..].files_from
    var-kind field files_from
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 21
  variable opts[..].log_file
    var-kind field log_file
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 22
  variable opts[..].password_file
    var-kind field password_file
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 23
  variable opts[..].timeout
    var-kind field timeout
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].port
    var-kind field port
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 24
  variable opts[..].block_size
    var-kind field block_size
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 25
  variable opts[..].max_delete
    var-kind field max_delete
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 26

ppt ..print_options():::EXIT0
  ppt-type subexit
  variable opts
    var-kind variable
    rep-type hashcode
    dec-type rsync_options*
    flags is_param 
    comparability 1
  variable opts[..]
    var-kind array
    enclosing-var opts
    array 1
    rep-type hashcode[]
    dec-type rsync_options[]
    comparability 2
  variable opts[..].verbose
    var-kind field verbose
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].quiet
    var-kind field quiet
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].archive
    var-kind field archive
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].recursive
    var-kind field recursive
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].preserve_links
    var-kind field preserve_links
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 6
  variable opts[..].preserve_perms
    var-kind field preserve_perms
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 7
  variable opts[..].preserve_times
    var-kind field preserve_times
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 8
  variable opts[..].preserve_owner
    var-kind field preserve_owner
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 9
  variable opts[..].preserve_group
    var-kind field preserve_group
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 10
  variable opts[..].preserve_devices
    var-kind field preserve_devices
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 11
  variable opts[..].delete_mode
    var-kind field delete_mode
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 12
  variable opts[..].delete_before
    var-kind field delete_before
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].delete_during
    var-kind field delete_during
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].delete_after
    var-kind field delete_after
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].force
    var-kind field force
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].dry_run
    var-kind field dry_run
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].checksum
    var-kind field checksum
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].size_only
    var-kind field size_only
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].one_file_system
    var-kind field one_file_system
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].whole_file
    var-kind field whole_file
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 13
  variable opts[..].backup
    var-kind field backup
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 14
  variable opts[..].update
    var-kind field update
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].inplace
    var-kind field inplace
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].append
    var-kind field append
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].dirs
    var-kind field dirs
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].compress
    var-kind field compress
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].numeric_ids
    var-kind field numeric_ids
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].cvs_exclude
    var-kind field cvs_exclude
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].progress
    var-kind field progress
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].itemize_changes
    var-kind field itemize_changes
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].human_readable
    var-kind field human_readable
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].relative_paths
    var-kind field relative_paths
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 15
  variable opts[..].no_implied_dirs
    var-kind field no_implied_dirs
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].list_only
    var-kind field list_only
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].backup_dir
    var-kind field backup_dir
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 16
  variable opts[..].backup_suffix
    var-kind field backup_suffix
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 17
  variable opts[..].exclude_pattern
    var-kind field exclude_pattern
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 18
  variable opts[..].include_pattern
    var-kind field include_pattern
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 19
  variable opts[..].filter_rule
    var-kind field filter_rule
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 20
  variable opts[..].files_from
    var-kind field files_from
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 21
  variable opts[..].log_file
    var-kind field log_file
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 22
  variable opts[..].password_file
    var-kind field password_file
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 23
  variable opts[..].timeout
    var-kind field timeout
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].port
    var-kind field port
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 24
  variable opts[..].block_size
    var-kind field block_size
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 25
  variable opts[..].max_delete
    var-kind field max_delete
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 26

ppt ..validate_options():::ENTER
  ppt-type enter
  variable opts
    var-kind variable
    rep-type hashcode
    dec-type rsync_options*
    flags is_param 
    comparability 1
  variable opts[..]
    var-kind array
    enclosing-var opts
    array 1
    rep-type hashcode[]
    dec-type rsync_options[]
    comparability 2
  variable opts[..].verbose
    var-kind field verbose
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].quiet
    var-kind field quiet
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].archive
    var-kind field archive
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].recursive
    var-kind field recursive
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].preserve_links
    var-kind field preserve_links
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 6
  variable opts[..].preserve_perms
    var-kind field preserve_perms
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 7
  variable opts[..].preserve_times
    var-kind field preserve_times
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 8
  variable opts[..].preserve_owner
    var-kind field preserve_owner
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 9
  variable opts[..].preserve_group
    var-kind field preserve_group
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 10
  variable opts[..].preserve_devices
    var-kind field preserve_devices
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 11
  variable opts[..].delete_mode
    var-kind field delete_mode
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 12
  variable opts[..].delete_before
    var-kind field delete_before
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].delete_during
    var-kind field delete_during
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].delete_after
    var-kind field delete_after
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].force
    var-kind field force
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].dry_run
    var-kind field dry_run
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].checksum
    var-kind field checksum
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].size_only
    var-kind field size_only
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].one_file_system
    var-kind field one_file_system
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].whole_file
    var-kind field whole_file
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 13
  variable opts[..].backup
    var-kind field backup
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 14
  variable opts[..].update
    var-kind field update
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].inplace
    var-kind field inplace
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].append
    var-kind field append
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].dirs
    var-kind field dirs
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].compress
    var-kind field compress
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].numeric_ids
    var-kind field numeric_ids
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].cvs_exclude
    var-kind field cvs_exclude
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].progress
    var-kind field progress
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].itemize_changes
    var-kind field itemize_changes
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].human_readable
    var-kind field human_readable
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].relative_paths
    var-kind field relative_paths
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 15
  variable opts[..].no_implied_dirs
    var-kind field no_implied_dirs
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].list_only
    var-kind field list_only
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].backup_dir
    var-kind field backup_dir
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 16
  variable opts[..].backup_suffix
    var-kind field backup_suffix
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 17
  variable opts[..].exclude_pattern
    var-kind field exclude_pattern
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 18
  variable opts[..].include_pattern
    var-kind field include_pattern
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 19
  variable opts[..].filter_rule
    var-kind field filter_rule
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 20
  variable opts[..].files_from
    var-kind field files_from
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 21
  variable opts[..].log_file
    var-kind field log_file
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 22
  variable opts[..].password_file
    var-kind field password_file
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 23
  variable opts[..].timeout
    var-kind field timeout
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].port
    var-kind field port
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 24
  variable opts[..].block_size
    var-kind field block_size
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 25
  variable opts[..].max_delete
    var-kind field max_delete
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 26

ppt ..validate_options():::EXIT0
  ppt-type subexit
  variable opts
    var-kind variable
    rep-type hashcode
    dec-type rsync_options*
    flags is_param 
    comparability 1
  variable opts[..]
    var-kind array
    enclosing-var opts
    array 1
    rep-type hashcode[]
    dec-type rsync_options[]
    comparability 2
  variable opts[..].verbose
    var-kind field verbose
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].quiet
    var-kind field quiet
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].archive
    var-kind field archive
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].recursive
    var-kind field recursive
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].preserve_links
    var-kind field preserve_links
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 6
  variable opts[..].preserve_perms
    var-kind field preserve_perms
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 7
  variable opts[..].preserve_times
    var-kind field preserve_times
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 8
  variable opts[..].preserve_owner
    var-kind field preserve_owner
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 9
  variable opts[..].preserve_group
    var-kind field preserve_group
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 10
  variable opts[..].preserve_devices
    var-kind field preserve_devices
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 11
  variable opts[..].delete_mode
    var-kind field delete_mode
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 12
  variable opts[..].delete_before
    var-kind field delete_before
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].delete_during
    var-kind field delete_during
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].delete_after
    var-kind field delete_after
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].force
    var-kind field force
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].dry_run
    var-kind field dry_run
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].checksum
    var-kind field checksum
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].size_only
    var-kind field size_only
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].one_file_system
    var-kind field one_file_system
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].whole_file
    var-kind field whole_file
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 13
  variable opts[..].backup
    var-kind field backup
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 14
  variable opts[..].update
    var-kind field update
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].inplace
    var-kind field inplace
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].append
    var-kind field append
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].dirs
    var-kind field dirs
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].compress
    var-kind field compress
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].numeric_ids
    var-kind field numeric_ids
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].cvs_exclude
    var-kind field cvs_exclude
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].progress
    var-kind field progress
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].itemize_changes
    var-kind field itemize_changes
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].human_readable
    var-kind field human_readable
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].relative_paths
    var-kind field relative_paths
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 15
  variable opts[..].no_implied_dirs
    var-kind field no_implied_dirs
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].list_only
    var-kind field list_only
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].backup_dir
    var-kind field backup_dir
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 16
  variable opts[..].backup_suffix
    var-kind field backup_suffix
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 17
  variable opts[..].exclude_pattern
    var-kind field exclude_pattern
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 18
  variable opts[..].include_pattern
    var-kind field include_pattern
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 19
  variable opts[..].filter_rule
    var-kind field filter_rule
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 20
  variable opts[..].files_from
    var-kind field files_from
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 21
  variable opts[..].log_file
    var-kind field log_file
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 22
  variable opts[..].password_file
    var-kind field password_file
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 23
  variable opts[..].timeout
    var-kind field timeout
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].port
    var-kind field port
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 24
  variable opts[..].block_size
    var-kind field block_size
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 25
  variable opts[..].max_delete
    var-kind field max_delete
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 26
  variable return
    var-kind variable
    rep-type int
    dec-type int
    comparability 27

ppt ..parse_arguments():::ENTER
  ppt-type enter
  variable argc
    var-kind variable
    rep-type int
    dec-type int
    flags is_param 
    comparability 1
  variable argv
    var-kind variable
    rep-type hashcode
    dec-type char**
    flags is_param 
    comparability 1
  variable argv[..]
    var-kind array
    enclosing-var argv
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 2
  variable opts
    var-kind variable
    rep-type hashcode
    dec-type rsync_options*
    flags is_param 
    comparability 3
  variable opts[..]
    var-kind array
    enclosing-var opts
    array 1
    rep-type hashcode[]
    dec-type rsync_options[]
    comparability 4
  variable opts[..].verbose
    var-kind field verbose
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].quiet
    var-kind field quiet
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].archive
    var-kind field archive
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].recursive
    var-kind field recursive
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].preserve_links
    var-kind field preserve_links
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].preserve_perms
    var-kind field preserve_perms
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].preserve_times
    var-kind field preserve_times
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].preserve_owner
    var-kind field preserve_owner
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].preserve_group
    var-kind field preserve_group
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].preserve_devices
    var-kind field preserve_devices
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].delete_mode
    var-kind field delete_mode
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].delete_before
    var-kind field delete_before
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].delete_during
    var-kind field delete_during
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].delete_after
    var-kind field delete_after
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].force
    var-kind field force
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].dry_run
    var-kind field dry_run
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].checksum
    var-kind field checksum
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].size_only
    var-kind field size_only
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].one_file_system
    var-kind field one_file_system
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].whole_file
    var-kind field whole_file
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 6
  variable opts[..].backup
    var-kind field backup
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].update
    var-kind field update
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].inplace
    var-kind field inplace
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].append
    var-kind field append
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].dirs
    var-kind field dirs
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].compress
    var-kind field compress
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].numeric_ids
    var-kind field numeric_ids
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].cvs_exclude
    var-kind field cvs_exclude
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].progress
    var-kind field progress
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].itemize_changes
    var-kind field itemize_changes
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].human_readable
    var-kind field human_readable
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].relative_paths
    var-kind field relative_paths
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 7
  variable opts[..].no_implied_dirs
    var-kind field no_implied_dirs
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].list_only
    var-kind field list_only
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].backup_dir
    var-kind field backup_dir
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 8
  variable opts[..].backup_suffix
    var-kind field backup_suffix
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 9
  variable opts[..].exclude_pattern
    var-kind field exclude_pattern
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 10
  variable opts[..].include_pattern
    var-kind field include_pattern
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 11
  variable opts[..].filter_rule
    var-kind field filter_rule
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 12
  variable opts[..].files_from
    var-kind field files_from
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 13
  variable opts[..].log_file
    var-kind field log_file
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 14
  variable opts[..].password_file
    var-kind field password_file
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 15
  variable opts[..].timeout
    var-kind field timeout
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].port
    var-kind field port
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 16
  variable opts[..].block_size
    var-kind field block_size
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 17
  variable opts[..].max_delete
    var-kind field max_delete
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 18

ppt ..parse_arguments():::EXIT0
  ppt-type subexit
  variable argc
    var-kind variable
    rep-type int
    dec-type int
    flags is_param 
    comparability 1
  variable argv
    var-kind variable
    rep-type hashcode
    dec-type char**
    flags is_param 
    comparability 1
  variable argv[..]
    var-kind array
    enclosing-var argv
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 2
  variable opts
    var-kind variable
    rep-type hashcode
    dec-type rsync_options*
    flags is_param 
    comparability 3
  variable opts[..]
    var-kind array
    enclosing-var opts
    array 1
    rep-type hashcode[]
    dec-type rsync_options[]
    comparability 4
  variable opts[..].verbose
    var-kind field verbose
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].quiet
    var-kind field quiet
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].archive
    var-kind field archive
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].recursive
    var-kind field recursive
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].preserve_links
    var-kind field preserve_links
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].preserve_perms
    var-kind field preserve_perms
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].preserve_times
    var-kind field preserve_times
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].preserve_owner
    var-kind field preserve_owner
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].preserve_group
    var-kind field preserve_group
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].preserve_devices
    var-kind field preserve_devices
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].delete_mode
    var-kind field delete_mode
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].delete_before
    var-kind field delete_before
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].delete_during
    var-kind field delete_during
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].delete_after
    var-kind field delete_after
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].force
    var-kind field force
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].dry_run
    var-kind field dry_run
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].checksum
    var-kind field checksum
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].size_only
    var-kind field size_only
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].one_file_system
    var-kind field one_file_system
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].whole_file
    var-kind field whole_file
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 6
  variable opts[..].backup
    var-kind field backup
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].update
    var-kind field update
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].inplace
    var-kind field inplace
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].append
    var-kind field append
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].dirs
    var-kind field dirs
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].compress
    var-kind field compress
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].numeric_ids
    var-kind field numeric_ids
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].cvs_exclude
    var-kind field cvs_exclude
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].progress
    var-kind field progress
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].itemize_changes
    var-kind field itemize_changes
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].human_readable
    var-kind field human_readable
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].relative_paths
    var-kind field relative_paths
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 7
  variable opts[..].no_implied_dirs
    var-kind field no_implied_dirs
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].list_only
    var-kind field list_only
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].backup_dir
    var-kind field backup_dir
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 8
  variable opts[..].backup_suffix
    var-kind field backup_suffix
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 9
  variable opts[..].exclude_pattern
    var-kind field exclude_pattern
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 10
  variable opts[..].include_pattern
    var-kind field include_pattern
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 11
  variable opts[..].filter_rule
    var-kind field filter_rule
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 12
  variable opts[..].files_from
    var-kind field files_from
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 13
  variable opts[..].log_file
    var-kind field log_file
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 14
  variable opts[..].password_file
    var-kind field password_file
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 15
  variable opts[..].timeout
    var-kind field timeout
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].port
    var-kind field port
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 16
  variable opts[..].block_size
    var-kind field block_size
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 17
  variable opts[..].max_delete
    var-kind field max_delete
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 18
  variable return
    var-kind variable
    rep-type int
    dec-type int
    comparability 19

ppt ..parse_long_option():::ENTER
  ppt-type enter
  variable opt
    var-kind variable
    rep-type string
    dec-type char*
    flags is_param 
    comparability 1
  variable arg
    var-kind variable
    rep-type string
    dec-type char*
    flags is_param 
    comparability 2
  variable opts
    var-kind variable
    rep-type hashcode
    dec-type rsync_options*
    flags is_param 
    comparability 3
  variable opts[..]
    var-kind array
    enclosing-var opts
    array 1
    rep-type hashcode[]
    dec-type rsync_options[]
    comparability 4
  variable opts[..].verbose
    var-kind field verbose
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].quiet
    var-kind field quiet
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].archive
    var-kind field archive
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 6
  variable opts[..].recursive
    var-kind field recursive
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 7
  variable opts[..].preserve_links
    var-kind field preserve_links
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 8
  variable opts[..].preserve_perms
    var-kind field preserve_perms
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 9
  variable opts[..].preserve_times
    var-kind field preserve_times
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 10
  variable opts[..].preserve_owner
    var-kind field preserve_owner
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 11
  variable opts[..].preserve_group
    var-kind field preserve_group
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 12
  variable opts[..].preserve_devices
    var-kind field preserve_devices
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 13
  variable opts[..].delete_mode
    var-kind field delete_mode
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].delete_before
    var-kind field delete_before
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].delete_during
    var-kind field delete_during
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].delete_after
    var-kind field delete_after
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].force
    var-kind field force
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].dry_run
    var-kind field dry_run
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].checksum
    var-kind field checksum
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].size_only
    var-kind field size_only
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].one_file_system
    var-kind field one_file_system
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].whole_file
    var-kind field whole_file
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 14
  variable opts[..].backup
    var-kind field backup
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].update
    var-kind field update
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].inplace
    var-kind field inplace
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].append
    var-kind field append
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].dirs
    var-kind field dirs
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].compress
    var-kind field compress
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].numeric_ids
    var-kind field numeric_ids
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].cvs_exclude
    var-kind field cvs_exclude
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].progress
    var-kind field progress
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].itemize_changes
    var-kind field itemize_changes
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].human_readable
    var-kind field human_readable
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].relative_paths
    var-kind field relative_paths
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 15
  variable opts[..].no_implied_dirs
    var-kind field no_implied_dirs
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].list_only
    var-kind field list_only
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].backup_dir
    var-kind field backup_dir
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 2
  variable opts[..].backup_suffix
    var-kind field backup_suffix
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 16
  variable opts[..].exclude_pattern
    var-kind field exclude_pattern
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 17
  variable opts[..].include_pattern
    var-kind field include_pattern
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 18
  variable opts[..].filter_rule
    var-kind field filter_rule
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 19
  variable opts[..].files_from
    var-kind field files_from
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 20
  variable opts[..].log_file
    var-kind field log_file
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 21
  variable opts[..].password_file
    var-kind field password_file
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 22
  variable opts[..].timeout
    var-kind field timeout
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].port
    var-kind field port
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 23
  variable opts[..].block_size
    var-kind field block_size
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 24
  variable opts[..].max_delete
    var-kind field max_delete
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 25

ppt ..parse_long_option():::EXIT0
  ppt-type subexit
  variable opt
    var-kind variable
    rep-type string
    dec-type char*
    flags is_param 
    comparability 1
  variable arg
    var-kind variable
    rep-type string
    dec-type char*
    flags is_param 
    comparability 2
  variable opts
    var-kind variable
    rep-type hashcode
    dec-type rsync_options*
    flags is_param 
    comparability 3
  variable opts[..]
    var-kind array
    enclosing-var opts
    array 1
    rep-type hashcode[]
    dec-type rsync_options[]
    comparability 4
  variable opts[..].verbose
    var-kind field verbose
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].quiet
    var-kind field quiet
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].archive
    var-kind field archive
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 6
  variable opts[..].recursive
    var-kind field recursive
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 7
  variable opts[..].preserve_links
    var-kind field preserve_links
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 8
  variable opts[..].preserve_perms
    var-kind field preserve_perms
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 9
  variable opts[..].preserve_times
    var-kind field preserve_times
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 10
  variable opts[..].preserve_owner
    var-kind field preserve_owner
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 11
  variable opts[..].preserve_group
    var-kind field preserve_group
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 12
  variable opts[..].preserve_devices
    var-kind field preserve_devices
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 13
  variable opts[..].delete_mode
    var-kind field delete_mode
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].delete_before
    var-kind field delete_before
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].delete_during
    var-kind field delete_during
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].delete_after
    var-kind field delete_after
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].force
    var-kind field force
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].dry_run
    var-kind field dry_run
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].checksum
    var-kind field checksum
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].size_only
    var-kind field size_only
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].one_file_system
    var-kind field one_file_system
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].whole_file
    var-kind field whole_file
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 14
  variable opts[..].backup
    var-kind field backup
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].update
    var-kind field update
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].inplace
    var-kind field inplace
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].append
    var-kind field append
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].dirs
    var-kind field dirs
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].compress
    var-kind field compress
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].numeric_ids
    var-kind field numeric_ids
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].cvs_exclude
    var-kind field cvs_exclude
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].progress
    var-kind field progress
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].itemize_changes
    var-kind field itemize_changes
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].human_readable
    var-kind field human_readable
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].relative_paths
    var-kind field relative_paths
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 15
  variable opts[..].no_implied_dirs
    var-kind field no_implied_dirs
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].list_only
    var-kind field list_only
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].backup_dir
    var-kind field backup_dir
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 2
  variable opts[..].backup_suffix
    var-kind field backup_suffix
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 16
  variable opts[..].exclude_pattern
    var-kind field exclude_pattern
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 17
  variable opts[..].include_pattern
    var-kind field include_pattern
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 18
  variable opts[..].filter_rule
    var-kind field filter_rule
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 19
  variable opts[..].files_from
    var-kind field files_from
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 20
  variable opts[..].log_file
    var-kind field log_file
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 21
  variable opts[..].password_file
    var-kind field password_file
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 22
  variable opts[..].timeout
    var-kind field timeout
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].port
    var-kind field port
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 23
  variable opts[..].block_size
    var-kind field block_size
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 24
  variable opts[..].max_delete
    var-kind field max_delete
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 25
  variable return
    var-kind variable
    rep-type int
    dec-type int
    comparability 26

ppt ..parse_short_option():::ENTER
  ppt-type enter
  variable opt
    var-kind variable
    rep-type int
    dec-type char
    flags is_param 
    comparability 1
  variable opts
    var-kind variable
    rep-type hashcode
    dec-type rsync_options*
    flags is_param 
    comparability 2
  variable opts[..]
    var-kind array
    enclosing-var opts
    array 1
    rep-type hashcode[]
    dec-type rsync_options[]
    comparability 3
  variable opts[..].verbose
    var-kind field verbose
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].quiet
    var-kind field quiet
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].archive
    var-kind field archive
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].recursive
    var-kind field recursive
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].preserve_links
    var-kind field preserve_links
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].preserve_perms
    var-kind field preserve_perms
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].preserve_times
    var-kind field preserve_times
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].preserve_owner
    var-kind field preserve_owner
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].preserve_group
    var-kind field preserve_group
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].preserve_devices
    var-kind field preserve_devices
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].delete_mode
    var-kind field delete_mode
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].delete_before
    var-kind field delete_before
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].delete_during
    var-kind field delete_during
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].delete_after
    var-kind field delete_after
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].force
    var-kind field force
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].dry_run
    var-kind field dry_run
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].checksum
    var-kind field checksum
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].size_only
    var-kind field size_only
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].one_file_system
    var-kind field one_file_system
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].whole_file
    var-kind field whole_file
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].backup
    var-kind field backup
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].update
    var-kind field update
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].inplace
    var-kind field inplace
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].append
    var-kind field append
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].dirs
    var-kind field dirs
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].compress
    var-kind field compress
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].numeric_ids
    var-kind field numeric_ids
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].cvs_exclude
    var-kind field cvs_exclude
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].progress
    var-kind field progress
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].itemize_changes
    var-kind field itemize_changes
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].human_readable
    var-kind field human_readable
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].relative_paths
    var-kind field relative_paths
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 6
  variable opts[..].no_implied_dirs
    var-kind field no_implied_dirs
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].list_only
    var-kind field list_only
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].backup_dir
    var-kind field backup_dir
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 7
  variable opts[..].backup_suffix
    var-kind field backup_suffix
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 8
  variable opts[..].exclude_pattern
    var-kind field exclude_pattern
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 9
  variable opts[..].include_pattern
    var-kind field include_pattern
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 10
  variable opts[..].filter_rule
    var-kind field filter_rule
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 11
  variable opts[..].files_from
    var-kind field files_from
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 12
  variable opts[..].log_file
    var-kind field log_file
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 13
  variable opts[..].password_file
    var-kind field password_file
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 14
  variable opts[..].timeout
    var-kind field timeout
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].port
    var-kind field port
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 15
  variable opts[..].block_size
    var-kind field block_size
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 16
  variable opts[..].max_delete
    var-kind field max_delete
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 17

ppt ..parse_short_option():::EXIT0
  ppt-type subexit
  variable opt
    var-kind variable
    rep-type int
    dec-type char
    flags is_param 
    comparability 1
  variable opts
    var-kind variable
    rep-type hashcode
    dec-type rsync_options*
    flags is_param 
    comparability 2
  variable opts[..]
    var-kind array
    enclosing-var opts
    array 1
    rep-type hashcode[]
    dec-type rsync_options[]
    comparability 3
  variable opts[..].verbose
    var-kind field verbose
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].quiet
    var-kind field quiet
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].archive
    var-kind field archive
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].recursive
    var-kind field recursive
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].preserve_links
    var-kind field preserve_links
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].preserve_perms
    var-kind field preserve_perms
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].preserve_times
    var-kind field preserve_times
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].preserve_owner
    var-kind field preserve_owner
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].preserve_group
    var-kind field preserve_group
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].preserve_devices
    var-kind field preserve_devices
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].delete_mode
    var-kind field delete_mode
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].delete_before
    var-kind field delete_before
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].delete_during
    var-kind field delete_during
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].delete_after
    var-kind field delete_after
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].force
    var-kind field force
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].dry_run
    var-kind field dry_run
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].checksum
    var-kind field checksum
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].size_only
    var-kind field size_only
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].one_file_system
    var-kind field one_file_system
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].whole_file
    var-kind field whole_file
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].backup
    var-kind field backup
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].update
    var-kind field update
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].inplace
    var-kind field inplace
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].append
    var-kind field append
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].dirs
    var-kind field dirs
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].compress
    var-kind field compress
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].numeric_ids
    var-kind field numeric_ids
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].cvs_exclude
    var-kind field cvs_exclude
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].progress
    var-kind field progress
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].itemize_changes
    var-kind field itemize_changes
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].human_readable
    var-kind field human_readable
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].relative_paths
    var-kind field relative_paths
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 6
  variable opts[..].no_implied_dirs
    var-kind field no_implied_dirs
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].list_only
    var-kind field list_only
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].backup_dir
    var-kind field backup_dir
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 7
  variable opts[..].backup_suffix
    var-kind field backup_suffix
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 8
  variable opts[..].exclude_pattern
    var-kind field exclude_pattern
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 9
  variable opts[..].include_pattern
    var-kind field include_pattern
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 10
  variable opts[..].filter_rule
    var-kind field filter_rule
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 11
  variable opts[..].files_from
    var-kind field files_from
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 12
  variable opts[..].log_file
    var-kind field log_file
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 13
  variable opts[..].password_file
    var-kind field password_file
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 14
  variable opts[..].timeout
    var-kind field timeout
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].port
    var-kind field port
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 15
  variable opts[..].block_size
    var-kind field block_size
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 16
  variable opts[..].max_delete
    var-kind field max_delete
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 17
  variable return
    var-kind variable
    rep-type int
    dec-type int
    comparability 18

ppt ..init_options():::ENTER
  ppt-type enter
  variable opts
    var-kind variable
    rep-type hashcode
    dec-type rsync_options*
    flags is_param 
    comparability 1
  variable opts[..]
    var-kind array
    enclosing-var opts
    array 1
    rep-type hashcode[]
    dec-type rsync_options[]
    comparability 2
  variable opts[..].verbose
    var-kind field verbose
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].quiet
    var-kind field quiet
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].archive
    var-kind field archive
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].recursive
    var-kind field recursive
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].preserve_links
    var-kind field preserve_links
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].preserve_perms
    var-kind field preserve_perms
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].preserve_times
    var-kind field preserve_times
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].preserve_owner
    var-kind field preserve_owner
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].preserve_group
    var-kind field preserve_group
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].preserve_devices
    var-kind field preserve_devices
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].delete_mode
    var-kind field delete_mode
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].delete_before
    var-kind field delete_before
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].delete_during
    var-kind field delete_during
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].delete_after
    var-kind field delete_after
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].force
    var-kind field force
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].dry_run
    var-kind field dry_run
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].checksum
    var-kind field checksum
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].size_only
    var-kind field size_only
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].one_file_system
    var-kind field one_file_system
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].whole_file
    var-kind field whole_file
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].backup
    var-kind field backup
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].update
    var-kind field update
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].inplace
    var-kind field inplace
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].append
    var-kind field append
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].dirs
    var-kind field dirs
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].compress
    var-kind field compress
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].numeric_ids
    var-kind field numeric_ids
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].cvs_exclude
    var-kind field cvs_exclude
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].progress
    var-kind field progress
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].itemize_changes
    var-kind field itemize_changes
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].human_readable
    var-kind field human_readable
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].relative_paths
    var-kind field relative_paths
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].no_implied_dirs
    var-kind field no_implied_dirs
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].list_only
    var-kind field list_only
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].backup_dir
    var-kind field backup_dir
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 6
  variable opts[..].backup_suffix
    var-kind field backup_suffix
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 7
  variable opts[..].exclude_pattern
    var-kind field exclude_pattern
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 8
  variable opts[..].include_pattern
    var-kind field include_pattern
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 9
  variable opts[..].filter_rule
    var-kind field filter_rule
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 10
  variable opts[..].files_from
    var-kind field files_from
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 11
  variable opts[..].log_file
    var-kind field log_file
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 12
  variable opts[..].password_file
    var-kind field password_file
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 13
  variable opts[..].timeout
    var-kind field timeout
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].port
    var-kind field port
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 14
  variable opts[..].block_size
    var-kind field block_size
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 15
  variable opts[..].max_delete
    var-kind field max_delete
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 16

ppt ..init_options():::EXIT0
  ppt-type subexit
  variable opts
    var-kind variable
    rep-type hashcode
    dec-type rsync_options*
    flags is_param 
    comparability 1
  variable opts[..]
    var-kind array
    enclosing-var opts
    array 1
    rep-type hashcode[]
    dec-type rsync_options[]
    comparability 2
  variable opts[..].verbose
    var-kind field verbose
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].quiet
    var-kind field quiet
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].archive
    var-kind field archive
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].recursive
    var-kind field recursive
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].preserve_links
    var-kind field preserve_links
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].preserve_perms
    var-kind field preserve_perms
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].preserve_times
    var-kind field preserve_times
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].preserve_owner
    var-kind field preserve_owner
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].preserve_group
    var-kind field preserve_group
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].preserve_devices
    var-kind field preserve_devices
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].delete_mode
    var-kind field delete_mode
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].delete_before
    var-kind field delete_before
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].delete_during
    var-kind field delete_during
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].delete_after
    var-kind field delete_after
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].force
    var-kind field force
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].dry_run
    var-kind field dry_run
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].checksum
    var-kind field checksum
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].size_only
    var-kind field size_only
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].one_file_system
    var-kind field one_file_system
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].whole_file
    var-kind field whole_file
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 4
  variable opts[..].backup
    var-kind field backup
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].update
    var-kind field update
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].inplace
    var-kind field inplace
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].append
    var-kind field append
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].dirs
    var-kind field dirs
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].compress
    var-kind field compress
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].numeric_ids
    var-kind field numeric_ids
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].cvs_exclude
    var-kind field cvs_exclude
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].progress
    var-kind field progress
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].itemize_changes
    var-kind field itemize_changes
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].human_readable
    var-kind field human_readable
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].relative_paths
    var-kind field relative_paths
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 5
  variable opts[..].no_implied_dirs
    var-kind field no_implied_dirs
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].list_only
    var-kind field list_only
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].backup_dir
    var-kind field backup_dir
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 6
  variable opts[..].backup_suffix
    var-kind field backup_suffix
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 7
  variable opts[..].exclude_pattern
    var-kind field exclude_pattern
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 8
  variable opts[..].include_pattern
    var-kind field include_pattern
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 9
  variable opts[..].filter_rule
    var-kind field filter_rule
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 10
  variable opts[..].files_from
    var-kind field files_from
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 11
  variable opts[..].log_file
    var-kind field log_file
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 12
  variable opts[..].password_file
    var-kind field password_file
    enclosing-var opts[..]
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 13
  variable opts[..].timeout
    var-kind field timeout
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 3
  variable opts[..].port
    var-kind field port
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 14
  variable opts[..].block_size
    var-kind field block_size
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 15
  variable opts[..].max_delete
    var-kind field max_delete
    enclosing-var opts[..]
    array 1
    rep-type int[]
    dec-type int[]
    comparability 16

