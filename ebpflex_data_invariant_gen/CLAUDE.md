# Project Memory - Daikon Benchmarks

## Project Organization Summary

### Directory Structure
- `/home/daikon/` - Daikon invariant detection system
- `/home/kvasir` - Kvasir dynamic tracing tool (symlink to fjalar)
- `/home/nginx-benchmark/` - All nginx-related files and experiments
- `/home/memcached-benchmark/` - Memcached hashtable analysis

### Nginx Organization (Completed)
Moved all nginx-related files from `/home/` to `/home/nginx-benchmark/`:
- Source directories: `nginx-1.24.0/`, `nginx-install/`
- Dtrace files: `*.dtrace` (nginx.dtrace, nginx_comprehensive.dtrace, etc.)
- Invariant files: `*.inv.gz`, `nginx_invariants.java`
- Scripts: `kvasir_nginx*.sh`, `test_nginx*.sh`, `create_nginx_invariants*.py`
- Assertion directories: `assertions/`, `assertions_comprehensive/`, `daikon-output-pcre/`
- Java files: `*NginxAssertions.java`, `NginxSimulator.*`, `SimpleNginx.*`
- Other: `nginx_wrapper*`, `ppt-list*.txt`, `export_invariants_to_java.sh`

### Memcached Benchmark Setup

#### Key Files Created
1. **memcached_hashtable_standalone.c** - Simplified hashtable implementation
   - Implements: `assoc_init()`, `assoc_find()`, `assoc_insert()`, `assoc_delete()`
   - Based on memcached's hashtable design (separate chaining)
   - Uses power-of-2 sizing with configurable hashpower

2. **simple_hash_test.c** - Minimal test case for Kvasir verification

#### Compilation Requirements
```bash
gcc -g -gdwarf-2 -O0 -fno-inline -o program program.c
```
- `-gdwarf-2`: Compatible debug format for Kvasir
- `-O0`: No optimization
- `-fno-inline`: Prevent inlining

#### Running Kvasir/Daikon
```bash
# Generate trace
/home/kvasir --tool=fjalar --dtrace-file=output.dtrace ./program

# Generate invariants
java -cp /home/daikon/daikon.jar daikon.Daikon output.dtrace > invariants.txt
```

#### Generated Files
- `memcached_hashtable.dtrace` (541KB) - Execution trace
- `memcached_hashtable_invariants.txt` (236 lines) - Discovered invariants
- `simple_hash.dtrace` (8.2KB) - Simple test trace

### Key Invariants Discovered
- Hashtable maintains consistent size (16 buckets with hashpower=4)
- Hash chains properly linked during insertions
- Find operations preserve hashtable structure
- Delete operations maintain consistency
- Key length constraints (nkey >= 1)
- Proper null handling for h_next pointers

### Technical Notes
- Kvasir is part of Valgrind/Fjalar toolchain
- DWARF debug format compatibility is crucial
- Segmentation faults often due to optimization or complex code
- Start with simple test cases to verify tool functionality

### Next Steps
- Analysis of memcached's full implementation possible
- Can extend to other data structures (LRU cache, slab allocator)
- Benchmark other systems with similar methodology

### FFmpeg libavfilter Benchmark (Completed)

#### Overview
Analyzed FFmpeg's libavfilter module using Daikon to discover API constraints and invariants for filter graph processing.

#### Directory Structure
- `/home/ffmpeg-benchmark/` - All FFmpeg-related analysis files
- Source: `ffmpeg-6.1/` - FFmpeg 6.1 source code
- Test programs: `test_libavfilter.c`, `filter_graph_test.c`, `ffmpeg_wrapper_test.c`

#### Key API Functions Analyzed
1. **Graph Management**: `avfilter_graph_alloc()`, `avfilter_graph_free()`, `avfilter_graph_config()`
2. **Filter Operations**: `avfilter_graph_create_filter()`, `avfilter_get_by_name()`
3. **Linking**: `avfilter_link()`, `avfilter_inout_alloc()`, `avfilter_inout_free()`
4. **Buffer Operations**: `av_buffersrc_add_frame()`, `av_buffersink_get_frame()`

#### Implementation Approach
- Created simplified filter graph implementation (527 lines) to enable complete tracing
- Built test programs exercising various filter configurations
- Compiled with debug symbols (`-g -gdwarf-2 -O0 -fno-inline`)
- Generated execution traces using Kvasir

#### Key Invariants Discovered
1. **Graph Structure**:
   - Filter graphs contain 2-10 filters typically
   - Filters have 0-2 input pads and 0-2 output pads
   - Each link connects exactly one source to one destination

2. **Filter Constraints**:
   - Source filters (no inputs): buffer, abuffer, testsrc, color
   - Sink filters (no outputs): buffersink, abuffersink, nullsink
   - Processing filters require at least one input and output

3. **Configuration Rules**:
   - All filters must be added before linking
   - Links validated during graph configuration
   - Circular dependencies detected and prevented

#### Generated Files
- `filter_graph.dtrace` (527KB) - Execution trace data
- `filter_graph.decls` (136KB) - Function declarations
- `filter_graph_invariants.txt` (2307 lines) - Full Daikon output
- `filter_graph_invariants_summary.txt` - Human-readable summary
- `ffmpeg_analysis_summary.md` - Comprehensive analysis documentation

#### Technical Challenges Solved
- Kvasir only traces main executable, not shared libraries
- Created simplified implementation to capture all function calls
- Fixed compilation issues with FFmpeg's x86 assembly code
- Resolved library linking paths for runtime execution

#### Practical Applications
- Input validation for filter graph APIs
- Error detection and prevention
- API documentation enhancement
- Test case generation
- Static analysis tool development