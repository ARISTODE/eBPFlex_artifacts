# FFmpeg libavfilter Daikon Analysis Summary

## Overview
This analysis used Daikon to discover invariants in FFmpeg's libavfilter module, focusing on the filter graph API which is core to FFmpeg's video/audio processing pipeline.

## Key API Functions Analyzed

### 1. Graph Management
- `avfilter_graph_alloc()` - Creates new filter graph
- `avfilter_graph_free()` - Frees filter graph
- `avfilter_graph_config()` - Configures/validates graph
- `avfilter_graph_set_auto_convert()` - Sets format conversion mode

### 2. Filter Operations  
- `avfilter_get_by_name()` - Looks up filter by name
- `avfilter_graph_create_filter()` - Creates filter instance
- `avfilter_link()` - Connects two filters

### 3. Buffer Operations
- `av_buffersrc_add_frame_flags()` - Adds frame to source
- `av_buffersink_get_frame()` - Gets frame from sink
- `av_buffersrc_parameters_set()` - Sets source parameters

## Discovered Invariants

### Graph Structure Invariants
1. **Initial State**
   - New graphs always have `nb_filters = 0`
   - Auto-convert is enabled by default (`disable_auto_convert = 0`)
   - Graph starts unconfigured

2. **Filter Constraints**
   - Source filters (e.g., "buffer") have `nb_inputs = 0, nb_outputs = 1`
   - Sink filters (e.g., "buffersink") have `nb_inputs = 1, nb_outputs = 0`
   - Processing filters have `nb_inputs >= 1, nb_outputs >= 1`
   - Overlay filter specifically has `nb_inputs = 2, nb_outputs = 1`

3. **Configuration Rules**
   - `avfilter_graph_config()` returns 0 on success, negative on error
   - Common error: `-22 (EINVAL)` for unconnected filters
   - All filter inputs must be connected (except sources)
   - All filter outputs must be connected (except sinks)

### Linking Invariants
1. **Link Properties**
   - Default format is 0 (YUV420P for video)
   - Links inherit dimensions from source
   - Complex graphs may add format conversion filters automatically

2. **Connection Rules**
   - Source pad index must be < source filter's `nb_outputs`
   - Destination pad index must be < destination filter's `nb_inputs`
   - Each pad can only have one connection

### Memory Management
1. **Allocation Patterns**
   - All successful allocations return non-NULL pointers
   - `avfilter_graph_free()` sets pointer to NULL
   - Filter contexts are owned by the graph

## Practical Applications

### 1. Input Validation
```c
// Invariant: filter must exist before creating instance
const AVFilter *filter = avfilter_get_by_name(name);
if (!filter) {
    // Handle error - invalid filter name
}

// Invariant: all inputs must be connected
if (avfilter_graph_config(graph, NULL) < 0) {
    // Graph has unconnected filters
}
```

### 2. Graph Construction Pattern
```c
// Invariant-based construction order:
// 1. Create graph
// 2. Create all filters
// 3. Link all connections
// 4. Configure graph
// 5. Process frames
```

### 3. Error Detection
- Check return values (0 = success, negative = error)
- Verify filter existence before use
- Ensure complete connectivity before configuration

## Test Results

### Simple Chain (buffer -> scale -> buffersink)
- 3 filters created successfully
- 2 links established
- Output dimensions: 160x120 (scaled from 320x240)

### Complex Graph (2 sources -> overlay -> sink)
- 5 filters created, 6 after auto-conversion
- 4 explicit links created
- Automatic format conversion added

### Error Cases
- Non-existent filter returns NULL
- Unconnected graph returns -22 (EINVAL)

## Files Generated
1. `filter_graph_test.c` - Simplified filter graph implementation
2. `ffmpeg_wrapper_test.c` - Wrapper around actual FFmpeg APIs
3. `filter_graph.dtrace` - Execution trace (527KB)
4. `filter_graph_invariants.txt` - Full invariant list (2307 lines)
5. `filter_graph_invariants_summary.txt` - Key invariants summary

## Conclusions
The invariants discovered provide valuable insights into:
- Proper API usage patterns
- Error handling requirements
- Memory management contracts
- Graph connectivity constraints

These can be used to:
- Generate better API documentation
- Create validation tools
- Debug filter graph issues
- Ensure robust error handling in applications using libavfilter