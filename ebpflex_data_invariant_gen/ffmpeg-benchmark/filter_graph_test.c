/*
 * Focused test program for libavfilter graph operations
 * This program simulates the core filter graph data structures and operations
 * to enable Daikon analysis of invariants
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define MAX_FILTERS 32
#define MAX_PADS 8
#define MAX_LINKS 64

// Simplified structures mimicking FFmpeg's design
typedef struct FilterPad {
    char name[32];
    int type; // 0=video, 1=audio
    int format;
} FilterPad;

typedef struct FilterLink {
    struct FilterContext *src;
    struct FilterContext *dst;
    int src_pad;
    int dst_pad;
    int format;
    int w, h; // for video
    int sample_rate; // for audio
    int channels;
} FilterLink;

typedef struct FilterContext {
    char name[64];
    char filter_name[32];
    int nb_inputs;
    int nb_outputs;
    FilterPad inputs[MAX_PADS];
    FilterPad outputs[MAX_PADS];
    FilterLink *input_links[MAX_PADS];
    FilterLink *output_links[MAX_PADS];
    int configured;
    void *priv; // private data
} FilterContext;

typedef struct FilterGraph {
    int nb_filters;
    FilterContext *filters[MAX_FILTERS];
    int nb_links;
    FilterLink *links[MAX_LINKS];
    int configured;
    int auto_convert;
} FilterGraph;

// Function to create a new filter graph
FilterGraph* create_filter_graph() {
    FilterGraph *graph = (FilterGraph*)calloc(1, sizeof(FilterGraph));
    assert(graph != NULL);
    graph->nb_filters = 0;
    graph->nb_links = 0;
    graph->configured = 0;
    graph->auto_convert = 1;
    return graph;
}

// Function to free a filter graph
void free_filter_graph(FilterGraph *graph) {
    if (!graph) return;
    
    // Free all filters
    for (int i = 0; i < graph->nb_filters; i++) {
        free(graph->filters[i]);
    }
    
    // Free all links
    for (int i = 0; i < graph->nb_links; i++) {
        free(graph->links[i]);
    }
    
    free(graph);
}

// Function to create a filter context
FilterContext* create_filter(const char *filter_name, const char *instance_name) {
    FilterContext *ctx = (FilterContext*)calloc(1, sizeof(FilterContext));
    assert(ctx != NULL);
    
    strncpy(ctx->filter_name, filter_name, sizeof(ctx->filter_name) - 1);
    strncpy(ctx->name, instance_name, sizeof(ctx->name) - 1);
    ctx->configured = 0;
    
    // Set up filter properties based on type
    if (strcmp(filter_name, "buffer") == 0) {
        ctx->nb_inputs = 0;
        ctx->nb_outputs = 1;
        strcpy(ctx->outputs[0].name, "default");
        ctx->outputs[0].type = 0; // video
    } else if (strcmp(filter_name, "buffersink") == 0) {
        ctx->nb_inputs = 1;
        ctx->nb_outputs = 0;
        strcpy(ctx->inputs[0].name, "default");
        ctx->inputs[0].type = 0; // video
    } else if (strcmp(filter_name, "scale") == 0) {
        ctx->nb_inputs = 1;
        ctx->nb_outputs = 1;
        strcpy(ctx->inputs[0].name, "default");
        strcpy(ctx->outputs[0].name, "default");
        ctx->inputs[0].type = 0;
        ctx->outputs[0].type = 0;
    } else if (strcmp(filter_name, "overlay") == 0) {
        ctx->nb_inputs = 2;
        ctx->nb_outputs = 1;
        strcpy(ctx->inputs[0].name, "main");
        strcpy(ctx->inputs[1].name, "overlay");
        strcpy(ctx->outputs[0].name, "default");
    }
    
    return ctx;
}

// Function to add a filter to the graph
int add_filter_to_graph(FilterGraph *graph, FilterContext *filter) {
    if (!graph || !filter) return -1;
    if (graph->nb_filters >= MAX_FILTERS) return -1;
    
    graph->filters[graph->nb_filters++] = filter;
    graph->configured = 0; // Graph needs reconfiguration
    return 0;
}

// Function to link two filters
int link_filters(FilterContext *src, int src_pad, 
                FilterContext *dst, int dst_pad,
                FilterGraph *graph) {
    if (!src || !dst || !graph) return -1;
    if (src_pad >= src->nb_outputs || dst_pad >= dst->nb_inputs) return -1;
    if (graph->nb_links >= MAX_LINKS) return -1;
    
    FilterLink *link = (FilterLink*)calloc(1, sizeof(FilterLink));
    assert(link != NULL);
    
    link->src = src;
    link->dst = dst;
    link->src_pad = src_pad;
    link->dst_pad = dst_pad;
    
    // Default video properties
    link->format = 0; // YUV420P
    link->w = 640;
    link->h = 480;
    
    src->output_links[src_pad] = link;
    dst->input_links[dst_pad] = link;
    graph->links[graph->nb_links++] = link;
    
    graph->configured = 0;
    return 0;
}

// Function to configure the filter graph
int configure_graph(FilterGraph *graph) {
    if (!graph) return -1;
    if (graph->configured) return 0;
    
    // Validate all filters are connected properly
    for (int i = 0; i < graph->nb_filters; i++) {
        FilterContext *f = graph->filters[i];
        
        // Check inputs
        for (int j = 0; j < f->nb_inputs; j++) {
            if (!f->input_links[j]) {
                printf("Filter %s input %d not connected\n", f->name, j);
                return -1;
            }
        }
        
        // Check outputs (except for sinks)
        if (strcmp(f->filter_name, "buffersink") != 0) {
            for (int j = 0; j < f->nb_outputs; j++) {
                if (!f->output_links[j]) {
                    printf("Filter %s output %d not connected\n", f->name, j);
                    return -1;
                }
            }
        }
        
        f->configured = 1;
    }
    
    graph->configured = 1;
    return 0;
}

// Function to process a frame through the graph
int process_frame(FilterGraph *graph, int frame_num) {
    if (!graph || !graph->configured) return -1;
    
    printf("Processing frame %d through graph\n", frame_num);
    
    // Simulate frame processing through each filter
    for (int i = 0; i < graph->nb_filters; i++) {
        FilterContext *f = graph->filters[i];
        printf("  Filter %s (%s) processing frame %d\n", 
               f->name, f->filter_name, frame_num);
    }
    
    return 0;
}

// Test scenarios
void test_simple_chain() {
    printf("\n=== Test: Simple Filter Chain ===\n");
    
    FilterGraph *graph = create_filter_graph();
    
    // Create filters
    FilterContext *src = create_filter("buffer", "src");
    FilterContext *scale = create_filter("scale", "scale");
    FilterContext *sink = create_filter("buffersink", "sink");
    
    // Add to graph
    add_filter_to_graph(graph, src);
    add_filter_to_graph(graph, scale);
    add_filter_to_graph(graph, sink);
    
    // Link filters
    link_filters(src, 0, scale, 0, graph);
    link_filters(scale, 0, sink, 0, graph);
    
    // Configure
    int ret = configure_graph(graph);
    printf("Graph configuration: %s\n", ret == 0 ? "success" : "failed");
    
    // Process some frames
    for (int i = 0; i < 5; i++) {
        process_frame(graph, i);
    }
    
    free_filter_graph(graph);
}

void test_complex_graph() {
    printf("\n=== Test: Complex Filter Graph ===\n");
    
    FilterGraph *graph = create_filter_graph();
    
    // Create filters for overlay
    FilterContext *src1 = create_filter("buffer", "main_src");
    FilterContext *src2 = create_filter("buffer", "overlay_src");
    FilterContext *scale1 = create_filter("scale", "scale_main");
    FilterContext *scale2 = create_filter("scale", "scale_overlay");
    FilterContext *overlay = create_filter("overlay", "overlay");
    FilterContext *sink = create_filter("buffersink", "sink");
    
    // Add all filters
    add_filter_to_graph(graph, src1);
    add_filter_to_graph(graph, src2);
    add_filter_to_graph(graph, scale1);
    add_filter_to_graph(graph, scale2);
    add_filter_to_graph(graph, overlay);
    add_filter_to_graph(graph, sink);
    
    // Create links
    link_filters(src1, 0, scale1, 0, graph);
    link_filters(src2, 0, scale2, 0, graph);
    link_filters(scale1, 0, overlay, 0, graph); // main input
    link_filters(scale2, 0, overlay, 1, graph); // overlay input
    link_filters(overlay, 0, sink, 0, graph);
    
    // Configure
    int ret = configure_graph(graph);
    printf("Graph configuration: %s\n", ret == 0 ? "success" : "failed");
    printf("Total filters: %d, Total links: %d\n", 
           graph->nb_filters, graph->nb_links);
    
    // Process frames
    for (int i = 0; i < 3; i++) {
        process_frame(graph, i);
    }
    
    free_filter_graph(graph);
}

void test_invalid_graph() {
    printf("\n=== Test: Invalid Graph Configuration ===\n");
    
    FilterGraph *graph = create_filter_graph();
    
    // Create filters but don't connect them all
    FilterContext *src = create_filter("buffer", "src");
    FilterContext *scale = create_filter("scale", "scale");
    FilterContext *sink = create_filter("buffersink", "sink");
    
    add_filter_to_graph(graph, src);
    add_filter_to_graph(graph, scale);
    add_filter_to_graph(graph, sink);
    
    // Only partially link
    link_filters(src, 0, scale, 0, graph);
    // Missing link from scale to sink
    
    // Try to configure - should fail
    int ret = configure_graph(graph);
    printf("Graph configuration: %s (expected failure)\n", 
           ret == 0 ? "success" : "failed");
    
    free_filter_graph(graph);
}

void test_large_graph() {
    printf("\n=== Test: Large Filter Graph ===\n");
    
    FilterGraph *graph = create_filter_graph();
    
    // Create source and sink
    FilterContext *src = create_filter("buffer", "src");
    FilterContext *sink = create_filter("buffersink", "sink");
    add_filter_to_graph(graph, src);
    
    // Create chain of scale filters
    FilterContext *prev = src;
    for (int i = 0; i < 10; i++) {
        char name[32];
        sprintf(name, "scale_%d", i);
        FilterContext *scale = create_filter("scale", name);
        add_filter_to_graph(graph, scale);
        link_filters(prev, 0, scale, 0, graph);
        prev = scale;
    }
    
    add_filter_to_graph(graph, sink);
    link_filters(prev, 0, sink, 0, graph);
    
    // Configure
    int ret = configure_graph(graph);
    printf("Graph configuration: %s\n", ret == 0 ? "success" : "failed");
    printf("Total filters: %d, Total links: %d\n", 
           graph->nb_filters, graph->nb_links);
    
    // Process one frame through the long chain
    process_frame(graph, 0);
    
    free_filter_graph(graph);
}

int main() {
    printf("Filter Graph Test Program\n");
    printf("========================\n");
    
    test_simple_chain();
    test_complex_graph();
    test_invalid_graph();
    test_large_graph();
    
    printf("\nAll tests completed.\n");
    return 0;
}