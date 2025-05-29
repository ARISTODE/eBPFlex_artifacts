/*
 * FFmpeg libavfilter wrapper for Daikon analysis
 * This wraps key libavfilter functions to expose their behavior
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libavfilter/avfilter.h>
#include <libavfilter/buffersrc.h>
#include <libavfilter/buffersink.h>
#include <libavutil/opt.h>

// Wrapper for avfilter_graph_alloc
AVFilterGraph* wrapper_graph_alloc() {
    AVFilterGraph *graph = avfilter_graph_alloc();
    printf("Graph alloc: %p\n", (void*)graph);
    return graph;
}

// Wrapper for avfilter_graph_free
void wrapper_graph_free(AVFilterGraph **graph) {
    printf("Graph free: %p\n", graph ? (void*)*graph : NULL);
    avfilter_graph_free(graph);
}

// Wrapper for avfilter_get_by_name
const AVFilter* wrapper_get_filter(const char *name) {
    const AVFilter *filter = avfilter_get_by_name(name);
    printf("Get filter '%s': %p\n", name, (void*)filter);
    return filter;
}

// Wrapper for avfilter_graph_create_filter
int wrapper_create_filter(AVFilterGraph *graph, AVFilterContext **ctx,
                         const AVFilter *filter, const char *name,
                         const char *args) {
    int ret = avfilter_graph_create_filter(ctx, filter, name, args, NULL, graph);
    printf("Create filter '%s': ret=%d, ctx=%p\n", name, ret, *ctx);
    return ret;
}

// Wrapper for avfilter_link
int wrapper_link(AVFilterContext *src, unsigned srcpad,
                AVFilterContext *dst, unsigned dstpad) {
    int ret = avfilter_link(src, srcpad, dst, dstpad);
    printf("Link: src=%p[%u] -> dst=%p[%u], ret=%d\n", 
           (void*)src, srcpad, (void*)dst, dstpad, ret);
    return ret;
}

// Wrapper for avfilter_graph_config
int wrapper_config(AVFilterGraph *graph) {
    int ret = avfilter_graph_config(graph, NULL);
    printf("Config graph: ret=%d\n", ret);
    return ret;
}

// Test scenarios
void test_basic_operations() {
    printf("\n=== Test: Basic Operations ===\n");
    
    // Test 1: Graph allocation and free
    AVFilterGraph *graph = wrapper_graph_alloc();
    if (graph) {
        // Check initial state
        printf("Initial nb_filters: %d\n", graph->nb_filters);
        printf("Initial auto_convert: %u\n", graph->disable_auto_convert ? 0 : 1);
        
        wrapper_graph_free(&graph);
        printf("After free: graph=%p\n", (void*)graph);
    }
}

void test_filter_discovery() {
    printf("\n=== Test: Filter Discovery ===\n");
    
    const char *filter_names[] = {
        "buffer", "buffersink", "scale", "crop", "pad",
        "overlay", "format", "null", "anull", "invalid_filter"
    };
    
    for (int i = 0; i < 10; i++) {
        const AVFilter *f = wrapper_get_filter(filter_names[i]);
        if (f) {
            printf("Filter '%s': nb_inputs=%d, nb_outputs=%d\n",
                   filter_names[i], f->nb_inputs, f->nb_outputs);
        }
    }
}

void test_simple_chain() {
    printf("\n=== Test: Simple Chain ===\n");
    
    AVFilterGraph *graph = wrapper_graph_alloc();
    AVFilterContext *src = NULL, *scale = NULL, *sink = NULL;
    
    // Get filters
    const AVFilter *f_src = wrapper_get_filter("buffer");
    const AVFilter *f_scale = wrapper_get_filter("scale");
    const AVFilter *f_sink = wrapper_get_filter("buffersink");
    
    if (graph && f_src && f_scale && f_sink) {
        // Create filter contexts
        int ret;
        ret = wrapper_create_filter(graph, &src, f_src, "src",
                                   "video_size=320x240:pix_fmt=0:time_base=1/25");
        
        ret = wrapper_create_filter(graph, &scale, f_scale, "scale",
                                   "w=160:h=120");
        
        ret = wrapper_create_filter(graph, &sink, f_sink, "sink", NULL);
        
        // Check graph state
        printf("After creation: nb_filters=%d\n", graph->nb_filters);
        
        if (src && scale && sink) {
            // Link filters
            ret = wrapper_link(src, 0, scale, 0);
            ret = wrapper_link(scale, 0, sink, 0);
            
            // Configure
            ret = wrapper_config(graph);
            
            // Check final state
            printf("After config: nb_filters=%d\n", graph->nb_filters);
            if (ret >= 0 && src->nb_outputs > 0 && src->outputs[0]) {
                AVFilterLink *link = src->outputs[0];
                printf("First link: w=%d, h=%d, format=%d\n",
                       link->w, link->h, link->format);
            }
        }
    }
    
    wrapper_graph_free(&graph);
}

void test_complex_graph() {
    printf("\n=== Test: Complex Graph ===\n");
    
    AVFilterGraph *graph = wrapper_graph_alloc();
    
    // Enable auto convert
    avfilter_graph_set_auto_convert(graph, AVFILTER_AUTO_CONVERT_ALL);
    
    // Create multiple filters
    AVFilterContext *filters[5] = {0};
    const char *names[] = {"src1", "src2", "scale1", "overlay", "sink"};
    
    // Source 1
    const AVFilter *f = wrapper_get_filter("buffer");
    wrapper_create_filter(graph, &filters[0], f, names[0],
                         "video_size=640x480:pix_fmt=0:time_base=1/30");
    
    // Source 2  
    wrapper_create_filter(graph, &filters[1], f, names[1],
                         "video_size=320x240:pix_fmt=0:time_base=1/30");
    
    // Scale
    f = wrapper_get_filter("scale");
    wrapper_create_filter(graph, &filters[2], f, names[2], "w=320:h=240");
    
    // Overlay
    f = wrapper_get_filter("overlay");
    wrapper_create_filter(graph, &filters[3], f, names[3], "x=10:y=10");
    
    // Sink
    f = wrapper_get_filter("buffersink");
    wrapper_create_filter(graph, &filters[4], f, names[4], NULL);
    
    // Link: src1 -> scale -> overlay[0]
    //       src2 ----------> overlay[1] -> sink
    if (filters[0] && filters[1] && filters[2] && filters[3] && filters[4]) {
        wrapper_link(filters[0], 0, filters[2], 0);
        wrapper_link(filters[2], 0, filters[3], 0);
        wrapper_link(filters[1], 0, filters[3], 1);
        wrapper_link(filters[3], 0, filters[4], 0);
        
        printf("Before config: nb_filters=%d\n", graph->nb_filters);
        wrapper_config(graph);
        printf("After config: nb_filters=%d\n", graph->nb_filters);
    }
    
    wrapper_graph_free(&graph);
}

void test_error_cases() {
    printf("\n=== Test: Error Cases ===\n");
    
    AVFilterGraph *graph = wrapper_graph_alloc();
    AVFilterContext *src = NULL, *sink = NULL;
    
    // Test invalid filter name
    const AVFilter *f = wrapper_get_filter("nonexistent");
    printf("Invalid filter result: %p\n", (void*)f);
    
    // Test unconnected graph
    f = wrapper_get_filter("buffer");
    wrapper_create_filter(graph, &src, f, "src",
                         "video_size=320x240:pix_fmt=0:time_base=1/25");
    
    f = wrapper_get_filter("buffersink");
    wrapper_create_filter(graph, &sink, f, "sink", NULL);
    
    // Try to configure without linking
    int ret = wrapper_config(graph);
    printf("Config unconnected graph: ret=%d (expected < 0)\n", ret);
    
    wrapper_graph_free(&graph);
}

int main() {
    printf("FFmpeg libavfilter Wrapper Test\n");
    printf("Version: %u\n", avfilter_version());
    printf("================================\n");
    
    test_basic_operations();
    test_filter_discovery();
    test_simple_chain();
    test_complex_graph();
    test_error_cases();
    
    printf("\nAll tests completed.\n");
    return 0;
}