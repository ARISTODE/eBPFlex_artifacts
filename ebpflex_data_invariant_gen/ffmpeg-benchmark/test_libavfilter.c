/*
 * Test program for libavfilter APIs - designed for Daikon analysis
 * This program exercises key libavfilter interface functions
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libavfilter/avfilter.h>
#include <libavfilter/buffersrc.h>
#include <libavfilter/buffersink.h>
#include <libavformat/avformat.h>
#include <libavutil/opt.h>
#include <libavutil/imgutils.h>
#include <libavutil/channel_layout.h>

// Test 1: Basic filter graph creation and destruction
void test_filter_graph_lifecycle() {
    printf("Testing filter graph lifecycle...\n");
    
    // Create filter graph
    AVFilterGraph *filter_graph = avfilter_graph_alloc();
    if (!filter_graph) {
        fprintf(stderr, "Failed to allocate filter graph\n");
        return;
    }
    
    // Set auto convert flags
    avfilter_graph_set_auto_convert(filter_graph, AVFILTER_AUTO_CONVERT_ALL);
    
    // Free the graph
    avfilter_graph_free(&filter_graph);
}

// Test 2: Buffer source/sink creation
void test_buffer_src_sink() {
    printf("Testing buffer source and sink...\n");
    
    AVFilterGraph *filter_graph = avfilter_graph_alloc();
    AVFilterContext *buffersrc_ctx = NULL;
    AVFilterContext *buffersink_ctx = NULL;
    
    // Find buffer source and sink filters
    const AVFilter *buffersrc = avfilter_get_by_name("buffer");
    const AVFilter *buffersink = avfilter_get_by_name("buffersink");
    
    if (!buffersrc || !buffersink) {
        fprintf(stderr, "Failed to find buffer filters\n");
        avfilter_graph_free(&filter_graph);
        return;
    }
    
    // Create filter contexts
    int ret = avfilter_graph_create_filter(&buffersrc_ctx, buffersrc, "in",
                                           "video_size=320x240:pix_fmt=0:time_base=1/25",
                                           NULL, filter_graph);
    if (ret < 0) {
        fprintf(stderr, "Cannot create buffer source\n");
        avfilter_graph_free(&filter_graph);
        return;
    }
    
    ret = avfilter_graph_create_filter(&buffersink_ctx, buffersink, "out",
                                       NULL, NULL, filter_graph);
    if (ret < 0) {
        fprintf(stderr, "Cannot create buffer sink\n");
        avfilter_graph_free(&filter_graph);
        return;
    }
    
    // Connect filters
    ret = avfilter_link(buffersrc_ctx, 0, buffersink_ctx, 0);
    if (ret >= 0) {
        ret = avfilter_graph_config(filter_graph, NULL);
    }
    
    // Test buffer source parameters
    AVBufferSrcParameters *par = av_buffersrc_parameters_alloc();
    if (par) {
        par->width = 320;
        par->height = 240;
        par->format = AV_PIX_FMT_YUV420P;
        par->time_base = (AVRational){1, 25};
        av_buffersrc_parameters_set(buffersrc_ctx, par);
        av_free(par);
    }
    
    avfilter_graph_free(&filter_graph);
}

// Test 3: Simple filter chain (scale filter)
void test_scale_filter_chain() {
    printf("Testing scale filter chain...\n");
    
    AVFilterGraph *filter_graph = avfilter_graph_alloc();
    AVFilterContext *buffersrc_ctx = NULL;
    AVFilterContext *buffersink_ctx = NULL;
    AVFilterContext *scale_ctx = NULL;
    
    const AVFilter *buffersrc = avfilter_get_by_name("buffer");
    const AVFilter *buffersink = avfilter_get_by_name("buffersink");
    const AVFilter *scale = avfilter_get_by_name("scale");
    
    if (!buffersrc || !buffersink || !scale) {
        fprintf(stderr, "Failed to find filters\n");
        avfilter_graph_free(&filter_graph);
        return;
    }
    
    // Create buffer source
    int ret = avfilter_graph_create_filter(&buffersrc_ctx, buffersrc, "in",
                                           "video_size=640x480:pix_fmt=0:time_base=1/30",
                                           NULL, filter_graph);
    if (ret < 0) {
        avfilter_graph_free(&filter_graph);
        return;
    }
    
    // Create scale filter
    ret = avfilter_graph_create_filter(&scale_ctx, scale, "scale",
                                       "w=320:h=240", NULL, filter_graph);
    if (ret < 0) {
        avfilter_graph_free(&filter_graph);
        return;
    }
    
    // Create buffer sink
    ret = avfilter_graph_create_filter(&buffersink_ctx, buffersink, "out",
                                       NULL, NULL, filter_graph);
    if (ret < 0) {
        avfilter_graph_free(&filter_graph);
        return;
    }
    
    // Link filters: buffersrc -> scale -> buffersink
    ret = avfilter_link(buffersrc_ctx, 0, scale_ctx, 0);
    if (ret >= 0) {
        ret = avfilter_link(scale_ctx, 0, buffersink_ctx, 0);
    }
    if (ret >= 0) {
        ret = avfilter_graph_config(filter_graph, NULL);
    }
    
    // Test sending a frame through the filter
    AVFrame *frame = av_frame_alloc();
    if (frame) {
        frame->width = 640;
        frame->height = 480;
        frame->format = AV_PIX_FMT_YUV420P;
        
        ret = av_frame_get_buffer(frame, 0);
        if (ret >= 0) {
            // Fill with dummy data
            memset(frame->data[0], 128, frame->linesize[0] * frame->height);
            memset(frame->data[1], 128, frame->linesize[1] * frame->height/2);
            memset(frame->data[2], 128, frame->linesize[2] * frame->height/2);
            
            frame->pts = 0;
            ret = av_buffersrc_add_frame_flags(buffersrc_ctx, frame, AV_BUFFERSRC_FLAG_KEEP_REF);
        }
        
        av_frame_free(&frame);
    }
    
    // Try to get output frame
    AVFrame *filt_frame = av_frame_alloc();
    if (filt_frame) {
        ret = av_buffersink_get_frame(buffersink_ctx, filt_frame);
        if (ret >= 0) {
            printf("Got filtered frame: %dx%d\n", filt_frame->width, filt_frame->height);
        }
        av_frame_free(&filt_frame);
    }
    
    avfilter_graph_free(&filter_graph);
}

// Test 4: Parse filter graph from string
void test_parse_filter_graph() {
    printf("Testing filter graph parsing...\n");
    
    AVFilterGraph *filter_graph = avfilter_graph_alloc();
    AVFilterInOut *inputs = NULL;
    AVFilterInOut *outputs = NULL;
    
    const char *filters_descr = "scale=320:240,format=yuv420p";
    
    // Create buffer source
    const AVFilter *buffersrc = avfilter_get_by_name("buffer");
    AVFilterContext *buffersrc_ctx = NULL;
    int ret = avfilter_graph_create_filter(&buffersrc_ctx, buffersrc, "in",
                                           "video_size=640x480:pix_fmt=0:time_base=1/25",
                                           NULL, filter_graph);
    if (ret < 0) {
        avfilter_graph_free(&filter_graph);
        return;
    }
    
    // Create buffer sink
    const AVFilter *buffersink = avfilter_get_by_name("buffersink");
    AVFilterContext *buffersink_ctx = NULL;
    ret = avfilter_graph_create_filter(&buffersink_ctx, buffersink, "out",
                                       NULL, NULL, filter_graph);
    if (ret < 0) {
        avfilter_graph_free(&filter_graph);
        return;
    }
    
    // Create endpoints for the filter graph
    outputs = avfilter_inout_alloc();
    inputs = avfilter_inout_alloc();
    
    if (outputs && inputs) {
        outputs->name       = av_strdup("in");
        outputs->filter_ctx = buffersrc_ctx;
        outputs->pad_idx    = 0;
        outputs->next       = NULL;
        
        inputs->name       = av_strdup("out");
        inputs->filter_ctx = buffersink_ctx;
        inputs->pad_idx    = 0;
        inputs->next       = NULL;
        
        ret = avfilter_graph_parse_ptr(filter_graph, filters_descr,
                                       &inputs, &outputs, NULL);
        if (ret >= 0) {
            ret = avfilter_graph_config(filter_graph, NULL);
        }
    }
    
    avfilter_inout_free(&inputs);
    avfilter_inout_free(&outputs);
    avfilter_graph_free(&filter_graph);
}

// Test 5: Multiple filter types
void test_multiple_filters() {
    printf("Testing multiple filter types...\n");
    
    AVFilterGraph *filter_graph = avfilter_graph_alloc();
    
    // Test finding various filters
    const char *filter_names[] = {
        "scale", "crop", "pad", "overlay", "format",
        "hflip", "vflip", "rotate", "drawtext", "fade"
    };
    
    for (int i = 0; i < 10; i++) {
        const AVFilter *filter = avfilter_get_by_name(filter_names[i]);
        if (filter) {
            printf("Found filter: %s\n", filter_names[i]);
            
            // Try to create a context for each
            char name[32];
            snprintf(name, sizeof(name), "test_%s", filter_names[i]);
            
            AVFilterContext *ctx = avfilter_graph_alloc_filter(filter_graph, filter, name);
            if (ctx) {
                printf("  Created context for %s\n", filter_names[i]);
            }
        }
    }
    
    avfilter_graph_free(&filter_graph);
}

// Test 6: Audio filter graph
void test_audio_filter_graph() {
    printf("Testing audio filter graph...\n");
    
    AVFilterGraph *filter_graph = avfilter_graph_alloc();
    AVFilterContext *abuffersrc_ctx = NULL;
    AVFilterContext *abuffersink_ctx = NULL;
    AVFilterContext *volume_ctx = NULL;
    
    const AVFilter *abuffersrc = avfilter_get_by_name("abuffer");
    const AVFilter *abuffersink = avfilter_get_by_name("abuffersink");
    const AVFilter *volume = avfilter_get_by_name("volume");
    
    if (!abuffersrc || !abuffersink || !volume) {
        fprintf(stderr, "Failed to find audio filters\n");
        avfilter_graph_free(&filter_graph);
        return;
    }
    
    // Create audio buffer source
    char ch_layout_str[64];
    AVChannelLayout ch_layout = AV_CHANNEL_LAYOUT_STEREO;
    av_channel_layout_describe(&ch_layout, ch_layout_str, sizeof(ch_layout_str));
    
    char args[512];
    snprintf(args, sizeof(args),
             "time_base=1/44100:sample_rate=44100:sample_fmt=fltp:channel_layout=%s",
             ch_layout_str);
    
    int ret = avfilter_graph_create_filter(&abuffersrc_ctx, abuffersrc, "in",
                                           args, NULL, filter_graph);
    if (ret < 0) {
        avfilter_graph_free(&filter_graph);
        return;
    }
    
    // Create volume filter
    ret = avfilter_graph_create_filter(&volume_ctx, volume, "volume",
                                       "volume=0.5", NULL, filter_graph);
    if (ret < 0) {
        avfilter_graph_free(&filter_graph);
        return;
    }
    
    // Create audio buffer sink
    ret = avfilter_graph_create_filter(&abuffersink_ctx, abuffersink, "out",
                                       NULL, NULL, filter_graph);
    if (ret < 0) {
        avfilter_graph_free(&filter_graph);
        return;
    }
    
    // Link filters
    ret = avfilter_link(abuffersrc_ctx, 0, volume_ctx, 0);
    if (ret >= 0) {
        ret = avfilter_link(volume_ctx, 0, abuffersink_ctx, 0);
    }
    if (ret >= 0) {
        ret = avfilter_graph_config(filter_graph, NULL);
    }
    
    avfilter_graph_free(&filter_graph);
}

// Test 7: Complex filter graph with multiple inputs/outputs
void test_complex_filter_graph() {
    printf("Testing complex filter graph...\n");
    
    AVFilterGraph *filter_graph = avfilter_graph_alloc();
    
    // Create a more complex graph string
    const char *graph_str = "[in1]scale=640:480[s1];"
                           "[in2]scale=640:480[s2];"
                           "[s1][s2]overlay=0:0[out]";
    
    // Parse the graph
    AVFilterInOut *inputs = NULL;
    AVFilterInOut *outputs = NULL;
    
    int ret = avfilter_graph_parse2(filter_graph, graph_str, &inputs, &outputs);
    
    // Note: In a real application, we would need to connect actual sources/sinks
    // For testing, we just verify the parsing worked
    
    if (ret >= 0) {
        printf("Successfully parsed complex filter graph\n");
    }
    
    avfilter_inout_free(&inputs);
    avfilter_inout_free(&outputs);
    avfilter_graph_free(&filter_graph);
}

// Test 8: Filter graph commands
void test_filter_commands() {
    printf("Testing filter graph commands...\n");
    
    AVFilterGraph *filter_graph = avfilter_graph_alloc();
    AVFilterContext *buffersrc_ctx = NULL;
    AVFilterContext *scale_ctx = NULL;
    AVFilterContext *buffersink_ctx = NULL;
    
    // Create a simple graph with scale filter
    const AVFilter *buffersrc = avfilter_get_by_name("buffer");
    const AVFilter *scale = avfilter_get_by_name("scale");
    const AVFilter *buffersink = avfilter_get_by_name("buffersink");
    
    if (!buffersrc || !scale || !buffersink) {
        avfilter_graph_free(&filter_graph);
        return;
    }
    
    int ret = avfilter_graph_create_filter(&buffersrc_ctx, buffersrc, "in",
                                           "video_size=640x480:pix_fmt=0:time_base=1/25",
                                           NULL, filter_graph);
    if (ret < 0) {
        avfilter_graph_free(&filter_graph);
        return;
    }
    
    ret = avfilter_graph_create_filter(&scale_ctx, scale, "scale",
                                       "w=320:h=240", NULL, filter_graph);
    if (ret < 0) {
        avfilter_graph_free(&filter_graph);
        return;
    }
    
    ret = avfilter_graph_create_filter(&buffersink_ctx, buffersink, "out",
                                       NULL, NULL, filter_graph);
    if (ret < 0) {
        avfilter_graph_free(&filter_graph);
        return;
    }
    
    // Link and configure
    ret = avfilter_link(buffersrc_ctx, 0, scale_ctx, 0);
    if (ret >= 0) {
        ret = avfilter_link(scale_ctx, 0, buffersink_ctx, 0);
    }
    if (ret >= 0) {
        ret = avfilter_graph_config(filter_graph, NULL);
    }
    
    // Test sending commands
    char response[256] = {0};
    ret = avfilter_graph_send_command(filter_graph, "scale", "width", "640", 
                                      response, sizeof(response), 0);
    if (ret >= 0) {
        printf("Command sent successfully\n");
    }
    
    // Test queuing commands
    ret = avfilter_graph_queue_command(filter_graph, "scale", "height", "480", 0, 1.0);
    
    avfilter_graph_free(&filter_graph);
}

// Main function to run all tests
int main(int argc, char **argv) {
    printf("FFmpeg libavfilter API test program for Daikon\n");
    printf("libavfilter version: %d\n", avfilter_version());
    printf("Configuration: %s\n", avfilter_configuration());
    printf("License: %s\n", avfilter_license());
    printf("\n");
    
    // Run all test cases
    test_filter_graph_lifecycle();
    printf("\n");
    
    test_buffer_src_sink();
    printf("\n");
    
    test_scale_filter_chain();
    printf("\n");
    
    test_parse_filter_graph();
    printf("\n");
    
    test_multiple_filters();
    printf("\n");
    
    test_audio_filter_graph();
    printf("\n");
    
    test_complex_filter_graph();
    printf("\n");
    
    test_filter_commands();
    printf("\n");
    
    printf("All tests completed.\n");
    return 0;
}