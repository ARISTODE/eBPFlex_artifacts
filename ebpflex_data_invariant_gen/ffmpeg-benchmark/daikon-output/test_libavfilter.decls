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
    comparability 2
  variable argv[..]
    var-kind array
    enclosing-var argv
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 3

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
    comparability 2
  variable argv[..]
    var-kind array
    enclosing-var argv
    array 1
    rep-type string[]
    dec-type char*[]
    comparability 3
  variable return
    var-kind variable
    rep-type int
    dec-type int
    comparability 4

ppt ..test_filter_commands():::ENTER
  ppt-type enter

ppt ..test_filter_commands():::EXIT0
  ppt-type subexit

ppt ..test_complex_filter_graph():::ENTER
  ppt-type enter

ppt ..test_complex_filter_graph():::EXIT0
  ppt-type subexit

ppt ..test_audio_filter_graph():::ENTER
  ppt-type enter

ppt ..test_audio_filter_graph():::EXIT0
  ppt-type subexit

ppt ..test_multiple_filters():::ENTER
  ppt-type enter

ppt ..test_multiple_filters():::EXIT0
  ppt-type subexit

ppt ..test_parse_filter_graph():::ENTER
  ppt-type enter

ppt ..test_parse_filter_graph():::EXIT0
  ppt-type subexit

ppt ..test_scale_filter_chain():::ENTER
  ppt-type enter

ppt ..test_scale_filter_chain():::EXIT0
  ppt-type subexit

ppt ..test_buffer_src_sink():::ENTER
  ppt-type enter

ppt ..test_buffer_src_sink():::EXIT0
  ppt-type subexit

ppt ..test_filter_graph_lifecycle():::ENTER
  ppt-type enter

ppt ..test_filter_graph_lifecycle():::EXIT0
  ppt-type subexit

