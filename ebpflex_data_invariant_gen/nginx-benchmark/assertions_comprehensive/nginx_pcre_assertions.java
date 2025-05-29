// PCRE Compile Function Assertions
void pcre_compile_preconditions(const char* pattern, int options) {
    assert(pattern != null);
    assert(options >= 0);
}

void pcre_compile_postconditions(pcre* result, const char** errptr, int* erroffset) {
    if (result != null) {
        assert(errptr == null || *errptr == null);
    } else {
        assert(errptr != null && *errptr != null);
        assert(erroffset != null && *erroffset >= 0);
    }
}

// PCRE Exec Function Assertions
void pcre_exec_preconditions(const pcre* code, const char* subject, int length, 
                             int startoffset, int* ovector, int ovecsize) {
    assert(code != null);
    assert(subject != null);
    assert(length >= 0);
    assert(startoffset >= 0);
    assert(startoffset <= length);
    assert(ovector != null);
    assert(ovecsize >= 3);
    assert(ovecsize % 3 == 0);
}

void pcre_exec_postconditions(int result, int* ovector, int startoffset, int length) {
    assert(result >= -1);
    if (result >= 0) {
        // Match found
        assert(ovector[0] >= 0);
        assert(ovector[1] > ovector[0]);
        assert(ovector[0] >= startoffset);
        assert(ovector[1] <= length);
    }
}

// Nginx Regex Compile Assertions
void ngx_regex_compile_preconditions(ngx_regex_compile_t* rc) {
    assert(rc != null);
    assert(rc->pattern.data != null);
    assert(rc->pattern.len > 0);
    assert(rc->options >= 0);
}

void ngx_regex_compile_postconditions(ngx_int_t result, ngx_regex_compile_t* rc) {
    assert(result == 0 || result == -1);
    if (result == 0) {
        assert(rc->regex != null);
    } else {
        assert(rc->err.data != null);
    }
}

// Nginx Regex Exec Assertions
void ngx_regex_exec_preconditions(ngx_regex_t* re, ngx_str_t* s, int* captures, ngx_int_t n) {
    assert(re != null);
    assert(s->data != null);
    assert(s->len >= 0);
    assert(captures != null);
    assert(n > 0);
}

void ngx_regex_exec_postconditions(ngx_int_t result, int* captures, ngx_str_t* s) {
    assert(result >= -1);
    if (result >= 0) {
        assert(captures[0] >= 0);
        assert(captures[1] > captures[0]);
        assert(captures[1] <= s->len);
    }
}

// PCRE Study Assertions
void pcre_study_preconditions(const pcre* code, int options) {
    assert(code != null);
    assert(options >= 0);
    assert(options == 0 || options == 1); // PCRE_STUDY_JIT_COMPILE
}

void pcre_study_postconditions(pcre_extra* result, const char** errptr) {
    if (errptr != null && *errptr != null) {
        assert(result == null);
    }
}

// PCRE Full Info Assertions
void pcre_fullinfo_preconditions(const pcre* code, int what, void* where) {
    assert(code != null);
    assert(what >= 0);
    assert(what <= 23); // PCRE_INFO_* constants range
    assert(where != null);
}

void pcre_fullinfo_postconditions(int result) {
    assert(result == 0 || result == -1 || result == -2 || result == -3);
    // 0: success, -1: null code, -2: bad magic, -3: unknown option
}