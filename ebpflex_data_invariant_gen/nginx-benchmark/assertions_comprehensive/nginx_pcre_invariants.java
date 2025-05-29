===========================================================================
pcre_compile:::ENTER
pattern != null
options >= 0
===========================================================================
pcre_compile:::EXIT1
pattern == \old(pattern)
options == \old(options)
\result != null ==> errptr == null
\result == null ==> errptr != null
\result == null ==> erroffset >= 0
===========================================================================
pcre_exec:::ENTER
code != null
subject != null
length >= 0
startoffset >= 0
startoffset <= length
ovector != null
ovecsize >= 3
ovecsize % 3 == 0
===========================================================================
pcre_exec:::EXIT1
code == \old(code)
subject == \old(subject)
length == \old(length)
startoffset == \old(startoffset)
ovecsize == \old(ovecsize)
\result >= -1
\result < ovecsize
\result == -1 ==> "no match"
\result >= 0 ==> ovector[0] >= 0
\result >= 0 ==> ovector[1] > ovector[0]
\result >= 0 ==> ovector[0] >= startoffset
\result >= 0 ==> ovector[1] <= length
===========================================================================
ngx_regex_compile:::ENTER
rc != null
rc.pattern.data != null
rc.pattern.len > 0
rc.options >= 0
===========================================================================
ngx_regex_compile:::EXIT1
rc == \old(rc)
rc.pattern.data == \old(rc.pattern.data)
rc.pattern.len == \old(rc.pattern.len)
rc.options == \old(rc.options)
\result == 0 || \result == -1
\result == 0 ==> rc.regex != null
\result == -1 ==> rc.err.data != null
===========================================================================
ngx_regex_exec:::ENTER
re != null
s.data != null
s.len >= 0
captures != null
n > 0
===========================================================================
ngx_regex_exec:::EXIT1
re == \old(re)
s.data == \old(s.data)
s.len == \old(s.len)
n == \old(n)
\result >= -1
\result == -1 ==> "no match"
\result >= 0 ==> captures[0] >= 0
\result >= 0 ==> captures[1] > captures[0]
\result >= 0 ==> captures[1] <= s.len
===========================================================================
pcre_study:::ENTER
code != null
options >= 0
options == 0 || options == 1  // PCRE_STUDY_JIT_COMPILE
===========================================================================
pcre_study:::EXIT1
code == \old(code)
options == \old(options)
errptr != null ==> \result == null
errptr == null || *errptr == null
===========================================================================
pcre_fullinfo:::ENTER
code != null
extra == null || extra != null
what >= 0
what <= 23  // PCRE_INFO_* constants range
where != null
===========================================================================
pcre_fullinfo:::EXIT1
code == \old(code)
extra == \old(extra)
what == \old(what)
where == \old(where)
\result == 0 || \result == -1 || \result == -2 || \result == -3
\result == 0 ==> "success"
\result == -1 ==> "null code"
\result == -2 ==> "bad magic"
\result == -3 ==> "unknown option"
===========================================================================