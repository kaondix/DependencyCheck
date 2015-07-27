Embedded ID Analyzer
====================

OWASP dependency-check includes an analyzer that will scan all files for
embedded product ID information. The implementation is extremely fast. It
searches files for a pre-defined ASCII embedded ID header string, using the
Knuth-Morris-Pratt string search algorithm, which provides
Θ(n+m) performance, much better than the Θ((n-m) m) performance of a naïve
string search approach.<a href="#time">*</a>

The information collected is internally referred to as evidence and is grouped
into vendor, product, and version buckets. Other analyzers later use this
evidence to identify any Common Platform Enumeration (CPE) identifiers that
apply.

File types scanned: all

For more information on how modify C/C++ source code in order to embed 
detectable product ID information into binary object files, see the
[specification](./embedded-id-spec.html).

<a id="time">*</a> In the Θ notation, n refers to the file length in bytes,
and m refers to the length of the header string, which is 21. Therefore, the
KMP algorithm here provides a factor of 21 improvement over a naïve approach
when n ≫ 21.