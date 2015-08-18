Standard for Embedding Product Identifiers in Source Code
=========================================================

Document Conventions
--------------------

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC 2119 \[<a href="#ref1">1</a>\].

Terminology
-----------

* *Project* - A software project, which may compile to object code.
* *Source files* - The source files in a project.
* *Object files* - The executable and/or linkable outputs of compiling and/or
  linking the source files.
* *Product* - This SHOULD describe or identify the most common and
  recognizable title or name of the product. \[<a href="#ref2">2</a>\].
* *Vendor* - This SHOULD describe or identify the person or organization that
  manufactured or created the product \[<a href="#ref2">2</a>\].
* *Version* - This SHOULD be a vendor-specific alphanumeric string
  characterizing the particular release version of the product
  \[<a href="#ref2">2</a>\].
* *Artifacts* - Object files which are ultimately delivered to as part of
  product releases end users' working software systems. 
* *Product Identifier* - A 7-bit ASCII string embedded into a artifact that
  provides, at a minimum, the artifact's vendor, product, and version.

Introduction
------------

This document is intended to describe a voluntary standard for software
projects to insert product identifiers into source files, so that the source
and/or resulting object files will reliably contain that information. If this
standard is followed, the project's artifacts will reliably contain that
information, especially product name and version, in useful form. Tools that
automatically scan systems and build software inventories may then take
advantage of this. If all recommendations are followed, then it will be
possible for tools to scan the source code as well.

Embedding Concept
-----------------

If all artifacts can meaningfully be represented by the same product
identifier, in the sense described in the CPE specification
\[<a href="#ref2">2</a>\], then they SHOULD all have the same product
identifier embedded. Conversely, if they cannot be meaningfully represented by
the same product identifier, they SHOULD have different product identifiers.
The CPE specification MAY be used for guidance in determining when there is a
need for applying different identifiers.

Every artifact SHALL contain an embedded product identifier. Therefore, for
each artifact produced by the project"s build process, a source file SHALL
be identified to receive the embedded id. That source file's corresponding
object file SHALL be linked into the artifact.

For maximal usefulness, it is RECOMMENDED that the embedded identifier
contain values for vendor, product and version. Vendor and/or version values
MAY be omitted, or equivalently assigned a logical value of ANY or NA (see
\[<a href="#ref1">1</a>\]). However, doing so will lessen the usefulness of
the embedded identifier.

Embedding Guidance
------------------

<a id="A">\[A\]</a> If the project has only one artifact, a natural place
to insert the identifier is in a prominent source file that new developers
would typically look at first. 

<a id="B">\[B\]</a> If your project has more than one artifact, and it
has been determined they may collectively share a single product identifier:

* Any source file that is already linked into all artifacts may be used.
* If no such file can be identified, then create, e.g., a
  product_identifier.ext source file, where "ext" is "c", "C", "cpp", etc., as
  appropriate for the project. The developer MAY choose any name desired for
  this file. Of course, then the project build environment must be modified
  appropriately to ensure that the new source file's object file is linked
  into each artifact.

If your project has more than one artifact, and it has been determined that
more than one product identifier is needed:

* For any product identifier that is only to be applied to one artifact,
  apply rule \[<a href="#A">A</a>\] above within the scope of that artifact.
* For any product identifier that applies to more than one artifact, apply
  rule \[<a href="#B">B</a>] above within the scope of that subset of
  artifacts.

Embedding Syntax
----------------

### C/C++

The source file SHALL contain a variable declaration and definition of the
following form:

    char my_id[] = "ID_HEADER:vendor=VENDOR;product=PRODUCT;version=VERSION;";

ID\_HEADER is "EID:" followed by the following hexadecimal number, exactly as
presented:

    50CA347E-88EF4066

The number was randomly generated, and its purpose is to be a unique
improbable sequence to aid scanning tools in finding files that contain
embedded identifiers. Scanning tools SHALL use case-sensitive comparisons and
SHALL check for the single hyphen in the given location. The only possible
valid ID\_HEADER string is "EID:50CA347E-88EF4066".

The actual name of the variable MAY be any value the developer chooses. The
declaration and definition MAY be inserted via the preprocessor or macros from
information already present in other project files. However, to assist tools
that also scan source code, there SHOULD be at least one file in which the
string literal is directly present in its entirety. There SHALL be at most one
valid embedded product identifier per file. Tools SHALL depend only on
finding the ASCII text within the artifact or source code, and SHOULD NOT
depend on the symbol name it is bound to. The vendor, product and version
fields may be present in any order, though the order given here is
conventional and is RECOMMENDED. VENDOR, PRODUCT and VERSION are, of
course, replaced by appropriate values as defined in the terminology listing.
Each value SHALL be terminated with a semicolon.

Alternatively, the declaration and definition MAY be expressed using a CPE
formatted string, as defined in section 6.2 of the CPE specification
\[<a href="#ref1">1</a>\]. Here is an example that using three identifier
elements RECOMMENDED by this document:

    char my_id[] = "ID_HEADER:cpe:2.3:a:VENDOR:PRODUCT:VERSION:*:*:*:*:*:*";

The developer MAY consult the CPE specification in order to fill in additional
attributes, such as "update" or "edition". If they do, they SHOULD satisfy the
criteria in section 5.2 of \[<a href="#ref1">1</a>\], in order to ensure a
valid CPE.

### Other Programming Languages

If the language is a systems programming language, such as Go or Rust, then an
equivalent string variable declaration to that shown in the previous section
SHALL be used. I.e., it SHALL compile such that the string is embedded in the
object file, potentially accessible to code written in C or C++.

For all other languages, a string variable SHALL be declared with a value as
specified above. If the same string delimiter is available in the language, it
SHOULD be used. Otherwise, any string delimiter MAY be used. Assignment to a
variable is OPTIONAL, but the string value MUST be persisted in the final
artifact(s).

### Extensions

It may be desired to embed additional information in the embedded identifier
string. If using the CPE specification format, then provision exists for
additional fields covering update, edition, language, software edition, target
software, target hardware, and "other". See section 5.2 of
\[<a href="#ref1">1</a>\] for more details. For the other embedding syntax,
additional fields MAY be provided, such as license, simply by adding them
after the vendor, product and version fields defined in this specification.
If extension fields and values are provided, the value(s) MUST be terminated
with semicolon(s), and extension fields MUST NOT precede vendor, product or
version fields.

One example might be providing license information:

    char my_id[] = "ID_HEADER:vendor=VENDOR;product=PRODUCT;version=VERSION;license=LICENSE;";

where LICENSE might be "GNU GPL v3".

References
----------

<a id="ref1">\[1\]</a> S. Bradner, "Key Words for use in RFCs to Indicate
	Requirement Levels," March 1997. [Online]. Available:
	http://tools.ietf.org/html/rfc2119.

<a id="ref2">\[2\]</a> D. Waltermire, B. A. Cheikes and K. Scarfone, "Common
	Platform Enumeration: Naming Specification Version 2.3," August 2011.
	[Online]. Available:
	http://csrc.nist.gov/publications/nistir/ir7695/NISTIR-7695-CPE-Naming.pdf.