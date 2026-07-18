package engine

import "regexp"

// regexpCompile compiles a pattern's Go regex. Patterns are matched as
// substrings within object content (grep-style), so they are intentionally not
// anchored even though the engine tags them "exactly_matches" (that tag governs
// how the upstream engine validates whole fields, not how we search a blob).
//
// Go's regexp is RE2 and rejects backreferences/lookaround. The engine's Go
// variants are authored for RE2, so a compile error means a genuinely
// unsupported pattern; callers record it and skip the rule rather than aborting.
func regexpCompile(expr string) (*regexp.Regexp, error) {
	return regexp.Compile(expr)
}
