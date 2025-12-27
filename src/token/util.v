module token

@[inline]
pub fn is_name_char(c u8) bool {
	return (c >= `a` && c <= `z`) || is_uppercase_ascii(c) || c == `_` || c.is_digit()
}

pub fn is_uppercase_ascii(c u8) bool {
	return c >= `A` && c <= `Z`
}

@[inline]
pub fn is_type_identifier(identifier string) bool {
	return is_uppercase_ascii(identifier[0])
}

@[inline]
pub fn is_valid_identifier(identifier string, is_fully_qualified bool) bool {
	if identifier.len == 0 {
		return false
	}

	if is_fully_qualified && is_keyword(identifier) {
		return false
	}

	if !identifier[0].is_letter() && identifier[0] != `_` {
		return false
	}

	for i := 1; i < identifier.len; i++ {
		if !is_name_char(identifier[i]) {
			return false
		}
	}

	return true
}

@[inline]
pub fn is_keyword(identifier string) bool {
	return identifier in keyword_map
}

@[inline]
pub fn match_keyword(identifier ?string) ?Kind {
	if unwrapped := identifier {
		return keyword_map[unwrapped] or { return none }
	}

	return none
}

@[inline]
pub fn is_quote(c char) bool {
	return c == `'` || c == `\``
}
