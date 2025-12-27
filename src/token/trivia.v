module token

pub enum TriviaKind {
	whitespace
	newline
	line_comment
	block_comment
	doc_comment
}

pub struct Trivia {
pub:
	kind TriviaKind
	text string
}

pub fn (t Trivia) str() string {
	return t.text
}
