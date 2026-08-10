pub fn map(r Result(a, e), f fn(a) b) Result(b, e) {
	match r {
		Ok(a) -> Ok(f(a))
		Err(e) -> Err(e)
	}
}

pub fn map_err(r Result(a, e), f fn(e) e2) Result(a, e2) {
	match r {
		Ok(a) -> Ok(a)
		Err(e) -> Err(f(e))
	}
}

pub fn then(r Result(a, e), f fn(a) Result(b, e)) Result(b, e) {
	match r {
		Ok(x) -> f(x)
		Err(e) -> Err(e)
	}
}

// Unwrap a result that has a Nil error type. The error is not generic
// intentionally, as it is usually a mistake to be ignoring
// error values. Most of the time you would want to consume them.
pub fn unwrap(r Result(a, Nil), default a) a {
	match r {
		Ok(a) -> a
		Err(Nil) -> default
	}
}

// Lazily unwrap a result that has a Nil error type. The error is not generic
// intentionally, as it is usually a mistake to be ignoring
// error values. Most of the time you would want to consume them.
pub fn unwrap_lazy(r Result(a, Nil), default fn() a) a {
	match r {
		Ok(a) -> a
		Err(Nil) -> default()
	}
}

pub fn is_ok(r Result(a, e)) Bool {
	match r {
		Ok(_) -> True
		Err(_) -> False
	}
}

pub fn is_err(r Result(a, e)) Bool {
	match r {
		Ok(_) -> False
		Err(_) -> True
	}
}
