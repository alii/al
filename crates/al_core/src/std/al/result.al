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
