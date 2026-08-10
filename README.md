<img width="128" src="https://github.com/scarletindustries.png" />

### Scarlet programming language

A statically-typed and expression-oriented programming language for developer productivity.

[Documentation](https://scarlet.industries)

---

```scarlet
type Shape {
	Circle(r Float)
	Rect(w Float, h Float)
}

fn area(s Shape) Float {
	match s {
		Circle(r) -> 3.14159 * r * r
		Rect(w, h) -> w * h
	}
}

shapes = [Circle(r: 2.0), Rect(w: 3.0, h: 4.0), Circle(r: 1.0)]
println('total area: ${array.fold(shapes, 0.0, fn(acc, s) acc + area(s))}')
```

```
scarlet run <file.scrl>         Run a program
scarlet repl                    Start interactive REPL
scarlet check <file.scrl>       Type-check without running
scarlet fmt [glob path]         Format source files
```
