// al has a feature called comptime.
// it allows you to write code that is evaluated at compile time.
// it is useful for things like type checking, optimizations, and code generation.

// comptime is a keyword that you can use to mark a block of code that should be evaluated at compile time.

fn ct_hello_world() {
    comptime age := 10 * 10
    return age + 10
}

// Here's an example of calculating fibonacci at compile time.
fn fibonacci(n int) int {
    if n <= 1 {
        return n
    }

    return fibonacci(n - 1) + fibonacci(n - 2)
}

comptime fib := fibonacci(10) // this will be evaluated at compile time
println(fib)

println(ct_hello_world())