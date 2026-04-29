fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    println!("{}", liberty_node_cli::run_cli(&args));
}
