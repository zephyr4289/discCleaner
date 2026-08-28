use std::collections::BTreeMap;
use std::env;
use std::thread;
use std::time::Duration;

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut i = 1;
    let mut exit_code = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--echo-env" => {
                let mut env_map = BTreeMap::new();
                for (k, v) in env::vars() {
                    env_map.insert(k, v);
                }
                let json = serde_json::to_string_pretty(&env_map).unwrap();
                println!("{}", json);
            }
            "--sleep-ms" => {
                if let Some(val) = args.get(i + 1) {
                    if let Ok(ms) = val.parse::<u64>() {
                        thread::sleep(Duration::from_millis(ms));
                    }
                    i += 1;
                }
            }
            "--exit-code" => {
                if let Some(val) = args.get(i + 1) {
                    if let Ok(code) = val.parse::<i32>() {
                        exit_code = code;
                    }
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }

    std::process::exit(exit_code);
}
