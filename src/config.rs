use std::env;

pub struct Config {
    pub listen_addr: String,    // local socket address for coming DNS request
    // pub lookup_addr: String,
    pub remote_addr: String,    // remote socket address for relaying
    pub rule_file: String,      // rule file containing domain name – IP address list
}

impl Config {
    /// Get a default Config
    pub fn default() -> Config {
        Config {
            listen_addr: "127.0.0.1:53".to_owned(),
            // lookup_addr: "0.0.0.0:0".to_owned(),
            remote_addr: "114.114.114.114:53".to_owned(),
            rule_file: "rules/config.txt".to_owned(),
        }
    }

    /// Create a user defined Config based on command line arguments.
    /// The second argument is the path to rulefile
    pub fn new() -> Config {
        let mut config = Config::default();

        let mut args = env::args();
        args.next();
        if let Some(user_file) = args.next() {
            config.rule_file = user_file;
        }

        config
    }
}
