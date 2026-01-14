#[cfg(test)]
mod tests {
    #[test]
    fn test_basic_functionality() {
        // Basic test to ensure the project compiles
        assert_eq!(2 + 2, 4);
    }
    
    #[test]
    fn test_tool_exists() {
        // Verify the binary can be built
        let output = std::process::Command::new("cargo")
            .args(&["build"])
            .output()
            .expect("Failed to build");
        
        assert!(output.status.success());
    }
}
