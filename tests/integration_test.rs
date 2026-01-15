#[cfg(test)]
mod tests {
    use std::process::Command;
    
    #[test]
    fn test_basic_functionality() {
        // Basic test to ensure the project compiles
        assert_eq!(2 + 2, 4);
    }
    
    #[test]
    fn test_tool_exists() {
        // Verify the binary can be built
        let output = Command::new("cargo")
            .args(&["build"])
            .output()
            .expect("Failed to build");
        
        assert!(output.status.success());
    }
    
    #[test]
    fn test_help_command() {
        // Test that help command works
        let output = Command::new("cargo")
            .args(&["run", "--", "--help"])
            .output()
            .expect("Failed to run help");
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("Automated Cybersec/Opsec Defense Stack"));
        assert!(stdout.contains("monitor"));
        assert!(stdout.contains("analyze"));
        assert!(stdout.contains("block"));
    }
    
    #[test]
    fn test_status_command() {
        // Test status command
        let output = Command::new("cargo")
            .args(&["run", "--", "status"])
            .output()
            .expect("Failed to run status");
        
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("Defense System Status"));
    }
    
    #[test]
    fn test_block_command() {
        // Test blocking an IP
        let output = Command::new("cargo")
            .args(&["run", "--", "block", "--ip", "1.2.3.4", "--duration", "10"])
            .output()
            .expect("Failed to run block");
        
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("Blocking IP"));
    }
    
    #[test]
    fn test_monitor_creates_log() {
        // Clean up any existing test log
        std::fs::remove_file("test_monitor.log").ok();
        
        // Run monitor command
        let output = Command::new("cargo")
            .args(&["run", "--", "monitor", "--port", "9999", "--log", "test_monitor.log"])
            .output()
            .expect("Failed to run monitor");
        
        assert!(output.status.success());
        
        // Verify log file was created
        assert!(std::path::Path::new("test_monitor.log").exists());
        
        // Clean up
        std::fs::remove_file("test_monitor.log").ok();
    }
}
