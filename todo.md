# Vulnerability Scanner Roadmap

## 🏁 **Phase 1: Basic Host Discovery**
- [X] **Ping Scan**: Implement basic ICMP Ping to detect live hosts in a subnet.
- [X] **Handle Different Subnets**: Ensure the scanner works across subnets of different sizes (e.g., `/24`, `/28`).
- [X] **Hostname Resolution**: Use DNS lookups to resolve IPs to hostnames.
- [ ] **Command-Line Interface (CLI)**: Add basic CLI arguments for user inputs (e.g., target IP/subnet, timeout).
- [ ] **Export Results**: Output the list of live hosts to a text or CSV file.

## 🏗 **Phase 2: Port Scanning**
- [ ] **TCP Connect Scan**: Basic scanning of ports by attempting to connect using `socket.connect()`.
- [ ] **SYN Scan (Advanced)**: Implement more stealthy scans, though this will require raw sockets and admin privileges.
- [ ] **Port Range Scanning**: Allow users to define custom port ranges (e.g., `22-80`).
- [ ] **Banner Grabbing**: Grab banners from open ports to determine the service (HTTP, SSH, FTP, etc.).
- [ ] **Threading**: Implement threading to speed up port scanning.
- [ ] **Export Results**: Store results in a structured format, linking live hosts to their open ports.

## 🏅 **Phase 3: Network Scanning**
- [ ] **CIDR Scanning**: Scan entire networks (e.g., `192.168.1.0/24`).
- [ ] **Combined Host + Port Scan**: Automatically scan hosts in a subnet and then scan the open ports on those hosts.
- [ ] **Multithreading/Multiprocessing**: Increase the speed of the scan by using async methods or parallel threads.
- [ ] **Scanning Multiple Networks**: Allow users to provide multiple IP ranges/subnets to scan simultaneously.
- [ ] **GeoIP Lookup**: For public IPs, use a service to map the IP address to a geographical location.
- [ ] **Logging**: Introduce a logging system to capture scan progress, errors, and results in real-time.

## 🏆 **Phase 4: Advanced Features & Optimization**
- [ ] **Service Detection**: Use banners or specific probes to detect running services (HTTP version, SSH, etc.).
- [ ] **TLS/SSL Detection**: Check for SSL/TLS encryption on ports like 443 and 465.
- [ ] **Timeout Handling**: Implement timeouts for slow responses to avoid blocking indefinitely.
- [ ] **Retry Logic**: Retry unreachable hosts or ports with a delay between attempts.
- [ ] **Scan Progress Visualization**: Provide some feedback (e.g., percentage or estimated time remaining) during scans.
- [ ] **Exception Handling**: Ensure that all functions are resilient to errors and can handle timeouts, unreachable hosts, and other exceptions gracefully.
- [ ] **Export to JSON/CSV**: Output structured results, with open ports, hostnames, and timestamps, for further analysis.

## 🏗 **Phase 5: Polishing, Testing & Deployment**
- [ ] **Unit Tests**: Write test cases for critical functions (e.g., `is_host_up`, `scan_port`).
- [ ] **CLI Enhancements**: Allow for better argument parsing, error handling, and user-friendly outputs.
- [ ] **Optimization**: Profile and optimize slow functions (e.g., threading for port scans).
- [ ] **Cross-Platform Support**: Make sure the scanner works on both Linux and Windows.
- [ ] **GUI or TUI**: If you wish to, add a basic graphical user interface (GUI) or a terminal user interface (TUI) using `curses` or `tkinter`.
- [ ] **Documentation**: Add documentation for users, explaining how to use your scanner, set up the environment, and interpret results.
- [ ] **Packaging for Distribution**: Make the scanner easy to install (e.g., using `pip`, `setup.py`, or packaging as an executable).

## 📦 **Phase 6: Final Feature Additions and Scalability**
- [ ] **Scan Result Comparison**: Allow users to compare current scan results with previous scans (e.g., what hosts/ports have changed).
- [ ] **Scan Scheduling**: Set up recurring or scheduled scans (e.g., weekly scans of a network).
- [ ] **Vulnerability Detection**: Integrate simple vulnerability detection based on known port/services (e.g., check for open SMB ports, old versions of Apache).
- [ ] **Docker Integration**: Make it easy to run the scanner in a containerized environment, e.g., via Docker.

## 📈 **Phase 7: Real-World Testing & Deployment**
- [ ] **Real-world Testing**: Run the scanner on real networks, validate its reliability, and refine performance.
- [ ] **Security Considerations**: Ensure that the scanner does not inadvertently perform dangerous actions (e.g., DoS-like behavior, unintentional port flooding).
- [ ] **Code Optimization**: Revisit the codebase for possible optimizations to handle larger scans efficiently.

