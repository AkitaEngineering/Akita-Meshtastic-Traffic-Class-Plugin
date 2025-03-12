# Akita-Meshtastic-Traffic-Class-Plugin - Meshtastic Plugin

## Overview

The Akita Meshtastic Traffic Class Plugin is a Meshtastic plugin that introduces a sophisticated traffic class system, enabling enhanced network segmentation, quality of service (QoS), and reliability. Designed with Akita Engineering's high standards in mind, this plugin provides advanced features such as dynamic fragmentation, retransmission logic, congestion control, and adaptive traffic management.

## Features

* **Traffic Class Segmentation:** Logical separation of network traffic for different purposes (e.g., voice, data, critical alerts).
* **Quality of Service (QoS):** Prioritization of traffic based on configurable traffic class priorities.
* **Reliable Transmission:** Retransmission logic for reliable traffic classes, ensuring data delivery.
* **Congestion Control:** Dynamic adjustment of congestion windows to prevent network overload.
* **Dynamic Fragmentation:** Adaptive fragment size based on link quality.
* **Dynamic Traffic Class Adaptation:** Framework for automatic adjustment of traffic class parameters based on network conditions and device capabilities (requires implementation).
* **QoS Monitoring:** Framework for monitoring and reporting QoS metrics (requires implementation).
* **Error Correction and Forward Error Correction (FEC):** Configurable error correction (requires implementation).
* **Configuration Parameters:** Configurable retries, FEC level, and congestion window settings.
* **Radio State Handling:** Handles radio state changes for power saving.
* **Reassembly timeout:** Reassembly timers implemented.

## Installation

1.  **Clone the Repository:**
    ```bash
    git clone [repository URL]
    ```
2.  **Build the Plugin:**
    * Follow the Meshtastic plugin build instructions.
    * Place the `akita_traffic_class_plugin.cpp` file in the appropriate plugin directory.
    * Compile the plugin using the Meshtastic build system.
3.  **Install the Plugin:**
    * Copy the compiled plugin binary to the Meshtastic device's plugin directory.
    * Configure Meshtastic to load the plugin.

## Configuration

The plugin can be configured using the Meshtastic CLI or app.

### CLI Configuration Example

```bash
# Configure traffic class 1 with priority 5, reliable transmission, encryption, max fragment size 200, 3 retries, FEC level 2, congestion window 5
meshtastic --set plugin.akita_traffic_class.configure_class 1 5 true true 200 3 2 5
   ```
# Configuration Parameters

* **Traffic Class ID:** Unique identifier for the traffic class (e.g., 1-255).
* **Priority:** Priority level (higher values indicate higher priority).
* **Reliable:** Enable reliable transmission (retransmissions).
* **Encrypted:** Enable encryption (requires implementation).
* **Max Fragment Size:** Maximum fragment size in bytes.
* **Retries:** Number of retransmission attempts.
* **FEC Level:** Forward error correction level (requires implementation).
* **Congestion Window:** Initial congestion window size.

# Usage

Once installed and configured, the plugin will automatically manage traffic based on the configured traffic classes.

## Setting Traffic Class in Packets

To set the traffic class of a packet, use the appropriate Meshtastic API or CLI command.

## Example setting the traffic class of a message.

   ```Bash
meshtastic --sendtext "Hello Traffic Class 1" --dest !1 --traffic-class 1
   ```

# Important Considerations

* **Placeholders:** This version contains placeholders for critical functionalities. Implement these placeholders based on your specific needs.
* **Testing:** Thoroughly test the plugin after implementing the placeholders.
* **Security:** Implement robust security measures, especially for encryption.

# Further Development

* **Complete Placeholders:** Implement the TODO sections for encryption, FEC, routing metric updates, reassembly logic, QoS monitoring, and configuration loading.
* **Robust Error Handling:** Implement comprehensive error handling and logging.
* **Performance Optimization:** Profile and optimize the code for performance on resource-constrained devices.
* **Security Audit:** Conduct a thorough security audit to identify and address potential vulnerabilities.
* **Test-Driven Development:** Implement a robust test suite to ensure code quality and reliability.
* **CI/CD Integration:** Integrate the plugin into a CI/CD pipeline for automated testing and deployment.
* **Documentation and User Interface:** Provide comprehensive documentation and a user-friendly interface for configuration and monitoring.
* **Integration with Akita Ecosystem:** Explore integration with other Akita Engineering tools and platforms.
* **Battery Power Optimization:** Implement advanced power-saving strategies.
* **Firmware Over-the-Air (FOTA) Updates:** Design the plugin to support FOTA updates.
* **Link Quality Estimation Improvements:** Implement better link quality estimation.
* **GUI Interface:** Create a user-friendly GUI interface for configuration and monitoring.
* **Integration with External Systems:** Explore integration with external systems, such as MQTT brokers or cloud platforms.

# Contributing

Contributions are welcome! Please submit pull requests or open issues to report bugs or suggest enhancements.
