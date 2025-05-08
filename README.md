# Akita Meshtastic Traffic Class Plugin

## Overview

The Akita Meshtastic Traffic Class Plugin is a plugin designed for the Meshtastic firmware that introduces a sophisticated traffic class system. Its goal is to enable enhanced network segmentation, Quality of Service (QoS), and reliability features beyond the standard Meshtastic capabilities.

This plugin provides mechanisms for:

* Prioritizing different types of data.
* Ensuring reliable delivery of critical packets using ACKs and retransmissions.
* Handling large messages through fragmentation and reassembly.
* Adapting transmission parameters based on network conditions.
* Applying Forward Error Correction (FEC) and Encryption (structure implemented, requires external libraries).

**Note:** This plugin requires integration into the Meshtastic firmware source code and depends on specific Meshtastic APIs and potentially external libraries (AES, FEC) for full functionality.

## Features

* **Traffic Class Segmentation:** Define multiple traffic classes (e.g., default, reliable data, critical alerts) with unique IDs.
* **Configurable QoS Parameters:** Set per-class parameters including:
    * `priority`: Higher values get preferential treatment in transmission queues.
    * `reliable`: Enables ACK-based reliability and retransmissions.
    * `encrypted`: Enables payload encryption (requires AES library).
    * `maxFragmentSize`: Maximum size of data chunks before fragmentation.
    * `retries`: Number of retransmission attempts for reliable fragments.
    * `fec_num_parity_bytes`: Number of FEC parity bytes to add (0=disabled, requires FEC library).
    * `congestionWindow`: Parameter for AIMD congestion control.
    * `encryptionKey`: Key used for encryption (placeholder derivation).
* **Reliable Transmission:** Implements ACK/retransmission logic for traffic classes marked as reliable.
* **Fragmentation & Reassembly:** Automatically fragments outgoing packets larger than `maxFragmentSize` and reassembles incoming fragments. Handles timeouts for incomplete packets.
* **Encryption Structure:** Includes structure for AES encryption with per-packet IVs (requires crypto library integration).
* **FEC Structure:** Includes structure for block-based Forward Error Correction (requires FEC library integration).
* **Dynamic Adaptation (Conceptual):**
    * Adjusts congestion window based on ACK success/timeouts (AIMD).
    * Adjusts fragment size based on link quality (SNR).
    * Adjusts priorities based on battery level and channel utilization (basic heuristics implemented).
* **Routing Metric Adjustment (Conceptual):** Calculates adjusted link quality based on priority and SNR, including exponential backoff for poor links (requires Meshtastic API integration to apply).
* **QoS Monitoring:** Tracks basic statistics per traffic class (packets/fragments sent, ACKs received, timeouts, FEC status) and logs them periodically.
* **Configuration:**
    * Loads/saves traffic class settings to NVS.
    * Includes a stubbed command handler (`handleAdminCommand`) for potential external configuration via Meshtastic admin messages.
* **Power Awareness:** Reduces background activity (QoS monitoring, dynamic adaptation) when the device enters light sleep.
* **Resource Limiting:** Basic limits on the number of concurrent fragmentation sessions.
* **Data Callback:** Allows registration of a callback function to receive successfully processed data from the plugin.

## Installation and Integration

This plugin is **not** a standalone library. It must be integrated into the Meshtastic device firmware source code.

1.  **Prerequisites:** Set up the Meshtastic firmware build environment (PlatformIO, toolchains, etc.).
2.  **Clone Firmware:** Clone the official [Meshtastic device firmware repository](https://github.com/meshtastic/firmware).
3.  **Add Plugin Files:**
    * Copy `AkitaTrafficClassPlugin.h` and `AkitaTrafficClassPlugin.cpp` into the `src/modules/` directory (or appropriate plugin directory) of the firmware source.
4.  **Add Protobuf Definition:**
    * Copy `akita_plugin.proto` into the `protos/` directory of the firmware source.
    * Run the firmware's protobuf generation script (e.g., `./bin/regen-protos.sh`) to create/update the corresponding `.pb.h` and `.pb.c` files.
    * Ensure the `#include "akita_plugin.pb.h"` line in `AkitaTrafficClassPlugin.h` correctly points to the generated header.
5.  **Instantiate Plugin:**
    * Edit the relevant core file (e.g., `src/mesh/MeshService.cpp` or `src/modules/Modules.cpp`).
    * Include the plugin header: `#include "modules/AkitaTrafficClassPlugin.h"`
    * In the appropriate setup function (e.g., `MeshService::setupModules()`), add the instantiation line, passing the `MeshInterface` instance:
        ```cpp
        modules.push_back(new AkitaTrafficClassPlugin(*this)); 
        ```
6.  **Add Dependencies (CRITICAL):**
    * **AES Library:** You MUST integrate an AES library (like mbedTLS) into the firmware build if you intend to use the encryption feature. Link the library and replace the placeholder functions in `AkitaTrafficClassPlugin.cpp`.
    * **FEC Library:** You MUST integrate an FEC library (like a Reed-Solomon codec) into the firmware build if you intend to use the FEC feature. Link the library and replace the placeholder functions in `AkitaTrafficClassPlugin.cpp`.
7.  **Verify APIs:** Carefully check all calls to `_meshInterface`, `NVSStorage`, `g_powerFSM`, `RadioInterface`, etc., against the specific version of the Meshtastic firmware API you are using and adapt as necessary.
8.  **Compile:** Build the modified firmware using PlatformIO (e.g., `pio run -e your_target_board`).
9.  **Flash:** Flash the compiled firmware onto your Meshtastic device(s).

## Configuration

Traffic classes are configured within the plugin, typically loaded from NVS on startup. Default classes are created if no configuration is found.

**Parameters per Traffic Class:**

* `id`: (uint32_t) Unique identifier for the class.
* `priority`: (int) Higher number means higher priority (e.g., 1-10).
* `reliable`: (bool) `true` to enable ACKs and retransmissions.
* `encrypted`: (bool) `true` to enable AES encryption (requires library).
* `maxFragmentSize`: (int) Max bytes per LoRa payload chunk (adjust based on LoRa settings and overhead).
* `retries`: (int) Max retransmission attempts for reliable fragments.
* `fec_num_parity_bytes`: (uint8_t) Number of FEC parity bytes (0=disabled, max `FEC_MAX_PARITY_BYTES`). Requires library.
* `congestionWindow`: (int) Initial/current congestion window size.
* `encryptionKey`: (uint8_t) Single byte used to derive placeholder AES key (replace with secure key management).

**Configuration via Commands (Conceptual):**

The plugin includes a `handleAdminCommand` function stub. If the Meshtastic firmware routes specific admin messages/commands to the plugin (this requires core firmware support/integration), you could potentially configure it using commands like:

* `configure_class <id> <prio> <rel> <enc> <frag> <retry> <fec> <cw> <key_byte>`
* `delete_class <id>`
* `get_class_config <id>`
* `list_classes`

*(Check the `handleAdminCommand` function implementation for argument details).*

## Usage

1.  **Initialization:** The plugin initializes automatically when the firmware starts, loading its configuration.
2.  **Sending Data:** Use the `sendData` method of the plugin instance:
    ```cpp
    // Assuming 'akitaPluginInstance' is a pointer to the AkitaTrafficClassPlugin object
    // obtained after firmware initialization.
    uint8_t myData[] = {0x01, 0x02, 0x03};
    uint32_t targetNodeId = 0xFFFFFFFF; // Broadcast example
    uint32_t trafficClassId = 1; // Use traffic class 1 config

    bool success = akitaPluginInstance->sendData(myData, sizeof(myData), trafficClassId, targetNodeId);
    if (success) {
        // Packet accepted by the plugin for processing/sending
    } else {
        // Packet rejected (e.g., unknown TC, session limit reached)
    }
    ```
3.  **Receiving Data:** Register a callback function using `registerDataHandler`:
    ```cpp
    // Callback function example
    void myAppDataReceiver(uint32_t fromNodeId, uint32_t trafficClassId, const std::vector<uint8_t>& data) {
        // Process received data based on trafficClassId and fromNodeId
        printf("Received %d bytes via TC %u from 0x%x\n", data.size(), trafficClassId, fromNodeId);
    }

    // Registration (called once during setup)
    akitaPluginInstance->registerDataHandler(myAppDataReceiver);
    ```
    The plugin will call the registered handler when a complete packet (potentially reassembled, decrypted, and FEC-checked) is ready for the application layer.

## Protobuf Structure

The plugin uses custom protobuf messages embedded within the standard Meshtastic `MeshPacket` payload, identified by `PortNum_AKITA_TRAFFIC_CLASS_APP`.

* **`AkitaPluginEnvelope`**: The outer wrapper, containing either:
    * **`AkitaPacketPayload`**: For data transmission. Includes fields for the data chunk (`original_payload_chunk`), traffic class ID, fragmentation info (`is_fragment`, `fragment_id`, etc.), reliability flags (`ack_requested`), encryption IV (`encryption_iv`), and FEC data (`fec_data`).
    * **`AkitaControlMessage`**: For plugin-internal messages like ACKs (`ACK_FRAGMENT`).

*(Refer to `akita_plugin.proto` for details).*

## Dependencies

* **Meshtastic Firmware:** Requires source code integration and specific internal APIs.
* **Nanopb:** Used by Meshtastic for protobuf serialization.
* **(Required for full function) AES Library:** e.g., mbedTLS. Must be linked into the firmware build.
* **(Required for full function) FEC Library:** e.g., a Reed-Solomon library. Must be linked into the firmware build.

## Current Status & TODOs

* **Conceptual Implementation:** Core logic for fragmentation, reliability, QoS monitoring, configuration, and dynamic adaptation structures are implemented.
* **Placeholders:**
    * **AES Encryption:** Requires integration with a real crypto library (e.g., mbedTLS) and secure IV generation/management.
    * **FEC:** Requires integration with a real FEC library (e.g., Reed-Solomon).
    * **Routing Metric Update:** Requires a Meshtastic API to apply calculated metrics to the core routing algorithm.
* **API Verification:** All calls to Meshtastic internal APIs need verification against the target firmware version.
* **Testing:** Requires extensive testing on real hardware.

## Contributing

Contributions are welcome! Please submit pull requests or open issues to report bugs or suggest enhancements (assuming this project is hosted on a platform like GitHub).

