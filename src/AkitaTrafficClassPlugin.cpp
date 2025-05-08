#include "AkitaTrafficClassPlugin.h"
#include "MeshInterface.h"
#include "RadioInterface.h" 
#include "plugin_utils.h"   
#include "string.h"        
#include "NodeDB.h"
#include "PowerFSM.h"       // For g_powerFSM
#include "NVSStorage.h"     // For NVSStorage::getInstance()

// Nanopb includes for encoding/decoding
#include "pb_encode.h"
#include "pb_decode.h"

#include <numeric> // For std::accumulate
#include <vector>  // Ensure vector is included

// --- Crypto & FEC Library Includes (PLACEHOLDERS) ---
// TODO (MAJOR): Uncomment and ensure these headers are available and correct for your build environment
// #include <mbedtls/aes.h>
// #include <mbedtls/entropy.h>    // If using mbedtls for random IV generation
// #include <mbedtls/ctr_drbg.h> // If using mbedtls for random IV generation
// #include "esp_random.h"        // If using ESP-IDF random generation for IVs

// TODO (MAJOR): Include header for the chosen Reed-Solomon FEC library
// #include "reed_solomon.h" // Example header name

// --- End Library Includes ---


// Define how long to wait for fragments before timing out reassembly
#define REASSEMBLY_TIMEOUT_MS 30000 // 30 seconds
#define RETRANSMISSION_TIMEOUT_MS 5000 // 5 seconds for reliable fragments

// Maximum number of traffic classes we can store in NVS (to prevent unbounded NVS usage)
#define MAX_NVS_TRAFFIC_CLASSES 10
// Estimate for max fragments, used for sanity checks
#define MAX_FRAGMENTS_ESTIMATE 100
// Limits on concurrent fragmentation sessions to prevent resource exhaustion
#define MAX_INCOMING_SESSIONS 20
#define MAX_OUTGOING_SESSIONS 20

// AES block size (128 bits / 16 bytes)
#define AES_BLOCK_SIZE 16
// Size of the IV/Nonce for AES (typically same as block size for CBC/CTR)
#define AES_IV_SIZE 16


namespace meshtastic {

// --- Static Registration ---
// NOTE: Dynamic instantiation within MeshService::setupModules is the PREFERRED approach
// for modern Meshtastic firmware, as it allows passing the MeshInterface correctly.
// This static registration is provided for context/older patterns but may not function
// correctly without modification due to the constructor's MeshInterface dependency.
static Plugin* akitaTrafficClassPluginFactory() {
     // Cannot easily get MeshInterface here for constructor. Return nullptr or handle differently.
     LOG_W("Static akitaTrafficClassPluginFactory called - dynamic instantiation is preferred.");
     return nullptr; 
}
// The actual registration line. This runs when the firmware loads the plugin code.
bool AkitaTrafficClassPlugin::registered = PluginManager::getInstance()->registerPlugin("akita_traffic_class", akitaTrafficClassPluginFactory);
// --- End Static Registration ---


/**
 * @brief Constructor for the AkitaTrafficClassPlugin.
 * Initializes the plugin, loads configuration, and sets up default traffic classes if needed.
 * @param meshInterface Reference to the Meshtastic MeshInterface.
 */
AkitaTrafficClassPlugin::AkitaTrafficClassPlugin(MeshInterface& meshInterface) :
    ProtobufModule(meshInterface, PortNum_AKITA_TRAFFIC_CLASS_APP), // Initialize base ProtobufModule with interface and our PortNum
    gen(rd()), // Initialize C++ random number generator (can be used for non-crypto randomness)
    currentRadioState(RadioState_IDLE), // Initialize radio state
    lastQoSResetTime(std::chrono::steady_clock::now()) // Initialize QoS timer
     {
    LOG_I("Akita Traffic Class Plugin initializing...");
    loadPluginConfig(); // Load configuration from NVS

    // If no configuration was loaded from NVS, set up some defaults
    if (trafficClasses.empty()) {
        LOG_I("No existing config found. Setting default traffic classes.");
        // TC ID, Prio, Rel, Enc, FragSz, Retry, FECParityBytes, CW, EncKey
        configureTrafficClass(0, 3, false, false, 180, 0, 0, 5, 0xAA); // Default, no FEC
        configureTrafficClass(1, 5, true,  true,  150, 3, 4, 3, 0xBB); // Reliable, encrypted, 4 FEC bytes
        configureTrafficClass(2, 7, true,  true,  100, 5, 8, 2, 0xCC); // Critical, 8 FEC bytes
    }
    LOG_I("Akita Traffic Class Plugin initialized.");
}

/**
 * @brief Destructor for the AkitaTrafficClassPlugin.
 * Logs a shutdown message and potentially performs cleanup.
 */
AkitaTrafficClassPlugin::~AkitaTrafficClassPlugin() {
    LOG_I("Akita Traffic Class Plugin shutting down.");
    // Log warnings if there are still incomplete fragmentation sessions, indicating potential issues.
    if (!incomingFragments.empty()) {
        LOG_W("Plugin destroyed with %d incomplete incoming fragment sessions.", incomingFragments.size());
    }
     if (!outgoingFragments.empty()) {
        LOG_W("Plugin destroyed with %d incomplete outgoing fragment sessions.", outgoingFragments.size());
    }
    // TODO: Consider if queues need flushing or handling on shutdown
}

// --- Encryption Implementation (using mbedTLS structure) ---

/**
 * @brief Placeholder for AES encryption using a library like mbedTLS (CBC mode example).
 * @param plaintext Input data. Will be padded using PKCS#7 (padding not implemented in placeholder).
 * @param key 128-bit (16 byte) encryption key.
 * @param iv 128-bit (16 byte) Initialization Vector. MUST be unique per encryption.
 * @param ciphertext Output encrypted data. Resized appropriately.
 * @return True on simulated success, false otherwise.
 */
bool aesEncrypt(std::vector<uint8_t>& plaintext, const uint8_t* key, const uint8_t* iv, std::vector<uint8_t>& ciphertext) {
    // TODO (MAJOR): Replace with actual AES implementation (e.g., mbedtls_aes_crypt_cbc)
    LOG_W("AES Encrypt: Using placeholder structure. Requires real crypto library integration.");

    // --- Placeholder mbedTLS Structure ---
    // mbedtls_aes_context aes_ctx;
    // mbedtls_aes_init(&aes_ctx);
    // int ret = mbedtls_aes_setkey_enc(&aes_ctx, key, 128); // Assuming 128-bit key
    // if (ret != 0) { LOG_E("mbedtls_aes_setkey_enc failed: %d", ret); mbedtls_aes_free(&aes_ctx); return false; }
    
    // // PKCS#7 Padding (Example - MUST be implemented for CBC)
    // size_t pad_len = AES_BLOCK_SIZE - (plaintext.size() % AES_BLOCK_SIZE);
    // // Even if size is multiple of block size, add a full block of padding
    // if (pad_len == 0) pad_len = AES_BLOCK_SIZE; 
    // plaintext.insert(plaintext.end(), pad_len, (uint8_t)pad_len);
    
    // ciphertext.resize(plaintext.size()); // Ciphertext size matches padded plaintext size
    // uint8_t stream_iv[AES_IV_SIZE]; // mbedtls_aes_crypt_cbc modifies the IV
    // memcpy(stream_iv, iv, AES_IV_SIZE); 

    // ret = mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT, plaintext.size(), stream_iv, plaintext.data(), ciphertext.data());
    // mbedtls_aes_free(&aes_ctx);
    // if (ret != 0) { 
    //     LOG_E("mbedtls_aes_crypt_cbc (encrypt) failed: %d", ret); 
    //     plaintext.resize(plaintext.size() - pad_len); // Remove padding on failure
    //     return false; 
    // }
    // --- End Placeholder mbedTLS Structure ---

    // Simple simulation: Copy and XOR with first byte of IV
    ciphertext = plaintext; // Simulate padding was added conceptually
    if (!ciphertext.empty() && iv) {
        for(size_t i=0; i<ciphertext.size(); ++i) ciphertext[i] ^= iv[0];
    }

    return true; // Simulate success
}

/**
 * @brief Placeholder for AES decryption using a library like mbedTLS (CBC mode example).
 * @param ciphertext Input encrypted data. Must be multiple of block size.
 * @param key 128-bit (16 byte) decryption key.
 * @param iv 128-bit (16 byte) Initialization Vector used during encryption.
 * @param plaintext Output decrypted data. Resized appropriately after removing padding.
 * @return True on success, false otherwise (e.g., decryption or padding error).
 */
bool aesDecrypt(const std::vector<uint8_t>& ciphertext, const uint8_t* key, const uint8_t* iv, std::vector<uint8_t>& plaintext) {
    // TODO (MAJOR): Replace with actual mbedTLS implementation. Requires linking mbedTLS library.
    LOG_W("AES Decrypt: Using placeholder structure. Requires real mbedTLS integration.");
    
    // Basic checks
    if (ciphertext.empty()) { // Allow empty ciphertext (might represent padded empty plaintext)
         // Check if size is multiple of block size (required for CBC)
         // if ((ciphertext.size() % AES_BLOCK_SIZE) != 0) {
         //    LOG_E("AES Decrypt: Invalid ciphertext size (%d). Not a multiple of block size.", ciphertext.size());
         //    return false; 
         // }
    }


    // --- Placeholder mbedTLS Structure ---
    // mbedtls_aes_context aes_ctx;
    // mbedtls_aes_init(&aes_ctx);
    // int ret = mbedtls_aes_setkey_dec(&aes_ctx, key, 128); // Use setkey_dec for decryption
    // if (ret != 0) { LOG_E("mbedtls_aes_setkey_dec failed: %d", ret); mbedtls_aes_free(&aes_ctx); return false; }

    // plaintext.resize(ciphertext.size()); // Decrypted size initially matches ciphertext size
    // uint8_t stream_iv[AES_IV_SIZE]; 
    // memcpy(stream_iv, iv, AES_IV_SIZE);

    // ret = mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_DECRYPT, ciphertext.size(), stream_iv, ciphertext.data(), plaintext.data());
    // mbedtls_aes_free(&aes_ctx);
    // if (ret != 0) { LOG_E("mbedtls_aes_crypt_cbc (decrypt) failed: %d", ret); return false; }

    // // Remove PKCS#7 Padding
    // if (!plaintext.empty()) {
    //     size_t pad_len = plaintext.back();
    //     // Validate padding length
    //     if (pad_len == 0 || pad_len > AES_BLOCK_SIZE || pad_len > plaintext.size()) {
    //          LOG_E("AES Decrypt: Invalid padding length %d", pad_len); return false; 
    //     }
    //     // Verify all padding bytes have the correct value
    //     for (size_t i = 0; i < pad_len; ++i) { 
    //         if (plaintext[plaintext.size() - 1 - i] != pad_len) {
    //              LOG_E("AES Decrypt: Invalid padding bytes"); return false; 
    //         }
    //     }
    //     plaintext.resize(plaintext.size() - pad_len); // Remove padding
    // } else if (!ciphertext.empty()) { // If ciphertext wasn't empty but plaintext is after decrypt, error
    //      LOG_E("AES Decrypt: Decryption resulted in empty plaintext before padding removal."); return false;
    // }
    // --- End Placeholder mbedTLS Structure ---

    // Simple simulation: Copy and XOR with first byte of IV
    plaintext = ciphertext;
    if (!plaintext.empty() && iv) {
        for(size_t i=0; i<plaintext.size(); ++i) plaintext[i] ^= iv[0];
    }

    return true; // Simulate success
}

/**
 * @brief Applies configured encryption/decryption using placeholder AES functions.
 * @param data Data to encrypt or decrypt (modified in place).
 * @param key_byte The single byte key from config (used to derive placeholder AES key).
 * @param iv Pointer to the 16-byte IV to use (must be provided).
 * @param encrypt True to encrypt, false to decrypt.
 * @return True on success, false on failure.
 */
bool AkitaTrafficClassPlugin::applyPluginEncryption(std::vector<uint8_t>& data, uint8_t key_byte, const uint8_t* iv, bool encrypt) {
    if (!iv) {
        LOG_E("applyPluginEncryption: IV cannot be null!");
        return false;
    }
    
    // Derive placeholder 128-bit key
    uint8_t aesKey[16]; 
    memset(aesKey, key_byte, sizeof(aesKey)); 
    aesKey[15] = 0xAA; // Make it slightly less uniform

    std::vector<uint8_t> result_data;
    bool success = false;

    if (encrypt) {
        // Input 'data' is plaintext, output 'result_data' is ciphertext
        success = aesEncrypt(data, aesKey, 128, iv, result_data);
        if (success) {
            data = result_data; // Replace original data with ciphertext
        } else {
             LOG_E("Plugin AES Encryption failed!");
        }
    } else {
        // Input 'data' is ciphertext, output 'result_data' is plaintext
        success = aesDecrypt(data, aesKey, 128, iv, result_data);
         if (success) {
            data = result_data; // Replace original data with plaintext
        } else {
             LOG_E("Plugin AES Decryption failed!");
             data.clear(); // Clear data on decryption failure to prevent using corrupted plaintext
        }
    }
    return success;
}


// --- Structured (Simplified) FEC Methods ---
/**
 * @brief Generates block parity FEC bytes for a data chunk.
 * @param data_chunk The data to generate FEC for.
 * @param num_parity_bytes The number of parity bytes to generate. Max FEC_MAX_PARITY_BYTES.
 * @return A vector containing the generated parity bytes. Empty if no FEC or error.
 */
std::vector<uint8_t> AkitaTrafficClassPlugin::applyFEC(const std::vector<uint8_t>& data_chunk, uint8_t num_parity_bytes) {
    // TODO (MAJOR): Replace with real FEC library (e.g., Reed-Solomon) encoder call.
    LOG_W("FEC Apply: Using simplified block parity placeholder.");
    std::vector<uint8_t> fec_data;
    if (num_parity_bytes == 0) { 
        return fec_data; 
    }
    uint8_t actual_parity_bytes = std::min(num_parity_bytes, (uint8_t)FEC_MAX_PARITY_BYTES);
    if (actual_parity_bytes == 0) return fec_data; 

    fec_data.resize(actual_parity_bytes, 0x00); 
    if (!data_chunk.empty()) { // Only XOR if data exists
        for (size_t i = 0; i < data_chunk.size(); ++i) {
            fec_data[i % actual_parity_bytes] ^= data_chunk[i];
        }
    } else {
        // Handle 0-byte data case - parity remains zeros for this simple scheme
    }
    return fec_data;
}

/**
 * @brief Checks data integrity using received FEC data and potentially corrects it.
 * @param data_chunk The received data chunk (will be modified if corrected by a real library).
 * @param received_fec_chunk The received FEC parity data.
 * @return FEC_Status indicating outcome.
 */
FEC_Status AkitaTrafficClassPlugin::checkAndCorrectFEC(std::vector<uint8_t>& data_chunk, const std::vector<uint8_t>& received_fec_chunk) {
    // TODO (MAJOR): Replace with real FEC library (e.g., Reed-Solomon) decoder call.
    LOG_W("FEC Check: Using simplified block parity placeholder (detection only).");
    if (received_fec_chunk.empty()) {
        return FEC_NOT_APPLICABLE; 
    }
    // Allow empty data chunk check if FEC was generated for it
    // if (data_chunk.empty() && !received_fec_chunk.empty()) {
    //      LOG_W("FEC check: Data chunk is empty but FEC data exists. Assuming failure.");
    //      return FEC_FAILED;
    // }
    if (data_chunk.empty() && received_fec_chunk.empty()) {
        return FEC_NOT_APPLICABLE;
    }

    std::vector<uint8_t> calculated_fec_from_data = applyFEC(data_chunk, received_fec_chunk.size());

    if (calculated_fec_from_data.size() != received_fec_chunk.size()) {
        LOG_E("FEC check: Mismatch in expected FEC size (%d) and calculated FEC size (%d). Assuming failure.",
              received_fec_chunk.size(), calculated_fec_from_data.size());
        return FEC_FAILED; 
    }

    bool match = (calculated_fec_from_data == received_fec_chunk);

    if (match) {
        return FEC_OK;
    } else {
        LOG_W("Block parity FEC check: FAILED (parity mismatch)");
        return FEC_FAILED;
    }
}


/**
 * @brief Handles incoming packets directed to this plugin's PortNum.
 * Processes the AkitaPluginEnvelope, decrypts, checks FEC, handles fragmentation/reassembly,
 * sends ACKs, and delivers complete data via callback.
 * @param envelope The received AkitaPluginEnvelope protobuf message.
 * @param meshPacket The original MeshPacket containing the envelope.
 */
void AkitaTrafficClassPlugin::handleReceivedProtobuf(meshtastic_AkitaPluginEnvelope &envelope, const MeshPacket &meshPacket) {
    LOG_D("Akita Plugin: Received AkitaPluginEnvelope from 0x%x, RSSI %d, SNR %.2f",
          meshPacket.from, meshPacket.rx_rssi, meshPacket.rx_snr);

    if (envelope.which_payload_variant == meshtastic_AkitaPluginEnvelope_data_payload_tag) {
        processIncomingAkitaPayload(envelope.payload_variant.data_payload, meshPacket);
    } else if (envelope.which_payload_variant == meshtastic_AkitaPluginEnvelope_control_payload_tag) {
        processIncomingAkitaControl(envelope.payload_variant.control_payload, meshPacket);
    } else {
        LOG_W("Akita Plugin: Received envelope with unknown payload variant.");
    }
}

/**
 * @brief Processes the data payload part of an AkitaPluginEnvelope.
 * Handles decryption, FEC check, fragment storage, reassembly triggering, and final data delivery.
 * @param payload The received AkitaPacketPayload protobuf message.
 * @param meshPacket The original MeshPacket.
 */
void AkitaTrafficClassPlugin::processIncomingAkitaPayload(const meshtastic_AkitaPacketPayload &payload, const MeshPacket &meshPacket) {
    LOG_D("Processing AkitaDataPayload: TC=%u, FragID=%u, FragIndex=%u/%u from 0x%x",
        payload.traffic_class_id, payload.fragment_id, payload.fragment_index, payload.fragment_count, meshPacket.from);

    const TrafficClassConfig* config = getTrafficClassConfig(payload.traffic_class_id);
    if (!config) {
        LOG_E("Received payload for unknown TC %u. Dropping.", payload.traffic_class_id);
        return;
    }

    // Limit concurrent incoming sessions
    uint32_t combinedKey = (static_cast<uint32_t>(meshPacket.from) << 16) | (payload.fragment_id & 0xFFFF);
    if (payload.is_fragment && 
        incomingFragments.find(combinedKey) == incomingFragments.end() && 
        incomingFragments.size() >= MAX_INCOMING_SESSIONS) {
        LOG_E("Max incoming fragment sessions (%d) reached. Dropping new fragment ID %u from 0x%x.",
              MAX_INCOMING_SESSIONS, payload.fragment_id, meshPacket.from);
        return;
    }

    // --- Prepare data vectors ---
    std::vector<uint8_t> current_payload_chunk; 
    if (payload.original_payload_chunk.size > current_payload_chunk.max_size()){
         LOG_E("Fragment payload size %d exceeds vector max size. Dropping.", payload.original_payload_chunk.size);
         return;
    }
    current_payload_chunk.assign(payload.original_payload_chunk.bytes, payload.original_payload_chunk.bytes + payload.original_payload_chunk.size);
    
    std::vector<uint8_t> current_fec_data;
    if (payload.fec_data.size > current_fec_data.max_size()){
         LOG_E("Fragment FEC size %d exceeds vector max size. Dropping.", payload.fec_data.size);
         return;
    }
    current_fec_data.assign(payload.fec_data.bytes, payload.fec_data.bytes + payload.fec_data.size);

    // --- Decryption ---
    uint8_t received_iv[AES_IV_SIZE];
    bool iv_present = false;
    if (config->encrypted) {
        if (payload.encryption_iv.size == AES_IV_SIZE) {
            memcpy(received_iv, payload.encryption_iv.bytes, AES_IV_SIZE);
            iv_present = true;
        } else if (payload.encryption_iv.size != 0) {
            LOG_W("Received packet for encrypted TC %u with invalid IV size %d. Decryption will likely fail.", 
                payload.traffic_class_id, payload.encryption_iv.size);
        } else {
            LOG_E("Received packet for encrypted TC %u without an IV. Cannot decrypt.", payload.traffic_class_id);
            return; // Cannot proceed without IV for encrypted data
        }

        if (!iv_present) {
             LOG_E("Cannot decrypt TC %u fragment %u/%u: IV missing or invalid size.", 
                 payload.traffic_class_id, payload.fragment_index, payload.fragment_count);
             return; // Cannot proceed
        }
        // Pass key byte and received IV
        bool decrypt_ok = applyPluginEncryption(current_payload_chunk, config->encryptionKey, false, received_iv); 
        if (!decrypt_ok || current_payload_chunk.empty()) { 
            LOG_E("Decryption failed for TC %u, Frag %u/%u from 0x%x. Dropping.",
                payload.traffic_class_id, payload.fragment_index, payload.fragment_count, meshPacket.from);
            return; 
        }
        LOG_D("Decrypted payload chunk for TC %u", payload.traffic_class_id);
    }
    
    // --- FEC Check ---
    FEC_Status fec_status = FEC_NOT_APPLICABLE;
    bool fragment_data_ok = true; 
    if (config->fec_num_parity_bytes > 0) {
        fec_status = checkAndCorrectFEC(current_payload_chunk, current_fec_data);
        LOG_D("FEC Status for TC %u, Frag %u/%u: %d", payload.traffic_class_id, payload.fragment_index, payload.fragment_count, fec_status);
        if (fec_status == FEC_FAILED) {
            fragment_data_ok = false;
        }
    } else { 
        fec_status = FEC_NOT_APPLICABLE; 
    }

    // Update QoS Stats
    if (qosStats.count(payload.traffic_class_id)) {
        if (fec_status == FEC_FAILED) qosStats[payload.traffic_class_id].fecFailures++;
        if (fec_status == FEC_CORRECTED) qosStats[payload.traffic_class_id].fecCorrected++;
    }

    if (!fragment_data_ok) { 
        LOG_E("FEC FAILED for TC %u, Frag %u/%u from 0x%x. Fragment data is considered corrupt.", 
            payload.traffic_class_id, payload.fragment_index, payload.fragment_count, meshPacket.from);
    }

    // --- Store Fragment Info or Process Non-Fragmented ---
    if (payload.is_fragment) {
        IncomingFragmentedPacket::FragmentInfo fragInfo;
        fragInfo.raw_payload_chunk.assign(payload.original_payload_chunk.bytes, payload.original_payload_chunk.bytes + payload.original_payload_chunk.size); 
        fragInfo.fec_data_chunk.assign(payload.fec_data.bytes, payload.fec_data.bytes + payload.fec_data.size);
        fragInfo.processed_successfully = fragment_data_ok;
        if (fragment_data_ok) {
            fragInfo.corrected_decrypted_payload = current_payload_chunk; 
        }
        fragInfo.fec_num_parity_bytes_expected = config->fec_num_parity_bytes;
        fragInfo.encrypted_expected = config->encrypted;
        fragInfo.encryption_key_expected = config->encryptionKey;

        // Initialize map entry if first fragment for this combo
        if (incomingFragments.find(combinedKey) == incomingFragments.end()) {
            if (incomingFragments.size() >= MAX_INCOMING_SESSIONS) { // Double check limit before insert
                 LOG_E("Max incoming fragment sessions (%d) reached just before insert. Dropping fragment ID %u from 0x%x.",
                       MAX_INCOMING_SESSIONS, payload.fragment_id, meshPacket.from);
                 return;
            }
            incomingFragments[combinedKey].fragmentId = payload.fragment_id;
            incomingFragments[combinedKey].totalFragments = payload.fragment_count;
            incomingFragments[combinedKey].sourceNodeNum = meshPacket.from;
            incomingFragments[combinedKey].originalMessageSize = payload.original_message_size;
            incomingFragments[combinedKey].trafficClassId = payload.traffic_class_id;
        }
        
        incomingFragments[combinedKey].lastFragmentReceivedTime = std::chrono::steady_clock::now();
        incomingFragments[combinedKey].receivedRawFragments[payload.fragment_index] = fragInfo;


        LOG_D("Stored fragment %u (Processed OK: %d) for ID %u from 0x%x. Received %d/%u fragments.",
              payload.fragment_index, fragment_data_ok, payload.fragment_id, meshPacket.from,
              incomingFragments[combinedKey].receivedRawFragments.size(),
              incomingFragments[combinedKey].totalFragments);

        // Only send ACK if fragment data is considered OK
        if (fragment_data_ok && config->reliable && payload.ack_requested) { 
            sendAckForFragment(meshPacket.from, payload.fragment_id, payload.fragment_index);
        }

        // Check if *all* fragments are now present AND processed successfully
        bool all_fragments_accounted_for = (incomingFragments[combinedKey].receivedRawFragments.size() == (size_t)incomingFragments[combinedKey].totalFragments);
        if (all_fragments_accounted_for) {
            bool can_reassemble = true;
            for(int i=0; i < incomingFragments[combinedKey].totalFragments; ++i) {
                if(incomingFragments[combinedKey].receivedRawFragments.find(i) == incomingFragments[combinedKey].receivedRawFragments.end() ||
                   !incomingFragments[combinedKey].receivedRawFragments.at(i).processed_successfully) { 
                    can_reassemble = false;
                    LOG_W("Cannot reassemble ID %u: fragment %d missing or failed processing.", payload.fragment_id, i);
                    break;
                }
            }
            if (can_reassemble) {
                LOG_I("All %u fragments for ID %u from 0x%x successfully processed. Reassembling.", 
                    incomingFragments[combinedKey].totalFragments, payload.fragment_id, meshPacket.from);
                reassembleAndProcessPacket(combinedKey);
                incomingFragments.erase(combinedKey); // Clean up map entry after successful reassembly
            }
        }
    } else { // Non-fragmented packet
        LOG_I("Received non-fragmented Akita packet (TC %u) from 0x%x. Size: %d. FEC Status: %d",
              payload.traffic_class_id, meshPacket.from, current_payload_chunk.size(), fec_status);
        
        if (fragment_data_ok && config->reliable && payload.ack_requested) {
            sendAckForFragment(meshPacket.from, 0, 0); 
        }

        if (fragment_data_ok) {
            // Deliver data using the callback
            if (onDataReceived) {
                LOG_D("Delivering non-fragmented data (TC %u, %d bytes) from 0x%x via callback.",
                    payload.traffic_class_id, current_payload_chunk.size(), meshPacket.from);
                onDataReceived(meshPacket.from, payload.traffic_class_id, current_payload_chunk);
            } else {
                LOG_W("No data handler registered to receive non-fragmented data for TC %u.", payload.traffic_class_id);
            }
        } else {
            LOG_E("Non-fragmented packet for TC %u failed FEC/decryption. Discarding.", payload.traffic_class_id);
        }
    }
}

/**
 * @brief Processes incoming control messages (like ACKs).
 * @param controlMsg The received AkitaControlMessage protobuf.
 * @param meshPacket The original MeshPacket.
 */
void AkitaTrafficClassPlugin::processIncomingAkitaControl(const meshtastic_AkitaControlMessage &controlMsg, const MeshPacket &meshPacket) {
    LOG_D("Processing AkitaControlMessage type %d from 0x%x for fragID %u, fragIndex %u", 
        controlMsg.control_type, meshPacket.from, controlMsg.target_fragment_id, controlMsg.target_fragment_index);
    
    if (controlMsg.control_type == meshtastic_AkitaControlMessage_ControlType_ACK_FRAGMENT) {
        auto it = outgoingFragments.find(controlMsg.target_fragment_id); 
        if (it != outgoingFragments.end()) {
            OutgoingFragmentedPacket& pkt = it->second;
            // Verify ACK source matches destination (or was broadcast)
            if (pkt.destinationNodeNum == meshPacket.from || pkt.destinationNodeNum == BROADCAST_ADDR) { 
                // Check if index is valid and not already ACKed
                if (controlMsg.target_fragment_index < (uint32_t)pkt.totalFragments && 
                    pkt.ackedFragmentStatus.count(controlMsg.target_fragment_index) && 
                    !pkt.ackedFragmentStatus.at(controlMsg.target_fragment_index)) { // Use .at() after count check
                    
                    pkt.ackedFragmentStatus[controlMsg.target_fragment_index] = true;
                    pkt.ackedFragmentsCount++;
                    
                    // Update QoS Stats
                    uint32_t tcId = 0;
                    if (!pkt.fragments.empty()) tcId = pkt.fragments[0].payload_variant.data_payload.traffic_class_id;
                    if (qosStats.count(tcId)) {
                        qosStats[tcId].acksReceived++;
                    }
                    // Adjust Congestion Window on ACK
                    adjustCongestionWindow(tcId, true); 

                    LOG_D("ACK received for fragment %u of ID %u (to 0x%x). Total ACKed: %d/%d",
                          controlMsg.target_fragment_index, controlMsg.target_fragment_id,
                          pkt.destinationNodeNum, pkt.ackedFragmentsCount, pkt.totalFragments);

                    // If all fragments are now ACKed, remove the tracking entry
                    if (pkt.ackedFragmentsCount == pkt.totalFragments) {
                        LOG_I("All %d fragments for ID %u (to 0x%x) successfully ACKed. Cleaning up.", 
                            pkt.totalFragments, controlMsg.target_fragment_id, pkt.destinationNodeNum);
                        outgoingFragments.erase(it); // Erase map entry on completion
                    }
                } else if (controlMsg.target_fragment_index < (uint32_t)pkt.totalFragments && 
                           pkt.ackedFragmentStatus.count(controlMsg.target_fragment_index) && 
                           pkt.ackedFragmentStatus.at(controlMsg.target_fragment_index)) {
                    LOG_D("Duplicate ACK for fragment %u of ID %u. Ignoring.", controlMsg.target_fragment_index, controlMsg.target_fragment_id);
                } else {
                     LOG_W("Received ACK for out-of-bounds or non-tracked fragment index %u (total %d) of ID %u.", 
                        controlMsg.target_fragment_index, pkt.totalFragments, controlMsg.target_fragment_id);
                }
            } else {
                 LOG_W("Received ACK for fragment ID %u from 0x%x, but packet was destined for 0x%x. Ignoring.",
                    controlMsg.target_fragment_id, meshPacket.from, pkt.destinationNodeNum);
            }
        } else {
            LOG_W("Received ACK for unknown/timed-out outgoing fragment ID %u. Might be late.", controlMsg.target_fragment_id);
        }
    } else if (controlMsg.control_type == meshtastic_AkitaControlMessage_ControlType_REQUEST_RETRANSMISSION) {
        // TODO: Implement receiver-driven retransmission requests if needed.
        LOG_W("REQUEST_RETRANSMISSION handling not fully implemented.");
    }
}

/**
 * @brief Sends an ACK control message for a specific received fragment.
 * @param destinationNodeNum The node ID of the original sender.
 * @param fragmentId The fragment ID being acknowledged.
 * @param fragmentIndex The index of the fragment being acknowledged.
 */
void AkitaTrafficClassPlugin::sendAckForFragment(uint32_t destinationNodeNum, uint32_t fragmentId, uint32_t fragmentIndex) {
    // Avoid sending ACKs to broadcast address or self
    if (destinationNodeNum == BROADCAST_ADDR || destinationNodeNum == _meshInterface.getMyNodeNum()) {
        return;
    }

    LOG_D("Sending ACK for fragment ID %u, index %u to 0x%x", fragmentId, fragmentIndex, destinationNodeNum);

    meshtastic_AkitaPluginEnvelope envelope = meshtastic_AkitaPluginEnvelope_init_default;
    envelope.which_payload_variant = meshtastic_AkitaPluginEnvelope_control_payload_tag;
    
    meshtastic_AkitaControlMessage& controlMsg = envelope.payload_variant.control_payload;
    controlMsg = meshtastic_AkitaControlMessage_init_default;
    controlMsg.control_type = meshtastic_AkitaControlMessage_ControlType_ACK_FRAGMENT;
    controlMsg.target_fragment_id = fragmentId;
    controlMsg.target_fragment_index = fragmentIndex;

    // Send the ACK packet non-reliably
    sendRawPluginPacket(envelope, destinationNodeNum, false); 
}


/**
 * @brief Reassembles the final payload from successfully processed fragments and delivers it.
 * @param combinedKey The key used in the incomingFragments map.
 */
void AkitaTrafficClassPlugin::reassembleAndProcessPacket(uint32_t combinedKey) {
    auto it = incomingFragments.find(combinedKey);
    if (it == incomingFragments.end()) {
        LOG_E("Reassembly called for unknown combinedKey %u", combinedKey);
        return;
    }

    IncomingFragmentedPacket& fragmentedPacket = it->second;
    std::vector<uint8_t> fullPayload;
    
    // Pre-allocate based on original size if known and seems valid
    if (fragmentedPacket.originalMessageSize > 0 && fragmentedPacket.originalMessageSize < (MAX_LORA_PAYLOAD * MAX_FRAGMENTS_ESTIMATE)) { 
         fullPayload.reserve(fragmentedPacket.originalMessageSize);
    } else {
        // Estimate size based on successfully processed fragments
        size_t estimatedSize = 0;
        bool estimation_possible = true;
        for(int i=0; i < fragmentedPacket.totalFragments; ++i) {
            auto frag_it_info = fragmentedPacket.receivedRawFragments.find(i);
            if (frag_it_info != fragmentedPacket.receivedRawFragments.end() && frag_it_info->second.processed_successfully) {
                estimatedSize += frag_it_info->second.corrected_decrypted_payload.size();
            } else { 
                LOG_E("Missing or unprocessed fragment %u during reassembly size estimation for ID %u. Cannot reassemble.", i, fragmentedPacket.fragmentId);
                estimation_possible = false;
                break; 
            }
        }
        if (estimation_possible && estimatedSize > 0 && estimatedSize < (MAX_LORA_PAYLOAD * MAX_FRAGMENTS_ESTIMATE)) {
            fullPayload.reserve(estimatedSize);
        } else if (estimation_possible) {
             LOG_W("Reassembly for ID %u: Estimated size %d seems invalid. Using fallback allocation.", fragmentedPacket.fragmentId, estimatedSize);
             fullPayload.reserve(fragmentedPacket.totalFragments * 200); // Generic fallback
        } else {
             return; // Cannot reassemble if estimation failed
        }
    }

    // Concatenate payloads from successfully processed fragments in order
    for (int i = 0; i < fragmentedPacket.totalFragments; ++i) {
        auto frag_it_info = fragmentedPacket.receivedRawFragments.find(i);
        // This check should have passed if we reached here from processIncomingAkitaPayload's reassembly trigger
        if (frag_it_info == fragmentedPacket.receivedRawFragments.end() || !frag_it_info->second.processed_successfully) {
            LOG_E("Fragment %u for ID %u unexpectedly missing or failed during final reassembly stage. Aborting.", i, fragmentedPacket.fragmentId);
            return; 
        }
        const std::vector<uint8_t>& chunk_data = frag_it_info->second.corrected_decrypted_payload;
        // Check for potential overflow before inserting if reserve wasn't perfect
        if (fullPayload.size() + chunk_data.size() > fullPayload.capacity() && fullPayload.capacity() > 0) {
            // This might indicate originalMessageSize was wrong or chunks are larger than expected
            LOG_W("Reassembly overflow detected for ID %u. Potential data truncation.", fragmentedPacket.fragmentId);
            // Decide how to handle: reserve more, truncate, or error out. For now, let insert handle reallocation.
        }
        fullPayload.insert(fullPayload.end(), chunk_data.begin(), chunk_data.end());
    }

    // Final size check against original size
    if (fragmentedPacket.originalMessageSize > 0 && fragmentedPacket.originalMessageSize != fullPayload.size()) {
        LOG_W("Reassembled packet ID %u size %d does not match original size %u.",
            fragmentedPacket.fragmentId, fullPayload.size(), fragmentedPacket.originalMessageSize);
    }

    LOG_I("Successfully reassembled packet ID %u from 0x%x (TC %u). Final size: %d bytes.",
          fragmentedPacket.fragmentId, fragmentedPacket.sourceNodeNum, fragmentedPacket.trafficClassId, fullPayload.size());

    // Deliver data using the callback
    if (onDataReceived) {
         LOG_D("Delivering reassembled data (TC %u, %d bytes) from 0x%x via callback.",
              fragmentedPacket.trafficClassId, fullPayload.size(), fragmentedPacket.sourceNodeNum);
        onDataReceived(fragmentedPacket.sourceNodeNum, fragmentedPacket.trafficClassId, fullPayload);
    } else {
        LOG_W("No data handler registered to receive reassembled data for TC %u.", fragmentedPacket.trafficClassId);
    }
}


/**
 * @brief Public method for applications to send data via this plugin.
 * Handles fragmentation, FEC, encryption, and queuing based on Traffic Class config.
 * @param data Pointer to the raw data buffer.
 * @param size Size of the data buffer.
 * @param trafficClassId The ID of the traffic class to use.
 * @param destinationNodeNum The destination node ID (use BROADCAST_ADDR for broadcast).
 * @return True if the data was accepted for processing, false otherwise (e.g., invalid TC, session limit).
 */
bool AkitaTrafficClassPlugin::sendData(const uint8_t *data, size_t size, uint32_t trafficClassId, uint32_t destinationNodeNum) {
    const TrafficClassConfig* config = getTrafficClassConfig(trafficClassId);
    if (!config) {
        LOG_E("SendData: Unknown traffic class ID %u", trafficClassId);
        return false;
    }

    LOG_D("SendData: TC=%u, Size=%d, Dest=0x%x, MaxFragSize=%d, FECParity=%d",
        trafficClassId, size, destinationNodeNum, config->maxFragmentSize, config->fec_num_parity_bytes);

    if (!data && size > 0) {
         LOG_E("SendData: Data pointer is null but size is %d.", size);
         return false;
    }
    if (size == 0 && config->fec_num_parity_bytes == 0) { 
        LOG_W("SendData: Attempted to send 0 bytes for TC %u with no FEC. Dropping.", trafficClassId);
        return false; 
    }
    
    // Calculate overhead per fragment/packet
    int protobufOverheadEstimate = 30 + (config->encrypted ? AES_IV_SIZE : 0); 
    uint8_t actual_fec_bytes_for_this_tc = std::min(config->fec_num_parity_bytes, (uint8_t)FEC_MAX_PARITY_BYTES);
    int actualMaxDataChunkSize = config->maxFragmentSize - protobufOverheadEstimate - actual_fec_bytes_for_this_tc;
    
    if (actualMaxDataChunkSize < 0) actualMaxDataChunkSize = 0; 

    bool needs_fragmentation = (size > (size_t)actualMaxDataChunkSize);
    if (size == 0 && actual_fec_bytes_for_this_tc > 0) {
        needs_fragmentation = false;
        actualMaxDataChunkSize = 0; 
    } else if (actualMaxDataChunkSize <= 0 && size > 0) {
        LOG_E("MaxFragmentSize %d for TC %u is too small (becomes %d for data chunk) after accounting for overhead and FEC (%d bytes). Cannot send %d data bytes.", 
            config->maxFragmentSize, trafficClassId, actualMaxDataChunkSize, actual_fec_bytes_for_this_tc, size);
        return false;
    }


    if (needs_fragmentation) {
        // Check outgoing session limit *before* starting fragmentation
        if (outgoingFragments.size() >= MAX_OUTGOING_SESSIONS) {
             LOG_E("Max outgoing fragment sessions (%d) reached. Cannot start new fragmentation for TC %u.",
                  MAX_OUTGOING_SESSIONS, trafficClassId);
             return false;
        }
        LOG_D("Data size %d > actualMaxDataChunkSize %d. Fragmenting for TC %u.", size, actualMaxDataChunkSize, trafficClassId);
        handleFragmentation(data, size, trafficClassId, destinationNodeNum);
    } else { // Send as a single packet
        meshtastic_AkitaPluginEnvelope envelope = meshtastic_AkitaPluginEnvelope_init_default;
        envelope.which_payload_variant = meshtastic_AkitaPluginEnvelope_data_payload_tag;
        meshtastic_AkitaPacketPayload& payload = envelope.payload_variant.data_payload;
        
        payload = meshtastic_AkitaPacketPayload_init_default;
        payload.traffic_class_id = trafficClassId;
        payload.is_fragment = false;
        payload.original_message_size = size;
        payload.ack_requested = config->reliable; 

        std::vector<uint8_t> data_chunk_vec(data, data + size); // Plaintext data
        std::vector<uint8_t> fec_data_vec;

        // Apply FEC before encryption
        if (actual_fec_bytes_for_this_tc > 0) {
            fec_data_vec = applyFEC(data_chunk_vec, actual_fec_bytes_for_this_tc);
            if (fec_data_vec.size() > sizeof(payload.fec_data.bytes)) {
                LOG_E("Generated FEC data (size %d) too large for static buffer (size %d).",
                    fec_data_vec.size(), sizeof(payload.fec_data.bytes));
                return false; 
            }
            memcpy(payload.fec_data.bytes, fec_data_vec.data(), fec_data_vec.size());
            payload.fec_data.size = fec_data_vec.size();
        }

        // Apply Encryption
        if (config->encrypted) {
            uint8_t iv[AES_IV_SIZE];
            // TODO (MAJOR): Replace with secure random IV generation (e.g., using mbedtls CTR_DRBG or esp_random)
            // esp_fill_random(iv, sizeof(iv)); // Example using ESP-IDF API
             for(int i=0; i<AES_IV_SIZE; ++i) iv[i] = (uint8_t)dis(gen); // Using less secure C++ random as placeholder

            if (sizeof(iv) > sizeof(payload.encryption_iv.bytes)) {
                 LOG_E("Generated IV size %d too large for protobuf field size %d.", sizeof(iv), sizeof(payload.encryption_iv.bytes));
                 return false; 
            }
            memcpy(payload.encryption_iv.bytes, iv, sizeof(iv));
            payload.encryption_iv.size = sizeof(iv);

            bool encrypt_ok = applyPluginEncryption(data_chunk_vec, config->encryptionKey, true, iv); 
            if (!encrypt_ok) {
                 LOG_E("Encryption failed for non-fragmented packet TC %u", trafficClassId);
                 return false; 
            }
        }
        
        // Store the (potentially encrypted) data chunk
        if (data_chunk_vec.size() > sizeof(payload.original_payload_chunk.bytes)) {
             LOG_E("Payload (size %d) too large for static buffer (size %d) in AkitaPacketPayload for non-fragmented packet.",
                data_chunk_vec.size(), sizeof(payload.original_payload_chunk.bytes));
             return false; 
        }
        memcpy(payload.original_payload_chunk.bytes, data_chunk_vec.data(), data_chunk_vec.size());
        payload.original_payload_chunk.size = data_chunk_vec.size();
        
        // Track single reliable packets
        if (config->reliable && destinationNodeNum != BROADCAST_ADDR) {
             // Check outgoing session limit *before* adding
             if (outgoingFragments.size() >= MAX_OUTGOING_SESSIONS) {
                 LOG_E("Max outgoing fragment sessions (%d) reached. Cannot track single reliable packet for TC %u.",
                      MAX_OUTGOING_SESSIONS, trafficClassId);
                 return false; 
             }
            uint32_t pseudoFragId = generateFragmentId(); 
            payload.fragment_id = pseudoFragId; 
            payload.fragment_index = 0;
            payload.fragment_count = 1;

            OutgoingFragmentedPacket pseudoPkt;
            pseudoPkt.fragmentId = pseudoFragId;
            pseudoPkt.totalFragments = 1;
            pseudoPkt.destinationNodeNum = destinationNodeNum;
            pseudoPkt.fragments.push_back(envelope); // Store the prepared envelope
            pseudoPkt.ackedFragmentStatus[0] = false;
            pseudoPkt.lastSentTime = std::chrono::steady_clock::time_point::min(); // Indicate not sent yet
            pseudoPkt.ackedFragmentsCount = 0;
            pseudoPkt.retryCount = 0;
            outgoingFragments[pseudoFragId] = pseudoPkt;
        }

        transmitQueues[trafficClassId].push(envelope);
        LOG_D("Queued non-fragmented packet for TC %u to 0x%x (Reliable: %d, Enc: %d, FEC: %d bytes)", 
            trafficClassId, destinationNodeNum, config->reliable, config->encrypted, payload.fec_data.size);
    }
    return true;
}

/**
 * @brief Internal handler to fragment large data packets.
 * Creates fragment payloads, applies FEC/Encryption, and queues them.
 * @param data Pointer to the original data buffer.
 * @param size Size of the original data.
 * @param trafficClassId The ID of the traffic class to use.
 * @param destinationNodeNum The destination node ID.
 */
void AkitaTrafficClassPlugin::handleFragmentation(const uint8_t *data, size_t size, uint32_t trafficClassId, uint32_t destinationNodeNum) {
    const TrafficClassConfig* config = getTrafficClassConfig(trafficClassId);
    if (!config) {
        LOG_E("Fragment: Unknown TC %u", trafficClassId);
        return;
    }
    
    int protobufOverheadEstimate = 30 + (config->encrypted ? AES_IV_SIZE : 0); 
    uint8_t actual_fec_bytes_for_this_tc = std::min(config->fec_num_parity_bytes, (uint8_t)FEC_MAX_PARITY_BYTES);
    int actualMaxDataChunkSize = config->maxFragmentSize - protobufOverheadEstimate - actual_fec_bytes_for_this_tc;

     if (actualMaxDataChunkSize <= 0) { 
        LOG_E("MaxFragmentSize %d for TC %u is too small for fragmentation (becomes %d for data chunk) after overhead and FEC.", 
            config->maxFragmentSize, trafficClassId, actualMaxDataChunkSize);
        return;
    }

    uint32_t fragId = generateFragmentId();
    int numFragments = (size + actualMaxDataChunkSize - 1) / actualMaxDataChunkSize;
    if (numFragments <= 0) { 
        LOG_E("Calculated zero fragments needed for size %d, chunk size %d. Aborting fragmentation.", size, actualMaxDataChunkSize);
        return;
    }

    LOG_D("Fragmenting packet ID %u for TC %u into %d fragments (data chunk size ~%d). Dest 0x%x", 
        fragId, trafficClassId, numFragments, actualMaxDataChunkSize, destinationNodeNum);

    OutgoingFragmentedPacket outgoingPkt;
    outgoingPkt.fragmentId = fragId;
    outgoingPkt.totalFragments = numFragments;
    outgoingPkt.destinationNodeNum = destinationNodeNum;
    outgoingPkt.ackedFragmentsCount = 0; 
    outgoingPkt.retryCount = 0; 
    outgoingPkt.lastSentTime = std::chrono::steady_clock::time_point::min(); // Indicate not sent yet

    for (int i = 0; i < numFragments; ++i) {
        meshtastic_AkitaPluginEnvelope envelope = meshtastic_AkitaPluginEnvelope_init_default;
        envelope.which_payload_variant = meshtastic_AkitaPluginEnvelope_data_payload_tag;
        meshtastic_AkitaPacketPayload& payload = envelope.payload_variant.data_payload;

        payload = meshtastic_AkitaPacketPayload_init_default;
        payload.traffic_class_id = trafficClassId;
        payload.is_fragment = true;
        payload.fragment_id = fragId;
        payload.fragment_index = i;
        payload.fragment_count = numFragments;
        payload.original_message_size = size;
        payload.ack_requested = config->reliable; 

        size_t offset = i * actualMaxDataChunkSize;
        size_t chunkSize = std::min((size_t)actualMaxDataChunkSize, size - offset);
        
        std::vector<uint8_t> data_chunk_vec(data + offset, data + offset + chunkSize); // Plaintext chunk
        std::vector<uint8_t> fec_data_vec;

        // Apply FEC before encryption
        if (actual_fec_bytes_for_this_tc > 0) {
            fec_data_vec = applyFEC(data_chunk_vec, actual_fec_bytes_for_this_tc);
             if (fec_data_vec.size() > sizeof(payload.fec_data.bytes)) {
                LOG_E("Generated FEC data (size %d) for fragment %d too large for static buffer (size %d).",
                    fec_data_vec.size(), i, sizeof(payload.fec_data.bytes));
                continue; 
            }
            memcpy(payload.fec_data.bytes, fec_data_vec.data(), fec_data_vec.size());
            payload.fec_data.size = fec_data_vec.size();
        }

        // Apply Encryption
        if (config->encrypted) {
             uint8_t iv[AES_IV_SIZE];
             // TODO (MAJOR): Replace with secure random IV generation
             // esp_fill_random(iv, sizeof(iv)); // Example using ESP-IDF API
             for(int k=0; k<AES_IV_SIZE; ++k) iv[k] = (uint8_t)dis(gen); // Placeholder random IV
            
             if (sizeof(iv) > sizeof(payload.encryption_iv.bytes)) {
                 LOG_E("Generated IV size %d too large for protobuf field size %d.", sizeof(iv), sizeof(payload.encryption_iv.bytes));
                 continue; 
             }
             memcpy(payload.encryption_iv.bytes, iv, sizeof(iv));
             payload.encryption_iv.size = sizeof(iv);

            bool encrypt_ok = applyPluginEncryption(data_chunk_vec, config->encryptionKey, true, iv); 
            if (!encrypt_ok) {
                 LOG_E("Encryption failed for fragment %d of ID %u", i, fragId);
                 continue; // Skip this fragment if encryption failed
            }
        }

        // Store the (potentially encrypted) data chunk
        if (data_chunk_vec.size() > sizeof(payload.original_payload_chunk.bytes)) {
             LOG_E("Fragment data chunk (size %d) for index %d too large for static buffer (size %d).",
                data_chunk_vec.size(), i, sizeof(payload.original_payload_chunk.bytes));
             continue; 
        }
        memcpy(payload.original_payload_chunk.bytes, data_chunk_vec.data(), data_chunk_vec.size());
        payload.original_payload_chunk.size = data_chunk_vec.size();
        
        outgoingPkt.fragments.push_back(envelope);
        if(config->reliable) {
            outgoingPkt.ackedFragmentStatus[i] = false; 
        }
    }

    if (!outgoingPkt.fragments.empty()) {
        // Check limit *before* inserting
        if (outgoingFragments.size() >= MAX_OUTGOING_SESSIONS) {
             LOG_E("Max outgoing fragment sessions (%d) reached. Cannot track new fragment ID %u.",
                  MAX_OUTGOING_SESSIONS, fragId);
             return; // Don't queue if we can't track it
        }
        outgoingFragments[fragId] = outgoingPkt; 
        for(const auto& frag_env : outgoingPkt.fragments) { 
            meshtastic_AkitaPluginEnvelope env_copy = frag_env; 
            transmitQueues[trafficClassId].push(env_copy);
        }
        // lastSentTime will be updated when first fragment is actually sent
        LOG_D("Queued %d fragments for ID %u, TC %u. Reliable: %d, Enc: %d, FEC per frag: %d bytes", 
            numFragments, fragId, trafficClassId, config->reliable, config->encrypted, actual_fec_bytes_for_this_tc);
    }
}


/**
 * @brief Sends a prepared AkitaPluginEnvelope over the mesh.
 * Handles nanopb encoding and calls the MeshInterface send function.
 * @param envelope The envelope to send.
 * @param destinationNodeNum Destination node ID.
 * @param reliable Whether to request an ACK from the transport layer.
 */
void AkitaTrafficClassPlugin::sendRawPluginPacket(meshtastic_AkitaPluginEnvelope &envelope, uint32_t destinationNodeNum, bool reliable) {
    uint8_t buffer[meshtastic_AkitaPluginEnvelope_size]; // Max possible size from nanopb options
    pb_ostream_t ostream = pb_ostream_from_buffer(buffer, sizeof(buffer));

    if (!pb_encode(&ostream, meshtastic_AkitaPluginEnvelope_fields, &envelope)) {
        LOG_E("Failed to encode AkitaPluginEnvelope: %s", PB_GET_ERROR(&ostream));
        return; 
    }
    if (ostream.bytes_written == 0) {
        LOG_W("Encoded AkitaPluginEnvelope resulted in 0 bytes. Not sending.");
        return; 
    }
    if (ostream.bytes_written > MAX_PAYLOAD_LEN) { // Check against actual LoRa payload limit
         LOG_E("Encoded AkitaPluginEnvelope (%d bytes) exceeds max LoRa payload size (%d). Cannot send.", 
               ostream.bytes_written, MAX_PAYLOAD_LEN);
         return;
    }


    uint8_t hopLimit = _meshInterface.getHopLimit(); 
    uint8_t channelIndex = 0; 
    // channelIndex = _meshInterface.getPrimaryChannelIndex(); // Example hypothetical API

    LOG_D("Sending Akita envelope (%d bytes) to 0x%x, port %d, reliable (wantAck): %d, hopLimit: %d",
        ostream.bytes_written, destinationNodeNum, PortNum_AKITA_TRAFFIC_CLASS_APP, reliable, hopLimit);

    // Use MeshInterface to send the packet
    bool sendQueued = _meshInterface.sendData(destinationNodeNum, PortNum_AKITA_TRAFFIC_CLASS_APP, 
                            buffer, ostream.bytes_written, 
                            reliable, hopLimit, channelIndex, PacketFlag::NONE); 
    
    if (!sendQueued) {
        LOG_E("MeshInterface::sendData failed to queue packet for TC %u, Dest 0x%x", 
            (envelope.which_payload_variant == meshtastic_AkitaPluginEnvelope_data_payload_tag ? envelope.payload_variant.data_payload.traffic_class_id : 999), 
            destinationNodeNum);
        // TODO: If reliable, should this trigger a failure/retry mechanism immediately?
    } else {
        // Update QoS stats for sent packets/fragments
        if (envelope.which_payload_variant == meshtastic_AkitaPluginEnvelope_data_payload_tag) {
            uint32_t tcId = envelope.payload_variant.data_payload.traffic_class_id;
            if (qosStats.count(tcId)) {
                if (envelope.payload_variant.data_payload.is_fragment || envelope.payload_variant.data_payload.fragment_count == 1) {
                    qosStats[tcId].fragmentsSent++;
                } else {
                    qosStats[tcId].packetsSent++;
                }
            }
        }
    }
}


/**
 * @brief Main periodic loop function called by the Meshtastic core.
 * Handles queue servicing, timeouts, and background tasks.
 */
void AkitaTrafficClassPlugin::loop() {
    // Skip processing if radio is in a deep sleep state
    if (currentRadioState == RadioState_SLEEPING) {
        return;
    }

    serviceTransmitQueues();
    checkReassemblyTimeouts();
    checkRetransmissionTimeouts(); 

    // Run background tasks less often if radio is in light sleep
    bool allowBackgroundTask = (currentRadioState != RadioState_LIGHT_SLEEP);
    static std::chrono::steady_clock::time_point lastAdaptationTime = std::chrono::steady_clock::now();
    
    if (allowBackgroundTask && 
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - lastAdaptationTime).count() > 10) { 
        dynamicTrafficClassAdaptation();
        monitorQoS(); 
        lastAdaptationTime = std::chrono::steady_clock::now();
    }
}

/**
 * @brief Services the transmit queues based on priority and potentially congestion control.
 * Dequeues and sends packets according to a weighted scheme.
 */
void AkitaTrafficClassPlugin::serviceTransmitQueues() {
    if (trafficClasses.empty()) return;

    std::vector<uint32_t> sorted_tcs;
    for(auto const& [tc_id, config_val] : trafficClasses) { 
        sorted_tcs.push_back(tc_id);
    }
    // Sort TCs by priority (descending)
    std::sort(sorted_tcs.begin(), sorted_tcs.end(), [&](uint32_t a, uint32_t b){
        auto it_a = trafficClasses.find(a);
        auto it_b = trafficClasses.find(b);
        if (it_a != trafficClasses.end() && it_b != trafficClasses.end()) {
            return it_a->second.priority > it_b->second.priority;
        }
        return false; 
    });

    int total_packets_sent_this_cycle = 0;
    const int MAX_PACKETS_PER_LOOP = 5; // Limit total sends per loop() call

    for (uint32_t tc_id : sorted_tcs) {
        if (transmitQueues.count(tc_id) && !transmitQueues[tc_id].empty()) {
            const TrafficClassConfig* currentTcConfig = getTrafficClassConfig(tc_id);
            if (!currentTcConfig) continue; 

            // Determine weighted number of packets allowed for this TC
            int weight = 1; 
            if (currentTcConfig->priority >= 7) weight = 4;
            else if (currentTcConfig->priority >= 5) weight = 2;
            
            int packets_allowed = weight;

            // --- Conceptual Congestion Control Check ---
            // TODO: Implement proper in-flight packet tracking for reliable TCs.
            // size_t in_flight = 0; 
            // if (currentTcConfig->reliable) {
            //    // in_flight = calculateInFlightPackets(tc_id); // Needs implementation
            //    packets_allowed = std::min(packets_allowed, currentTcConfig->congestionWindow - (int)in_flight);
            //    if (packets_allowed < 0) packets_allowed = 0;
            //    // LOG_D("TC %u: CW=%d, InFlight=%d, Allowed=%d", tc_id, currentTcConfig->congestionWindow, in_flight, packets_allowed);
            // }
            // --- End Conceptual Congestion Control Check ---

            for (int i = 0; i < packets_allowed && total_packets_sent_this_cycle < MAX_PACKETS_PER_LOOP; ++i) {
                if (transmitQueues[tc_id].empty()) break; 

                meshtastic_AkitaPluginEnvelope envelope = transmitQueues[tc_id].front();
                
                uint32_t dest = BROADCAST_ADDR; 
                bool reliable = currentTcConfig->reliable;
                uint32_t fragment_id_for_lookup = 0;

                // Determine destination and reliability based on envelope type
                if (envelope.which_payload_variant == meshtastic_AkitaPluginEnvelope_data_payload_tag) {
                     const auto& data_payload = envelope.payload_variant.data_payload;
                     // Reliability is already set from currentTcConfig
                     
                     // If it's a fragment or a tracked single reliable packet, find its destination
                     if(data_payload.is_fragment || (reliable && data_payload.fragment_count == 1)) { 
                        fragment_id_for_lookup = data_payload.fragment_id;
                        auto it_out = outgoingFragments.find(fragment_id_for_lookup);
                        if(it_out != outgoingFragments.end()) {
                            dest = it_out->second.destinationNodeNum;
                        } else {
                            // This fragment is queued but no longer tracked (e.g., timed out, ACKed). Should not happen if logic is correct.
                            LOG_W("Servicing queue: Tracked packet ID %u for TC %u not found in outgoingFragments map. Dropping from queue.", 
                                fragment_id_for_lookup, tc_id);
                            transmitQueues[tc_id].pop(); // Remove the stale item
                            continue; // Skip to next item in queue or next TC
                        }
                     } else {
                         // Non-fragmented, non-tracked packet. Destination must be implicitly BROADCAST or handled elsewhere.
                         // This highlights the need for a queue item struct that stores destination.
                     }
                } else if (envelope.which_payload_variant == meshtastic_AkitaPluginEnvelope_control_payload_tag) {
                    reliable = false; // Control messages are not sent reliably
                    // Destination for control messages needs robust handling if queued.
                    // Currently, ACKs are sent directly via sendAckForFragment -> sendRawPluginPacket.
                }
                
                LOG_D("Servicing queue for TC %u (Prio %d, Weight %d), packet %d/%d this cycle. Dest 0x%x.", 
                    tc_id, currentTcConfig->priority, weight, i+1, packets_allowed, dest);
                
                transmitQueues[tc_id].pop(); // Pop before sending attempt
                sendRawPluginPacket(envelope, dest, reliable); // Handles QoS increment on successful queueing by MeshInterface
                total_packets_sent_this_cycle++;
                
                // Update lastSentTime for reliable fragments immediately after sending attempt
                if (reliable && envelope.which_payload_variant == meshtastic_AkitaPluginEnvelope_data_payload_tag) {
                    const auto& data_p = envelope.payload_variant.data_payload;
                    if (data_p.is_fragment || data_p.fragment_count == 1) { 
                        if (fragment_id_for_lookup != 0) { 
                            auto it_out_update = outgoingFragments.find(fragment_id_for_lookup);
                            if (it_out_update != outgoingFragments.end()) {
                                // Update only if this is the first time sending or a retransmission
                                if (it_out_update->second.lastSentTime == std::chrono::steady_clock::time_point::min() || it_out_update->second.retryCount > 0) {
                                     it_out_update->second.lastSentTime = std::chrono::steady_clock::now();
                                }
                            }
                        }
                    }
                }
            } // end loop for packets_allowed
        } // end if queue not empty
        if (total_packets_sent_this_cycle >= MAX_PACKETS_PER_LOOP) break; // Stop processing lower priority TCs if loop limit hit
    } // end loop for sorted_tcs
}


/**
 * @brief Checks for timed-out incoming fragment reassembly sessions and cleans them up.
 */
void AkitaTrafficClassPlugin::checkReassemblyTimeouts() {
    auto now = std::chrono::steady_clock::now();
    for (auto it = incomingFragments.begin(); it != incomingFragments.end(); /* manual increment */) {
        // Check if time since last fragment received exceeds timeout
        if (std::chrono::duration_cast<std::chrono::milliseconds>(now - it->second.lastFragmentReceivedTime).count() > REASSEMBLY_TIMEOUT_MS) {
            LOG_W("Reassembly timeout for fragment ID %u from 0x%x. Discarding %d raw fragments.",
                  it->second.fragmentId, it->second.sourceNodeNum, it->second.receivedRawFragments.size());
            it = incomingFragments.erase(it); // Erase and get next iterator
        } else {
            ++it; // Move to next item if not timed out
        }
    }
}

/**
 * @brief Checks for timed-out outgoing reliable fragments and handles retransmissions or failure.
 */
void AkitaTrafficClassPlugin::checkRetransmissionTimeouts() {
    auto now = std::chrono::steady_clock::now();
    for (auto it = outgoingFragments.begin(); it != outgoingFragments.end(); /* manual increment */ ) {
        OutgoingFragmentedPacket& outgoingPkt = it->second;
        
        // Skip if lastSentTime is min(), means it hasn't been sent even once yet
        if (outgoingPkt.lastSentTime == std::chrono::steady_clock::time_point::min()) {
            ++it;
            continue;
        }

        uint32_t tc_id_of_pkt = 0;
        if (!outgoingPkt.fragments.empty()){ 
            tc_id_of_pkt = outgoingPkt.fragments[0].payload_variant.data_payload.traffic_class_id;
        } else {
             LOG_E("OutgoingFragmentedPacket for ID %u has no fragments. Removing.", outgoingPkt.fragmentId);
             it = outgoingFragments.erase(it); 
             continue; 
        }

        const TrafficClassConfig* current_config = getTrafficClassConfig(tc_id_of_pkt); 

        // Check only reliable packets that are not fully acknowledged
        if (current_config && current_config->reliable && outgoingPkt.ackedFragmentsCount < outgoingPkt.totalFragments) {
            // Check if timeout has occurred
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - outgoingPkt.lastSentTime).count() > RETRANSMISSION_TIMEOUT_MS) {
                // Adjust Congestion Window on timeout
                adjustCongestionWindow(tc_id_of_pkt, false); 

                // Check if max retries have been reached
                if (outgoingPkt.retryCount < current_config->retries) {
                    outgoingPkt.retryCount++;
                    int reQueuedCount = 0;
                    LOG_I("Retransmission timeout for reliable fragment ID %u (to 0x%x, TC %u, attempt %d/%d). Re-queuing non-ACKed fragments.",
                          outgoingPkt.fragmentId, outgoingPkt.destinationNodeNum, tc_id_of_pkt, outgoingPkt.retryCount, current_config->retries);
                    
                    bool needs_resend = false;
                    // Iterate through all fragments defined for this packet
                    for (uint32_t i = 0; i < (uint32_t)outgoingPkt.totalFragments; ++i) { 
                        // Check if fragment 'i' has been acknowledged
                        if (outgoingPkt.ackedFragmentStatus.count(i) && !outgoingPkt.ackedFragmentStatus.at(i)) { // Use .at() for safety after count check
                            // Ensure the fragment envelope exists (bounds check)
                            if (i < outgoingPkt.fragments.size()) { 
                                meshtastic_AkitaPluginEnvelope env_copy = outgoingPkt.fragments[i]; // Get the specific fragment envelope
                                transmitQueues[tc_id_of_pkt].push(env_copy); // Re-queue it
                                reQueuedCount++;
                                needs_resend = true;
                            } else {
                                LOG_E("Fragment index %u out of bounds for outgoing packet ID %u during retransmission.", i, outgoingPkt.fragmentId);
                            }
                        }
                    }
                    
                    if (needs_resend) {
                        outgoingPkt.lastSentTime = now; // Reset timer only if something was re-queued
                        LOG_D("Re-queued %d fragments for ID %u.", reQueuedCount, outgoingPkt.fragmentId);
                    } else { 
                        // This case should ideally not happen if ackedFragmentsCount < totalFragments,
                        // but could occur due to race conditions or logic errors.
                        LOG_W("All fragments for ID %u were marked ACKed while preparing retransmission. No re-queue needed.", outgoingPkt.fragmentId);
                    }
                    ++it; // Move to next packet in the map
                } else { // Max retries reached
                    LOG_E("Max retries (%d) reached for fragment ID %u (to 0x%x). Giving up on %d unacked fragments.", 
                        current_config->retries, outgoingPkt.fragmentId, outgoingPkt.destinationNodeNum, 
                        outgoingPkt.totalFragments - outgoingPkt.ackedFragmentsCount);
                    // Update QoS Stats for timeout
                    if (qosStats.count(tc_id_of_pkt)) {
                         qosStats[tc_id_of_pkt].timeouts++;
                    }
                    it = outgoingFragments.erase(it); // Erase and get next iterator from map
                    // No ++it here because erase returns the next valid iterator
                }
            } else { // Not timed out yet
                ++it;
            }
        } else if (current_config && current_config->reliable && outgoingPkt.ackedFragmentsCount == outgoingPkt.totalFragments) {
            // This packet is fully acknowledged, clean it up if it wasn't already
            LOG_I("All fragments for reliable ID %u (to 0x%x) confirmed ACKed during timeout check. Cleaning up.", outgoingPkt.fragmentId, outgoingPkt.destinationNodeNum);
            it = outgoingFragments.erase(it);
        } else { 
             // Not reliable, or some other state. Increment iterator.
            ++it;
        }
    }
}


/**
 * @brief Configures or updates a specific traffic class. Persists to NVS.
 * @param trafficClassId ID of the class (0-255).
 * @param priority Priority level (higher value = higher priority).
 * @param reliable Enable ACK/retransmission.
 * @param encrypted Enable encryption (requires crypto library).
 * @param maxFragmentSize Max bytes per fragment payload.
 * @param retries Max retransmission attempts for reliable.
 * @param fec_num_parity_bytes Number of FEC bytes (0=disabled).
 * @param congestionWindow Initial congestion window size.
 * @param encryptionKey Key byte for encryption.
 * @return True on success, false on failure (e.g., invalid args, NVS full).
 */
bool AkitaTrafficClassPlugin::configureTrafficClass(uint32_t trafficClassId, int priority, bool reliable, 
                                                    bool encrypted, int maxFragmentSize, int retries, 
                                                    uint8_t fec_num_parity_bytes, int congestionWindow, uint8_t encryptionKey) {
    // Validate inputs
    if (priority <= 0 || maxFragmentSize < MIN_MTU_FUDGE || retries < 0 || congestionWindow <= 0) {
         LOG_E("Invalid parameter value provided for configureTrafficClass TC %u.", trafficClassId);
         return false; // Return bool for command handler
    }

    bool is_new = (trafficClasses.find(trafficClassId) == trafficClasses.end());
    if (is_new && trafficClasses.size() >= MAX_NVS_TRAFFIC_CLASSES) {
        LOG_E("Cannot configure new traffic class %u. Max NVS limit %d reached.", trafficClassId, MAX_NVS_TRAFFIC_CLASSES);
        return false; // Return bool for command handler
    }

    TrafficClassConfig config_obj; 
    config_obj.trafficClassId = trafficClassId; 
    config_obj.priority = priority;
    config_obj.reliable = reliable;
    config_obj.encrypted = encrypted;
    config_obj.maxFragmentSize = maxFragmentSize;
    config_obj.retries = retries;
    config_obj.fec_num_parity_bytes = std::min(fec_num_parity_bytes, (uint8_t)FEC_MAX_PARITY_BYTES); 
    config_obj.congestionWindow = congestionWindow;
    config_obj.encryptionKey = encryptionKey;
    
    trafficClasses[trafficClassId] = config_obj;
    // Update default config only if it's intended to be persistent across potential dynamic changes
    defaultTrafficClassConfigs[trafficClassId] = config_obj; 
    // Initialize QoS stats if it's a new class
    if (is_new) {
        qosStats[trafficClassId] = {}; 
    }

    LOG_I("Configured Traffic Class ID %u: Prio=%d, Rel=%d, Enc=%d, FragSz=%d, Retry=%d, FECParity=%d, CW=%d, Key=0x%x",
        trafficClassId, priority, reliable, encrypted, maxFragmentSize, retries, config_obj.fec_num_parity_bytes, congestionWindow, encryptionKey);
    
    saveTrafficClassToNVS(config_obj); // Persist the configuration
    return true; // Indicate success
}

/**
 * @brief Gets the configuration for a specific traffic class.
 * @param trafficClassId The ID of the class.
 * @return Pointer to the TrafficClassConfig, or nullptr if not found.
 */
const TrafficClassConfig* AkitaTrafficClassPlugin::getTrafficClassConfig(uint32_t trafficClassId) {
    auto it = trafficClasses.find(trafficClassId);
    if (it != trafficClasses.end()) {
        return &it->second;
    }
    return nullptr; 
}

/**
 * @brief Deletes a traffic class configuration from memory and NVS.
 * @param trafficClassId The ID of the class to delete.
 * @return True if the class was found and deleted, false otherwise.
 */
bool AkitaTrafficClassPlugin::deleteTrafficClass(uint32_t trafficClassId) {
    bool deleted = false;
    if (trafficClasses.erase(trafficClassId) > 0) {
        LOG_I("Deleted traffic class %u from memory.", trafficClassId);
        deleted = true;
    }
    defaultTrafficClassConfigs.erase(trafficClassId);
    qosStats.erase(trafficClassId); 
    
    if (deleted) { 
        deleteTrafficClassFromNVS(trafficClassId);
    } else {
        LOG_W("Attempted to delete non-existent traffic class %u.", trafficClassId);
    }
    return deleted;
}


// --- Meshtastic API interaction ---
/**
 * @brief Gets the current device battery level percentage.
 * @return Battery level (0-100), or -1 if unavailable/error.
 */
int AkitaTrafficClassPlugin::getDeviceBatteryLevel() {
    // TODO (API): Verify g_powerFSM and its methods are correct for your firmware version.
    if (g_powerFSM) { 
        if (g_powerFSM->getHasBattery()) {
             return g_powerFSM->getBatteryLevel(); 
        } else {
            return -1; // No battery detected
        }
    }
    LOG_W("Could not get battery level, g_powerFSM not available or Meshtastic API changed.");
    return -1; // Indicate error
}

/**
 * @brief Gets the last received Signal-to-Noise Ratio (SNR) for a specific node.
 * @param nodeId The node ID to query.
 * @return SNR value (float), or -99.0f if unavailable/error.
 */
float AkitaTrafficClassPlugin::getLinkSnrToNode(uint32_t nodeId) {
    // TODO (API): Verify getNodeDB() and NodeInfo structure/methods are correct.
    if (!_meshInterface.getNodeDB()) {
        LOG_W("NodeDB not available via MeshInterface.");
        return -99.0f; 
    }
    NodeInfo *node = _meshInterface.getNodeDB()->getNode(nodeId); 
    if (node && node->has_snr()) { 
        return node->snr(); 
    }
    // Node not found or doesn't have SNR data
    return -99.0f; 
}

/**
 * @brief Gets the current estimated channel utilization.
 * @return Channel utilization (0.0 to 1.0), or -1.0f if unavailable/error.
 */
float AkitaTrafficClassPlugin::getChannelUtilization() {
    // TODO (API): Verify RadioInterface::getInstance() and getChannelUtilization() are correct.
    RadioInterface *radio = RadioInterface::getInstance();
    if (radio) {
        return radio->getChannelUtilization(); 
    }
    LOG_W("Could not get radio interface for channel utilization.");
    return -1.0f; // Indicate error
}


/**
 * @brief Gets the current number of packets waiting in the queue for a specific traffic class.
 * @param trafficClassId The ID of the traffic class.
 * @return Number of packets in the queue.
 */
size_t AkitaTrafficClassPlugin::getQueueLength(uint32_t trafficClassId) {
    // Use .count() to check existence before accessing with .at()
    if (transmitQueues.count(trafficClassId)) {
        return transmitQueues.at(trafficClassId).size(); // Use .at() for safety
    }
    return 0;
}

/**
 * @brief Generates a pseudo-random fragment ID.
 * @return A 32-bit fragment ID.
 */
uint32_t AkitaTrafficClassPlugin::generateFragmentId() {
    // Using C++ <random> is generally better than rand()
    std::uniform_int_distribution<uint32_t> distrib(1, 0xFFFFFFFE); // Avoid 0 and all Fs
    return distrib(gen);
}


// --- Dynamic Adaptation Logic ---
/**
 * @brief Periodically called to adjust traffic class parameters based on conditions.
 * Currently adjusts priority and fragment size based on battery and channel utilization (temporary changes).
 */
void AkitaTrafficClassPlugin::dynamicTrafficClassAdaptation() {
    // LOG_D("Running dynamic traffic class adaptation...");
    int battery = getDeviceBatteryLevel(); 
    
    float channelUtil = getChannelUtilization();
    if (channelUtil < 0) channelUtil = 0.5f; // Assume moderate if error

    for (auto& pair_tc : trafficClasses) { 
        TrafficClassConfig& current_config = pair_tc.second; 
        uint32_t tcId = pair_tc.first;

        // Restore to default first if conditions are good
        bool restored = false;
        if (defaultTrafficClassConfigs.count(tcId)) {
            const TrafficClassConfig& default_cfg = defaultTrafficClassConfigs.at(tcId); 
            if ((battery == -1 || battery > 25) && channelUtil < 0.6f) { // Good conditions
                if (current_config.priority != default_cfg.priority) {
                    // LOG_I("TC %u: Restoring priority to default %d", tcId, default_cfg.priority);
                    current_config.priority = default_cfg.priority; restored = true;
                }
                if (current_config.maxFragmentSize != default_cfg.maxFragmentSize) {
                     // LOG_I("TC %u: Restoring maxFragmentSize to default %d", tcId, default_cfg.maxFragmentSize);
                     current_config.maxFragmentSize = default_cfg.maxFragmentSize; restored = true;
                }
                 if (current_config.congestionWindow != default_cfg.congestionWindow) {
                     // LOG_I("TC %u: Restoring congestionWindow to default %d", tcId, default_cfg.congestionWindow);
                     current_config.congestionWindow = default_cfg.congestionWindow; restored = true;
                }
            }
        }

        // Apply temporary reductions based on current adverse conditions
        // These override the restoration if conditions are bad.
        if (battery != -1 && battery < 15 && defaultTrafficClassConfigs.count(tcId)) {
            const TrafficClassConfig& default_cfg = defaultTrafficClassConfigs.at(tcId);
            int new_prio = std::max(1, default_cfg.priority - 2); // Drastic reduction for low battery
            if (current_config.priority != new_prio && current_config.priority > 1) { 
               // LOG_I("TC %u: Priority temp adjusted to %d due to very low battery (%d%%)", tcId, new_prio, battery);
               current_config.priority = new_prio; // Apply temporary change (not saved to NVS)
            }
        } 
        else if (channelUtil > 0.75f && current_config.priority < 5 && defaultTrafficClassConfigs.count(tcId)) {
            const TrafficClassConfig& default_cfg = defaultTrafficClassConfigs.at(tcId);
            int new_frag_sz = std::max(80, default_cfg.maxFragmentSize - 40); // Reduce frag size on congestion
            if (current_config.maxFragmentSize != new_frag_sz) {
               // LOG_I("TC %u: MaxFragSize temp adjusted to %d due to high channel util (%.2f)", tcId, new_frag_sz, channelUtil);
               current_config.maxFragmentSize = new_frag_sz; // Apply temporary change (not saved to NVS)
            }
        }
    }
}

/**
 * @brief Periodically logs QoS statistics for each traffic class.
 */
void AkitaTrafficClassPlugin::monitorQoS() {
    auto now = std::chrono::steady_clock::now();
    // Reset stats periodically (e.g., every 60 seconds)
    if (std::chrono::duration_cast<std::chrono::seconds>(now - lastQoSResetTime).count() >= 60) {
        LOG_I("QoS Stats (last 60s):");
        for (auto const& [tcId, stats] : qosStats) {
            const TrafficClassConfig* cfg = getTrafficClassConfig(tcId);
            if (!cfg) continue;

            float successRate = -1.0f; // Indicate N/A or error initially
            if (cfg->reliable) {
                 uint32_t relevantSent = stats.fragmentsSent; 
                 if (relevantSent > 0) {
                    successRate = (float)stats.acksReceived / relevantSent;
                 } else {
                     successRate = 1.0f; // 100% success if nothing needed sending/acking
                 }
            }

            float fecCorrectionRate = -1.0f; // Indicate N/A
            uint32_t fecTotalChecked = stats.fecCorrected + stats.fecFailures;
            if (cfg->fec_num_parity_bytes > 0) {
                 if (fecTotalChecked > 0) {
                    fecCorrectionRate = (float)stats.fecCorrected / fecTotalChecked;
                 } else {
                     fecCorrectionRate = 1.0f; // 100% success if no errors/corrections needed
                 }
            }

            // Format output string carefully
            char qosBuffer[256];
            snprintf(qosBuffer, sizeof(qosBuffer), 
                "  TC %u: PktsSent=%u, FragsSent=%u, ACKsRecv=%u, Timeouts=%u, FECCorrect=%u, FECFail=%u",
                tcId, stats.packetsSent, stats.fragmentsSent, stats.acksReceived, stats.timeouts,
                stats.fecCorrected, stats.fecFailures);
            
            char ratesBuffer[100];
            snprintf(ratesBuffer, sizeof(ratesBuffer), ", SuccessRate=%.1f%%, FECCorrRate=%.1f%%",
                 successRate >= 0.0f ? successRate * 100.0f : -1.0f, // Show -1.0 if N/A
                 fecCorrectionRate >= 0.0f ? fecCorrectionRate * 100.0f : -1.0f); // Show -1.0 if N/A
            
            // Ensure no buffer overflow when concatenating
            if (strlen(qosBuffer) + strlen(ratesBuffer) < sizeof(qosBuffer)) {
                 strcat(qosBuffer, ratesBuffer);
            }
            LOG_I("%s", qosBuffer);
        }

        // Reset counters
        for (auto& pair : qosStats) {
            pair.second = {}; // Reset all counters to zero
        }
        lastQoSResetTime = now;
        LOG_I("QoS Stats reset.");
    }
}

/**
 * @brief Called when node information is updated. Adjusts routing metrics conceptually.
 * @param node The updated NodeInfo object.
 */
void AkitaTrafficClassPlugin::updateRoutingMetrics(const NodeInfo &node) {
    // Skip processing if radio is sleeping
    if (currentRadioState == RadioState_SLEEPING || currentRadioState == RadioState_LIGHT_SLEEP) {
        return;
    }

    uint32_t nodeId = node.node_num;
    if (nodeId == 0 || nodeId == BROADCAST_ADDR || nodeId == _meshInterface.getMyNodeNum()) return; // Ignore self/invalid

    float currentSnr = getLinkSnrToNode(nodeId);
    if (currentSnr <= -99.0f) {
        return; // No SNR data
    }

    // Exponential Backoff for poor links
    const float POOR_LINK_SNR_THRESHOLD = 0.0f; 
    int backoff_level = routingBackoffCounts.count(nodeId) ? routingBackoffCounts.at(nodeId) : 0;

    if (currentSnr < POOR_LINK_SNR_THRESHOLD) {
        backoff_level = std::min(backoff_level + 1, 5); 
        routingBackoffCounts[nodeId] = backoff_level;
        // LOG_D("Node 0x%x SNR %.1f is poor, increasing backoff level to %d", nodeId, currentSnr, backoff_level);
    } else {
        if (backoff_level > 0) {
             // LOG_D("Node 0x%x SNR %.1f is good, resetting backoff level from %d", nodeId, currentSnr, backoff_level);
        }
        routingBackoffCounts[nodeId] = 0; 
        backoff_level = 0;
    }

    float adjustedQuality = currentSnr; 
    if (backoff_level > 0) {
        adjustedQuality -= (float)(1 << backoff_level); 
    }

    // Apply adjustments per traffic class
    for (const auto& pair_tc : trafficClasses) {
        uint32_t tcId = pair_tc.first;
        const TrafficClassConfig& config = pair_tc.second;
        float tcAdjustedQuality = adjustedQuality;

        if (config.priority >= 7) {
            if (currentSnr < 5.0f) tcAdjustedQuality -= 10.0f; 
            else if (currentSnr > 10.0f) tcAdjustedQuality += 2.0f; 
        } 
        else if (config.priority <= 3) {
             if (currentSnr < -2.0f) tcAdjustedQuality -= 2.0f; 
        }
        
        // TODO (MAJOR): Update the Meshtastic routing table with tcAdjustedQuality for this node and traffic class.
        // This requires a specific API from MeshInterface or RadioInterface. The API signature is unknown.
        // It might look something like one of these (PURELY HYPOTHETICAL):
        // bool updateSuccess = _meshInterface.updateRoutingMetric(nodeId, tcId, tcAdjustedQuality); 
        // if (!updateSuccess) { LOG_E("Failed to update routing metric via MeshInterface API."); }
        // LOG_W("Routing metric update for TC %u to node 0x%x not implemented (API unknown). Calculated Quality: %.1f", tcId, nodeId, tcAdjustedQuality);
    }
}

/**
 * @brief Adjusts the congestion window for a traffic class based on success/failure feedback.
 * @param trafficClassId The ID of the traffic class.
 * @param success True if the last transmission attempt was successful (e.g., ACK received), false otherwise (e.g., timeout).
 */
void AkitaTrafficClassPlugin::adjustCongestionWindow(uint32_t trafficClassId, bool success) {
    auto it = trafficClasses.find(trafficClassId);
    if (it != trafficClasses.end()) {
        TrafficClassConfig& current_tc_config_cw = it->second; 
        int old_cw = current_tc_config_cw.congestionWindow;
        if (success) {
            // AIMD: Additive Increase
            current_tc_config_cw.congestionWindow = std::min(current_tc_config_cw.congestionWindow + 1, 20); // Cap at 20
        } else {
            // AIMD: Multiplicative Decrease
            current_tc_config_cw.congestionWindow = std::max(current_tc_config_cw.congestionWindow / 2, 1); // Floor at 1
             LOG_I("Congestion detected for TC %u (Timeout/Loss). Reducing CW from %d to %d.", 
                trafficClassId, old_cw, current_tc_config_cw.congestionWindow);
        }
        if (old_cw != current_tc_config_cw.congestionWindow) {
             LOG_D("Adjusted congestion window for TC %u to %d (success: %d)", trafficClassId, current_tc_config_cw.congestionWindow, success);
            // saveTrafficClassToNVS(current_tc_config_cw); // Persist CW changes if desired
        }
    }
}

/**
 * @brief Dynamically adjusts the maximum fragment size for a traffic class based on link SNR.
 * @param trafficClassId The ID of the traffic class.
 * @param linkSnr The current SNR to the relevant node (or average SNR).
 */
void AkitaTrafficClassPlugin::dynamicFragmentSizeAdjustment(uint32_t trafficClassId, float linkSnr) {
    auto it = trafficClasses.find(trafficClassId);
    if (it != trafficClasses.end()) { 
        TrafficClassConfig& current_cfg_fs = it->second; 
        int old_frag_sz = current_cfg_fs.maxFragmentSize;

        int baseFragSize = 180; 
        if (defaultTrafficClassConfigs.count(trafficClassId)) {
            baseFragSize = defaultTrafficClassConfigs.at(trafficClassId).maxFragmentSize;
        }
        
        int protobufOverheadEstimate = 30 + (current_cfg_fs.encrypted ? AES_IV_SIZE : 0); 
        int fec_bytes = current_cfg_fs.fec_num_parity_bytes; 

        int min_practical_data_size = 20; 
        int min_frag_size_with_overhead = min_practical_data_size + protobufOverheadEstimate + fec_bytes;

        // Adjust based on SNR thresholds
        if (linkSnr > 7.0f) current_cfg_fs.maxFragmentSize = baseFragSize; // Good link -> Max size
        else if (linkSnr > 2.0f) current_cfg_fs.maxFragmentSize = std::max(min_frag_size_with_overhead, baseFragSize - 40); // Fair link -> Medium size
        else if (linkSnr > -5.0f) current_cfg_fs.maxFragmentSize = std::max(min_frag_size_with_overhead, baseFragSize - 80); // Poor link -> Smaller size
        else current_cfg_fs.maxFragmentSize = std::max(min_frag_size_with_overhead, baseFragSize - 100); // Very poor link -> Smallest practical size
        
        // Ensure it doesn't go below minimum practical size after adjustments
        current_cfg_fs.maxFragmentSize = std::max(min_frag_size_with_overhead, current_cfg_fs.maxFragmentSize);

        if (old_frag_sz != current_cfg_fs.maxFragmentSize) {
            LOG_I("TC %u: DynamicFragSize adjusted from %d to %d based on SNR %.1f", 
               trafficClassId, old_frag_sz, current_cfg_fs.maxFragmentSize, linkSnr);
            // saveTrafficClassToNVS(current_cfg_fs); // Persist changes if desired
        }
    }
}


// --- Config Persistence ---
/**
 * @brief Loads all traffic class configurations from NVS.
 */
void AkitaTrafficClassPlugin::loadPluginConfig() {
    LOG_I("Loading Akita Plugin configuration from NVS...");
    NVSStorage* nvs = NVSStorage::getInstance(); 
    if (!nvs) {
        LOG_E("Failed to get NVS instance.");
        return;
    }

    trafficClasses.clear();
    defaultTrafficClassConfigs.clear(); 
    qosStats.clear(); // Clear stats when loading config
    uint8_t classCount = 0;
    char countKeyStr[strlen(NVS_KEY_PREFIX) + strlen("count") + 1];
    strcpy(countKeyStr, NVS_KEY_PREFIX);
    strcat(countKeyStr, "count");


    if (nvs->get_u8(countKeyStr, classCount)) {
        LOG_D("Found %u traffic classes in NVS.", classCount);
        classCount = std::min(classCount, static_cast<uint8_t>(MAX_NVS_TRAFFIC_CLASSES)); 

        for (uint8_t i = 0; i < classCount; ++i) {
            char keyBase[32];
            snprintf(keyBase, sizeof(keyBase), "%s%u_", NVS_KEY_PREFIX, i); 
            
            TrafficClassConfig cfg_nvs; 
            char idKey[40]; snprintf(idKey, sizeof(idKey), "%sid", keyBase);
            char prioKey[40]; snprintf(prioKey, sizeof(prioKey), "%sprio", keyBase);
            char relKey[40]; snprintf(relKey, sizeof(relKey), "%srel", keyBase);
            char encKeyStatusKey[40]; snprintf(encKeyStatusKey, sizeof(encKeyStatusKey), "%sencst", keyBase); 
            char fragSzKey[40]; snprintf(fragSzKey, sizeof(fragSzKey), "%sfragsz", keyBase);
            char retryKey[40]; snprintf(retryKey, sizeof(retryKey), "%sretry", keyBase);
            char fecBytesKey[40]; snprintf(fecBytesKey, sizeof(fecBytesKey), "%sfecbytes", keyBase); 
            char cwKey[40]; snprintf(cwKey, sizeof(cwKey), "%scw", keyBase);
            char encKeyValKey[40]; snprintf(encKeyValKey, sizeof(encKeyValKey), "%senckval", keyBase);


            uint32_t tcId_u32 = 0;
            uint8_t prio_u8 = 0;
            bool reliable_b = false;
            bool encrypted_b = false;
            uint16_t maxFragSize_u16 = 0; 
            uint8_t retries_u8 = 0;
            uint8_t fecNumParityBytes_u8 = 0; 
            uint8_t congestionWindow_u8 = 0;
            uint8_t encryptionKeyValue_u8 = 0;

            // Load ID first, only proceed if it's valid
            if (nvs->get_u32(idKey, tcId_u32) && tcId_u32 != 0xFFFFFFFF) { 
                cfg_nvs.trafficClassId = tcId_u32; 
                // Use default values from struct definition if NVS read fails for a field
                if (!nvs->get_u8(prioKey, prio_u8)) prio_u8 = 3; cfg_nvs.priority = prio_u8;
                if (!nvs->get_bool(relKey, reliable_b)) reliable_b = false; cfg_nvs.reliable = reliable_b;
                if (!nvs->get_bool(encKeyStatusKey, encrypted_b)) encrypted_b = false; cfg_nvs.encrypted = encrypted_b;
                if (!nvs->get_u16(fragSzKey, maxFragSize_u16)) maxFragSize_u16 = 180; cfg_nvs.maxFragmentSize = maxFragSize_u16;
                if (!nvs->get_u8(retryKey, retries_u8)) retries_u8 = 3; cfg_nvs.retries = retries_u8;
                if (!nvs->get_u8(fecBytesKey, fecNumParityBytes_u8)) fecNumParityBytes_u8 = 0; cfg_nvs.fec_num_parity_bytes = fecNumParityBytes_u8; 
                if (!nvs->get_u8(cwKey, congestionWindow_u8)) congestionWindow_u8 = 5; cfg_nvs.congestionWindow = congestionWindow_u8;
                if (!nvs->get_u8(encKeyValKey, encryptionKeyValue_u8)) encryptionKeyValue_u8 = 123; cfg_nvs.encryptionKey = encryptionKeyValue_u8;
                
                trafficClasses[cfg_nvs.trafficClassId] = cfg_nvs;
                defaultTrafficClassConfigs[cfg_nvs.trafficClassId] = cfg_nvs; 
                qosStats[cfg_nvs.trafficClassId] = {}; // Initialize QoS stats for loaded class
                LOG_I("Loaded TC %u: Prio %d, Rel %d, Enc %d, Frag %d, Retry %d, FECParity %d, CW %d, Key 0x%x",
                    cfg_nvs.trafficClassId, cfg_nvs.priority, cfg_nvs.reliable, cfg_nvs.encrypted, cfg_nvs.maxFragmentSize, 
                    cfg_nvs.retries, cfg_nvs.fec_num_parity_bytes, cfg_nvs.congestionWindow, cfg_nvs.encryptionKey);
            } else {
                LOG_D("NVS slot %u for TC is empty/invalid or failed to load ID.", i);
            }
        }
    } else {
        LOG_I("No Akita traffic class count key ('%s') found in NVS or count is 0.", countKeyStr);
    }
}

/**
 * @brief Saves a single traffic class configuration to an NVS slot.
 * Finds an existing slot for the TC ID or uses the next available one.
 * @param config_to_save The TrafficClassConfig object to save.
 */
void AkitaTrafficClassPlugin::saveTrafficClassToNVS(const TrafficClassConfig& config_to_save) { 
    NVSStorage* nvs = NVSStorage::getInstance();
    if (!nvs) {
        LOG_E("Failed to get NVS instance for saving TC %u.", config_to_save.trafficClassId);
        return;
    }

    int slot = -1;
    uint8_t classCount = 0;
    char countKeyStr[strlen(NVS_KEY_PREFIX) + strlen("count") + 1];
    strcpy(countKeyStr, NVS_KEY_PREFIX);
    strcat(countKeyStr, "count");

    nvs->get_u8(countKeyStr, classCount); 

    // Find existing slot for this TC ID
    for (uint8_t i = 0; i < classCount; ++i) {
        char keyBase[32];
        snprintf(keyBase, sizeof(keyBase), "%s%u_", NVS_KEY_PREFIX, i);
        char idKey[40]; snprintf(idKey, sizeof(idKey), "%sid", keyBase);
        uint32_t tcId_u32 = 0xFFFFFFFF; 
        if (nvs->get_u32(idKey, tcId_u32) && tcId_u32 == config_to_save.trafficClassId) {
            slot = i;
            break;
        }
    }

    // If not found, find an empty/invalid slot or add a new one
    if (slot == -1) { 
        bool foundEmptySlot = false;
        for (uint8_t i = 0; i < classCount; ++i) { 
             char keyBase[32];
             snprintf(keyBase, sizeof(keyBase), "%s%u_", NVS_KEY_PREFIX, i);
             char idKey[40]; snprintf(idKey, sizeof(idKey), "%sid", keyBase);
             uint32_t tcId_u32 = 0;
             // Check if slot is empty (key doesn't exist) or marked invalid
             if (!nvs->get_u32(idKey, tcId_u32) || tcId_u32 == 0xFFFFFFFF) { 
                 slot = i;
                 foundEmptySlot = true;
                 LOG_D("Found empty/invalid NVS slot %d for new TC %u", slot, config_to_save.trafficClassId);
                 break;
             }
        }
        if (!foundEmptySlot) {
            if (classCount < MAX_NVS_TRAFFIC_CLASSES) {
                slot = classCount; // Add to the end
                classCount++;
                LOG_D("Adding new TC %u to NVS slot %d, new count %d", config_to_save.trafficClassId, slot, classCount);
                if (!nvs->set_u8(countKeyStr, classCount)) {
                    LOG_E("Failed to update NVS class count when adding TC %u", config_to_save.trafficClassId);
                    return; 
                }
            } else {
                 LOG_E("Failed to find slot to save TC %u and NVS is full (%u classes).", config_to_save.trafficClassId, classCount);
                 return;
            }
        }
    }
    
    // --- Save all fields to the determined slot ---
    char keyBase[32];
    snprintf(keyBase, sizeof(keyBase), "%s%u_", NVS_KEY_PREFIX, slot);
    
    char idKey[40]; snprintf(idKey, sizeof(idKey), "%sid", keyBase);
    char prioKey[40]; snprintf(prioKey, sizeof(prioKey), "%sprio", keyBase);
    char relKey[40]; snprintf(relKey, sizeof(relKey), "%srel", keyBase);
    char encKeyStatusKey[40]; snprintf(encKeyStatusKey, sizeof(encKeyStatusKey), "%sencst", keyBase);
    char fragSzKey[40]; snprintf(fragSzKey, sizeof(fragSzKey), "%sfragsz", keyBase);
    char retryKey[40]; snprintf(retryKey, sizeof(retryKey), "%sretry", keyBase);
    char fecBytesKey[40]; snprintf(fecBytesKey, sizeof(fecBytesKey), "%sfecbytes", keyBase); 
    char cwKey[40]; snprintf(cwKey, sizeof(cwKey), "%scw", keyBase);
    char encKeyValKey[40]; snprintf(encKeyValKey, sizeof(encKeyValKey), "%senckval", keyBase);

    bool success = true;
    // Check return value of each set operation
    success &= nvs->set_u32(idKey, config_to_save.trafficClassId);
    success &= nvs->set_u8(prioKey, static_cast<uint8_t>(config_to_save.priority));
    success &= nvs->set_bool(relKey, config_to_save.reliable);
    success &= nvs->set_bool(encKeyStatusKey, config_to_save.encrypted);
    success &= nvs->set_u16(fragSzKey, static_cast<uint16_t>(config_to_save.maxFragmentSize));
    success &= nvs->set_u8(retryKey, static_cast<uint8_t>(config_to_save.retries));
    success &= nvs->set_u8(fecBytesKey, config_to_save.fec_num_parity_bytes); 
    success &= nvs->set_u8(cwKey, static_cast<uint8_t>(config_to_save.congestionWindow));
    success &= nvs->set_u8(encKeyValKey, config_to_save.encryptionKey);

    if (success) {
        LOG_I("Saved TC %u to NVS slot %d.", config_to_save.trafficClassId, slot);
        if (!nvs->commit()) { 
             LOG_E("NVS commit failed after saving TC %u", config_to_save.trafficClassId);
        }
    } else {
        LOG_E("Failed to save one or more NVS values for TC %u.", config_to_save.trafficClassId);
        // Consider if a partial save should be reverted or handled differently
    }
}

/**
 * @brief Deletes a traffic class configuration from NVS by marking its slot invalid.
 * @param trafficClassId The ID of the class to delete.
 */
void AkitaTrafficClassPlugin::deleteTrafficClassFromNVS(uint32_t trafficClassId) {
    NVSStorage* nvs = NVSStorage::getInstance();
    if (!nvs) {
        LOG_E("Failed to get NVS instance for deleting TC %u.", trafficClassId);
        return;
    }
    uint8_t classCount = 0;
    char countKeyStr[strlen(NVS_KEY_PREFIX) + strlen("count") + 1];
    strcpy(countKeyStr, NVS_KEY_PREFIX);
    strcat(countKeyStr, "count");
    nvs->get_u8(countKeyStr, classCount);

    bool foundAndErased = false;
    for (uint8_t i = 0; i < classCount; ++i) {
        char keyBase[32];
        snprintf(keyBase, sizeof(keyBase), "%s%u_", NVS_KEY_PREFIX, i);
        char idKey[40]; snprintf(idKey, sizeof(idKey), "%sid", keyBase);
        uint32_t tcId_u32 = 0;
        // Check if the ID matches the one we want to delete
        if (nvs->get_u32(idKey, tcId_u32) && tcId_u32 == trafficClassId) {
            LOG_I("Marking TC %u (slot %u) as deleted in NVS by setting ID to 0xFFFFFFFF.", trafficClassId, i);
            // Mark slot as invalid by writing an invalid ID marker
            if (!nvs->set_u32(idKey, 0xFFFFFFFF)) { 
                 LOG_E("Failed to mark NVS slot %u for TC %u as deleted.", i, trafficClassId);
            } else {
                foundAndErased = true;
            }
            // Optionally erase other keys for this slot for cleanliness
            // nvs->erase_key(...); 
            break; // Found the slot, no need to continue loop
        }
    }

    if (foundAndErased) {
        // Commit the change (marking as deleted)
        if (!nvs->commit()) {
             LOG_E("NVS commit failed after deleting TC %u", trafficClassId);
        }
    } else {
        LOG_W("TC %u not found in NVS for deletion.", trafficClassId);
    }
}


// --- Command Handling ---
/**
 * @brief Handles administrative commands intended for this plugin.
 * @param command The command name (e.g., "configure_class").
 * @param args A vector of string arguments for the command.
 * @return True if the command was recognized and handled, false otherwise.
 */
bool AkitaTrafficClassPlugin::handleAdminCommand(const std::string& command, const std::vector<std::string>& args) {
     LOG_I("Handling admin command: %s", command.c_str());

    if (command == "configure_class" || command == "config_class") {
        // Expected args: <id> <prio> <rel> <enc> <frag> <retry> <fec> <cw> <key>
        if (args.size() != 9) {
            LOG_E("configure_class: Incorrect number of arguments (%d). Expected 9.", args.size());
            return true; // Command recognized, but args wrong
        }
        try {
            // Use stoul for unsigned, stoi for signed, check ranges
            uint32_t id = std::stoul(args[0]);
            int prio = std::stoi(args[1]);
            bool rel = (args[2] == "true" || args[2] == "1");
            bool enc = (args[3] == "true" || args[3] == "1");
            int frag = std::stoi(args[4]);
            int retry = std::stoi(args[5]);
            int fec = std::stoi(args[6]); 
            int cw = std::stoi(args[7]);
            // Use stoul with base 0 to allow hex (0x...) or decimal for key
            uint8_t key = static_cast<uint8_t>(std::stoul(args[8], nullptr, 0)); 

            // Additional validation
            if (prio <= 0 || frag < MIN_MTU_FUDGE || retry < 0 || cw <= 0) {
                 LOG_E("configure_class: Invalid numeric argument value (prio/frag/retry/cw).");
                 return true;
            }
            if (fec < 0 || fec > FEC_MAX_PARITY_BYTES) {
                 LOG_E("configure_class: Invalid FEC parity bytes value %d (must be 0-%d).", fec, FEC_MAX_PARITY_BYTES);
                 return true;
            }

            bool success = configureTrafficClass(id, prio, rel, enc, frag, retry, (uint8_t)fec, cw, key);
            LOG_I("configure_class command %s.", success ? "succeeded" : "failed");

        } catch (const std::invalid_argument& ia) {
            LOG_E("configure_class: Invalid argument format: %s", ia.what());
        } catch (const std::out_of_range& oor) {
             LOG_E("configure_class: Argument out of range: %s", oor.what());
        }
        return true; // Command recognized

    } else if (command == "delete_class") {
        if (args.size() != 1) {
             LOG_E("delete_class: Incorrect number of arguments (%d). Expected 1 (ID).", args.size());
             return true;
        }
         try {
            uint32_t id = std::stoul(args[0]);
            bool success = deleteTrafficClass(id);
             LOG_I("delete_class command %s.", success ? "succeeded" : "failed");
         } catch (const std::invalid_argument& ia) {
            LOG_E("delete_class: Invalid argument format: %s", ia.what());
        } catch (const std::out_of_range& oor) {
             LOG_E("delete_class: Argument out of range: %s", oor.what());
        }
        return true; // Command recognized

    } else if (command == "get_class_config") {
         if (args.size() != 1) {
             LOG_E("get_class_config: Incorrect number of arguments (%d). Expected 1 (ID).", args.size());
             return true;
        }
         try {
            uint32_t id = std::stoul(args[0]);
            const TrafficClassConfig* cfg = getTrafficClassConfig(id);
            if (cfg) {
                char buffer[200];
                 snprintf(buffer, sizeof(buffer), 
                    "TC %u Config: Prio=%d, Rel=%d, Enc=%d, FragSz=%d, Retry=%d, FECParity=%d, CW=%d, Key=0x%02X",
                    cfg->trafficClassId, cfg->priority, cfg->reliable, cfg->encrypted, cfg->maxFragmentSize, 
                    cfg->retries, cfg->fec_num_parity_bytes, cfg->congestionWindow, cfg->encryptionKey);
                 LOG_I("%s", buffer);
                 // TODO: In a real implementation, this buffer would be sent back via an AdminMessage response.
            } else {
                 LOG_W("get_class_config: Traffic class ID %u not found.", id);
            }
         } catch (const std::invalid_argument& ia) {
            LOG_E("get_class_config: Invalid argument format: %s", ia.what());
        } catch (const std::out_of_range& oor) {
             LOG_E("get_class_config: Argument out of range: %s", oor.what());
        }
        return true; // Command recognized

    } else if (command == "list_classes") {
        LOG_I("Current Traffic Classes:");
        if (trafficClasses.empty()) {
            LOG_I("  (None configured)");
        } else {
            for(const auto& pair : trafficClasses) {
                 const TrafficClassConfig& cfg = pair.second;
                 LOG_I("  TC %u: Prio=%d, Rel=%d, Enc=%d, FragSz=%d, Retry=%d, FECParity=%d, CW=%d, Key=0x%02X",
                    cfg.trafficClassId, cfg.priority, cfg.reliable, cfg.encrypted, cfg.maxFragmentSize, 
                    cfg.retries, cfg.fec_num_parity_bytes, cfg.congestionWindow, cfg.encryptionKey);
            }
        }
         return true; // Command recognized
    }

    LOG_W("Unknown admin command received by Akita plugin: %s", command.c_str());
    return false; // Command not recognized
}


// --- Data Callback Registration ---
/**
 * @brief Registers a callback function to receive successfully reassembled/processed data.
 * @param handler The function to call. It should match the DataReceiveCallback signature.
 */
void AkitaTrafficClassPlugin::registerDataHandler(DataReceiveCallback handler) {
    onDataReceived = handler;
    LOG_I("Data receive handler registered.");
}


// --- Overridden base Plugin methods ---
/**
 * @brief Called by Meshtastic core for any packet received by the radio.
 * Passes packets with the plugin's PortNum to handleReceivedProtobuf.
 * @param packet The received MeshPacket.
 */
void AkitaTrafficClassPlugin::onPacketReceived(MeshPacket &packet) {
    // Let the base ProtobufModule handle filtering by portnum and calling handleReceivedProtobuf
    ProtobufModule<meshtastic_AkitaPluginEnvelope>::onPacketReceived(packet);
}

/**
 * @brief Called by Meshtastic core before any packet is sent by the radio.
 * Allows inspection or modification. Returning false blocks the send.
 * @param packet The MeshPacket to be sent.
 * @param destination Pointer to the destination NodeInfo (can be null).
 * @return True to allow sending, false to block.
 */
bool AkitaTrafficClassPlugin::onPacketToSend(MeshPacket &packet, const NodeInfo* destination) {
    // Default behavior is to allow all packets to be sent.
    // Could add logic here to prioritize based on packet.priority if needed.
    return true; 
}

/**
 * @brief Called by Meshtastic core when node information is updated in the NodeDB.
 * @param node The updated NodeInfo object.
 */
void AkitaTrafficClassPlugin::onNodeUpdated(NodeInfo &node) {
    updateRoutingMetrics(node); // Trigger routing metric recalculation for this node
}

/**
 * @brief Called by Meshtastic core when the main device configuration changes.
 */
void AkitaTrafficClassPlugin::onConfigChanged() {
    LOG_I("Akita: Meshtastic global configuration changed. Reloading plugin config.");
    loadPluginConfig(); // Reload our NVS settings
}

/**
 * @brief Called by Meshtastic core when the radio's power/operational state changes.
 * @param state The new RadioState.
 */
void AkitaTrafficClassPlugin::onRadioStateChanged(RadioState state) {
     LOG_D("Akita: Radio state changed to %d", (int)state);
     currentRadioState = state; // Update internal state tracker for power saving logic
}


} // namespace meshtastic

