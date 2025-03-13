#include "meshtastic.h"
#include "plugin.h"
#include <map>
#include <queue>
#include <algorithm>
#include <random>
#include <chrono>
#include <iostream>

namespace meshtastic {

class AkitaTrafficClassPlugin : public Plugin {
public:
    virtual void onPacketReceived(Packet &packet) override;
    virtual void onPacketToSend(Packet &packet) override;
    virtual void onNodeUpdated(NodeInfo &node) override;
    virtual void onConfigChanged() override;
    virtual void onRadioStateChanged(RadioState state) override;

    void configureTrafficClass(uint32_t trafficClass, int priority, bool reliable, bool encrypted, int maxFragmentSize, int retries, int fecLevel, int congestionWindow);
    uint32_t getTrafficClassPriority(uint32_t trafficClass);
    bool isTrafficClassReliable(uint32_t trafficClass);
    bool isTrafficClassEncrypted(uint32_t trafficClass);
    int getMaxFragmentSize(uint32_t trafficClass);
    int getRetries(uint32_t trafficClass);
    int getFecLevel(uint32_t trafficClass);
    int getCongestionWindow(uint32_t trafficClass);

private:
    std::map<uint32_t, int> trafficClassPriorities;
    std::map<uint32_t, bool> trafficClassReliability;
    std::map<uint32_t, bool> trafficClassEncryption;
    std::map<uint32_t, int> trafficClassFragmentSizes;
    std::map<uint32_t, int> trafficClassRetries;
    std::map<uint32_t, int> trafficClassFecLevels;
    std::map<uint32_t, int> trafficClassCongestionWindows;
    std::map<uint32_t, std::queue<Packet>> trafficClassQueues;
    std::map<uint32_t, std::map<uint32_t, std::vector<Packet>>> fragmentBuffers;
    std::map<uint32_t, std::map<uint32_t, int>> fragmentRetryCounts;
    std::map<uint32_t, std::map<uint32_t, std::chrono::steady_clock::time_point>> fragmentTimers;
    std::map<uint32_t, std::map<uint32_t, std::vector<Packet>>> retransmissionQueues;
    std::map<uint32_t, std::map<uint32_t, std::chrono::steady_clock::time_point>> reassemblyTimers;
    std::map<uint32_t, int> defaultTrafficClassPriorities; // Store default priorities

    void processIncomingPacket(Packet &packet);
    void processOutgoingPacket(Packet &packet);
    void updateRoutingMetrics(NodeInfo &node);
    void transmitPackets();
    void handleFragmentation(Packet &packet, uint32_t trafficClass);
    void handleReassembly(Packet &packet, uint32_t trafficClass);
    void applyErrorCorrection(Packet& packet, uint32_t trafficClass);
    void applyForwardErrorCorrection(Packet& packet, uint32_t trafficClass);
    Packet createFragment(const Packet& original, uint32_t fragmentId, uint32_t offset, uint32_t fragmentSize);
    void handleRetransmission(uint32_t trafficClass, uint32_t fragmentId);
    void checkRetransmissionTimers();
    void adjustCongestionWindow(uint32_t trafficClass, bool success);
    void dynamicFragmentSize(uint32_t trafficClass, int linkQuality);
    void dynamicTrafficClassAdaptation();
    void monitorQoS();
    void loadConfig();
    void checkReassemblyTimers();

    std::random_device rd;
    std::mt19937 gen;
    std::uniform_int_distribution<> dis;

    int getBatteryLevel();
    int getLinkQuality(uint32_t nodeId);
    int getNodeLoad(uint32_t nodeId);
    int getNumPacketsInQueue(uint32_t trafficClass);

    void encrypt(std::string& data, uint8_t key);
    void decrypt(std::string& data, uint8_t key);

};

static Plugin *akitaTrafficClassPluginFactory() {
    return new AkitaTrafficClassPlugin();
}

static bool registered = PluginManager::getInstance()->registerPlugin("akita_traffic_class", akitaTrafficClassPluginFactory);

void AkitaTrafficClassPlugin::onPacketReceived(Packet &packet) {
    processIncomingPacket(packet);
}

void AkitaTrafficClassPlugin::onPacketToSend(Packet &packet) {
    processOutgoingPacket(packet);
}

void AkitaTrafficClassPlugin::onNodeUpdated(NodeInfo &node) {
    updateRoutingMetrics(node);
}

void AkitaTrafficClassPlugin::onConfigChanged() {
    loadConfig();
}

void AkitaTrafficClassPlugin::onRadioStateChanged(RadioState state) {
    // Handle radio state changes (e.g., power saving)
}

void AkitaTrafficClassPlugin::configureTrafficClass(uint32_t trafficClass, int priority, bool reliable, bool encrypted, int maxFragmentSize, int retries, int fecLevel, int congestionWindow) {
    trafficClassPriorities[trafficClass] = priority;
    trafficClassReliability[trafficClass] = reliable;
    trafficClassEncryption[trafficClass] = encrypted;
    trafficClassFragmentSizes[trafficClass] = maxFragmentSize;
    trafficClassRetries[trafficClass] = retries;
    trafficClassFecLevels[trafficClass] = fecLevel;
    trafficClassCongestionWindows[trafficClass] = congestionWindow;
}

uint32_t AkitaTrafficClassPlugin::getTrafficClassPriority(uint32_t trafficClass) {
    return trafficClassPriorities[trafficClass];
}

bool AkitaTrafficClassPlugin::isTrafficClassReliable(uint32_t trafficClass) {
    return trafficClassReliability[trafficClass];
}

bool AkitaTrafficClassPlugin::isTrafficClassEncrypted(uint32_t trafficClass) {
    return trafficClassEncryption[trafficClass];
}

int AkitaTrafficClassPlugin::getMaxFragmentSize(uint32_t trafficClass) {
    return trafficClassFragmentSizes[trafficClass];
}

int AkitaTrafficClassPlugin::getRetries(uint32_t trafficClass) {
    return trafficClassRetries[trafficClass];
}

int AkitaTrafficClassPlugin::getFecLevel(uint32_t trafficClass) {
    return trafficClassFecLevels[trafficClass];
}

int AkitaTrafficClassPlugin::getCongestionWindow(uint32_t trafficClass) {
    return trafficClassCongestionWindows[trafficClass];
}

void AkitaTrafficClassPlugin::processIncomingPacket(Packet &packet) {
    uint32_t trafficClass = packet.decoded.data.traffic_class();
    if (trafficClassPriorities.count(trafficClass)) {
        if (isTrafficClassEncrypted(trafficClass)) {
            decrypt(*packet.decoded.data.mutable_payload().mutable_data(), 123);
        }

        if (packet.decoded.data.has_fragment_id()) {
            handleReassembly(packet, trafficClass);
        } else {
            MESHTASTIC_DEBUG("Processing packet (forwarding, display, etc.)");
        }
    } else {
        MESHTASTIC_DEBUG("Dropping unknown traffic class");
    }
}

void AkitaTrafficClassPlugin::processOutgoingPacket(Packet &packet) {
    uint32_t trafficClass = packet.decoded.data.traffic_class();
    if (packet.decoded.data.payload().size() > getMaxFragmentSize(trafficClass)) {
        handleFragmentation(packet, trafficClass);
    } else {
        trafficClassQueues[trafficClass].push(packet);
        transmitPackets();
    }
}

void AkitaTrafficClassPlugin::updateRoutingMetrics(NodeInfo &node) {
    uint32_t nodeId = node.nodeNum;

    for (const auto& [trafficClass, priority] : trafficClassPriorities) {
        int linkQuality = getLinkQuality(nodeId);
        int adjustedLinkQuality = linkQuality;

        if (priority > 5) {
            if (linkQuality < 50) {
                adjustedLinkQuality = 0;
            } else {
                adjustedLinkQuality = linkQuality + (priority - 5) * 5;
            }
        } else if (priority < 3){
            if (linkQuality < 20){
                adjustedLinkQuality = 0
                    }
        } else {
            adjustedLinkQuality = linkQuality;
        }

        static std::map<uint32_t, std::map<uint32_t, int>> backoffCounts;
        if (linkQuality < 20) {
            backoffCounts[trafficClass][nodeId]++;
            adjustedLinkQuality = adjustedLinkQuality / (backoffCounts[trafficClass][nodeId]);
        } else {
            backoffCounts[trafficClass][nodeId] = 0;
        }

        MESHTASTIC_DEBUG("Updating routing metric for node {}, traffic class {}, adjusted link quality {}", nodeId, trafficClass, adjustedLinkQuality);
        // TODO: Update the Meshtastic routing table with the adjustedLinkQuality
        // RadioInterface::getInstance()->updateRoutingMetric(nodeId, trafficClass, adjustedLinkQuality);
    }
}

int AkitaTrafficClassPlugin::getLinkQuality(uint32_t nodeId) {
    // TODO: Implement logic to get link quality from Meshtastic API
    // Example (replace with actual Meshtastic API call):
    return 60; // Placeholder
}

void AkitaTrafficClassPlugin::transmitPackets() {
    std::vector<uint32_t> trafficClasses;
    for (const auto& pair : trafficClassPriorities) {
        trafficClasses.push_back(pair.first);
    }

    static size_t currentTrafficClassIndex = 0;

    for (size_t i = 0; i < trafficClasses.size(); ++i) {
        uint32_t trafficClass = trafficClasses[currentTrafficClassIndex];

        if (!trafficClassQueues[trafficClass].empty()) {
            Packet packet = trafficClassQueues[trafficClass].front();
            trafficClassQueues[trafficClass].pop();

            if (isTrafficClassReliable(trafficClass)) {
                applyErrorCorrection(packet, trafficClass);
                applyForwardErrorCorrection(packet, trafficClass);
            }
            if(isTrafficClassEncrypted(trafficClass)){
                encrypt(*packet.decoded.data.mutable_payload().mutable_data(), 123);
            }

            RadioInterface::getInstance()->sendPacket(packet);

            currentTrafficClassIndex = (currentTrafficClassIndex + 1) % trafficClasses.size();
            return;
        }

        currentTrafficClassIndex = (currentTrafficClassIndex + 1) % trafficClasses.size();
    }
}

void AkitaTrafficClassPlugin::handleFragmentation(Packet &packet, uint32_t trafficClass) {
    uint32_t fragmentId = rand();
    uint32_t offset = 0;
    uint32_t fragmentSize = getMaxFragmentSize(trafficClass);
    const std::string& payload = packet.decoded.data.payload();

    while (offset < payload.size()) {
        Packet fragment = createFragment(packet, fragmentId, offset, fragmentSize);
        fragment.decoded.data.set_traffic_class(trafficClass);
        trafficClassQueues[trafficClass].push(fragment);
        offset += fragmentSize;
    }
    transmitPackets();
}

Packet AkitaTrafficClassPlugin::createFragment(const Packet& original, uint32_t fragmentId, uint32_t offset, uint32_t fragmentSize){
    Packet fragment = original;
    fragment.decoded.data.set_fragment_id(fragmentId);
    fragment.decoded.data.set_fragment_offset(offset);
    fragment.decoded.data.set_payload(original.decoded.data.payload().substr(offset, fragmentSize));
    return fragment;
}

void AkitaTrafficClassPlugin::handleReassembly(Packet &packet, uint32_t trafficClass) {
    uint32_t fragmentId = packet.decoded.data.fragment_id();
    uint32_t offset = packet.decoded.data.fragment_offset();

    fragmentBuffers[trafficClass][fragmentId].push_back(packet);
    reassemblyTimers[trafficClass][fragmentId] = std::chrono::steady_clock::now() + std::chrono::seconds(5);

    // TODO: Implement logic to check if all fragments have been received, handle out-of-order fragments, and reassemble the packet.
    // TODO: Implement retransmission requests for missing fragments.
    MESHTASTIC_DEBUG("Handling fragment reassembly");
}

void AkitaTrafficClassPlugin::applyErrorCorrection(Packet& packet, uint32_t trafficClass) {
    std::string& payload = packet.decoded.data.mutable_payload();
    uint8_t checksum = 0;
    for (uint8_t byte : payload) {
        checksum ^= byte;
    }
    payload += checksum;
}

void AkitaTrafficClassPlugin::applyForwardErrorCorrection(Packet& packet, uint32_t trafficClass){
    std::string& payload = packet.decoded.data.mutable_payload();
    payload += (uint8_t)(payload[0] ^ payload[payload.size()-1]);
}

void AkitaTrafficClassPlugin::handleRetransmission(uint32_t trafficClass, uint32_t fragmentId) {
    if (fragmentRetryCounts[trafficClass][fragmentId] < getRetries(trafficClass)) {
        for (const auto& fragment : fragmentBuffers[trafficClass][fragmentId]) {
            retransmissionQueues[trafficClass][fragmentId].push_back(fragment);
        }
        fragmentRetryCounts[trafficClass][fragmentId]++;
        fragmentTimers[trafficClass][fragmentId] = std::chrono::steady_clock::now() + std::chrono::milliseconds(2000);
    } else {
        MESHTASTIC_DEBUG("Max retransmissions reached");
    }
}

void AkitaTrafficClassPlugin::checkRetransmissionTimers() {
    auto now = std::chrono::steady_clock::now();
    for (auto& trafficClassMap : fragmentTimers) {
        for (auto it = trafficClassMap.second.begin(); it != trafficClassMap.second.end();) {
            if (it->second <= now) {
                handleRetransmission(trafficClassMap.first, it->first);
                it = trafficClassMap.second.erase(it);
            } else {
                ++it;
            }
        }
    }
}

void AkitaTrafficClassPlugin::adjustCongestionWindow(uint32_t trafficClass, bool success) {
    int& window = trafficClassCongestionWindows[trafficClass];
    if (success) {
        window = std::min(window + 1, 10);
    } else {
        window = std::max(window / 2, 1);
    }
}

void AkitaTrafficClassPlugin::dynamicFragmentSize(uint32_t trafficClass, int linkQuality) {
    if (linkQuality > 70) {
        trafficClassFragmentSizes[trafficClass] = 250;
    } else if (linkQuality > 40) {
        trafficClassFragmentSizes[trafficClass] = 150;
    } else {
        trafficClassFragmentSizes[trafficClass] = 50;
    }
}

void AkitaTrafficClassPlugin::dynamicTrafficClassAdaptation() {
    for (auto& [trafficClass, priority] : trafficClassPriorities) {
        int batteryLevel = getBatteryLevel();
        int linkQuality = getLinkQuality(RadioInterface::getInstance()->getNodeId());
        int nodeLoad = getNodeLoad(RadioInterface::getInstance()->getNodeId());
        int queueLength = getNumPacketsInQueue(trafficClass);

        if (batteryLevel < 20) {
            if (trafficClass != 0) {
                if (priority > 1) {
                    trafficClassPriorities[trafficClass] = std::max(1, priority - 1);
                    MESHTASTIC_DEBUG("Traffic class {} priority reduced due to low battery.", trafficClass);
                }
            }
        } else if (linkQuality < 30) {
            if (trafficClass != 0) {
                if (priority > 1) {
                    trafficClassPriorities[trafficClass] = std::max(1, priority - 1);
                    MESHTASTIC_DEBUG("Traffic class {} priority reduced due to poor link quality.", trafficClass);
                }
            }
        } else if (nodeLoad > 80) {
            if (trafficClass != 0) {
                if (priority > 1) {
                    trafficClassPriorities[trafficClass] = std::max(1, priority - 1);
                    MESHTASTIC_DEBUG("Traffic class {} priority reduced due to high node load.", trafficClass);
                }
            }
        } else if (queueLength > 20 && priority > 1) {
            if (trafficClass != 0) {
                trafficClassPriorities[trafficClass] = std::max(1, priority - 1);
                    MESHTASTIC_DEBUG("Traffic class {} priority reduced due to long queue.", trafficClass);
                }
            }
        } else {
            if (trafficClassPriorities[trafficClass] != defaultTrafficClassPriorities[trafficClass]) {
                trafficClassPriorities[trafficClass] = defaultTrafficClassPriorities[trafficClass];
                MESHTASTIC_DEBUG("Traffic class {} priority restored.", trafficClass);
            }
        }
    }
}

void AkitaTrafficClassPlugin::monitorQoS() {
    // TODO: Implement QoS monitoring
    MESHTASTIC_DEBUG("QoS monitoring placeholder");
}

void AkitaTrafficClassPlugin::loadConfig() {
    // Simulate loading from JSON
    std::string jsonConfig = "{\"trafficClasses\": [{\"id\": 1, \"priority\": 5}, {\"id\": 2, \"priority\": 3}]}";
    // TODO: Replace with actual Meshtastic JSON parsing
    // Example:
    // auto config = nlohmann::json::parse(jsonConfig);
    // for (auto& tc : config["trafficClasses"]) {
    //     configureTrafficClass(tc["id"], tc["priority"], ...);
    // }
    trafficClassPriorities[1] = 5;
    trafficClassPriorities[2] = 3;

    for (const auto& [trafficClass, priority] : trafficClassPriorities) {
        defaultTrafficClassPriorities[trafficClass] = priority;
    }

    MESHTASTIC_DEBUG("Loading configuration placeholder");
}

void AkitaTrafficClassPlugin::checkReassemblyTimers() {
    auto now = std::chrono::steady_clock::now();
    for (auto& trafficClassMap : reassemblyTimers) {
        for (auto it = trafficClassMap.second.begin(); it != trafficClassMap.second.end();) {
            if (it->second <= now) {
                MESHTASTIC_DEBUG("Reassembly timeout for traffic class {}, fragment ID {}", trafficClassMap.first, it->first);
                fragmentBuffers[trafficClassMap.first].erase(it->first);
                it = trafficClassMap.second.erase(it);
            } else {
                ++it;
            }
        }
    }
}

int AkitaTrafficClassPlugin::getBatteryLevel() {
    // TODO: Implement logic to get battery level from Meshtastic API
    // Example (replace with actual Meshtastic API call):
    return 80; // Placeholder
}

int AkitaTrafficClassPlugin::getNodeLoad(uint32_t nodeId) {
    // TODO: Implement logic to get node load from meshtastic API.
    return 50; // placeholder
}

int AkitaTrafficClassPlugin::getNumPacketsInQueue(uint32_t trafficClass) {
    // Get the number of packets in the specified traffic class queue
    return trafficClassQueues[trafficClass].size();
}

void AkitaTrafficClassPlugin::encrypt(std::string& data, uint8_t key) {
    for (char& byte : data) {
        byte ^= key;
    }
}

void AkitaTrafficClassPlugin::decrypt(std::string& data, uint8_t key) {
    encrypt(data, key); // XOR is its own inverse
}

} // namespace meshtastic
