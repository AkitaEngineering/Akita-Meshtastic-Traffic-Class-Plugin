#include "meshtastic.h"
#include "plugin.h"
#include <map>
#include <queue>
#include <algorithm>
#include <random>
#include <chrono>
#include <iostream> // For logging (replace with Meshtastic's logging)

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

// ... (getters as before) ...

void AkitaTrafficClassPlugin::processIncomingPacket(Packet &packet) {
    uint32_t trafficClass = packet.decoded.data.traffic_class();
    if (trafficClassPriorities.count(trafficClass)) {
        if (isTrafficClassEncrypted(trafficClass)) {
            // TODO: Implement decryption
            std::cout << "DEBUG: Packet decryption placeholder" << std::endl;
        }

        if (packet.decoded.data.has_fragment_id()) {
            handleReassembly(packet, trafficClass);
        } else {
            // TODO: Implement packet processing (forward, display, etc.)
            std::cout << "DEBUG: Processing packet (forwarding, display, etc.)" << std::endl;
        }
    } else {
        std::cout << "DEBUG: Dropping unknown traffic class" << std::endl;
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
    // Implement routing metric updates based on traffic class
    uint32_t nodeId = node.nodeNum;

    // Iterate through all traffic classes
    for (const auto& [trafficClass, priority] : trafficClassPriorities) {
        // Get link quality for this node
        int linkQuality = getLinkQuality(nodeId);

        // Adjust routing metric based on traffic class priority and link quality
        // Example: Higher priority traffic classes prefer better link quality
        int adjustedLinkQuality = linkQuality;

        if (priority > 5) { // High priority
            if (linkQuality < 50) {
                adjustedLinkQuality = 0; // Penalize poor links for high priority
            } else {
                adjustedLinkQuality = linkQuality + (priority - 5) * 5; // Reward good links
            }
        } else if (priority < 3){ //low priority
            if (linkQuality < 20){
                adjustedLinkQuality = 0;
            }
        } else { //medium priority
            adjustedLinkQuality = linkQuality;
        }

        // Update routing metric for this node and traffic class
        // TODO: Update the Meshtastic routing table with the adjustedLinkQuality
        // Example (replace with actual Meshtastic routing API call):
        std::cout << "DEBUG: Updating routing metric for node " << nodeId << ", traffic class " << trafficClass << ", adjusted link quality " << adjustedLinkQuality << std::endl;

        // You would typically use the RadioInterface or Routing API to update the routing table
        // with the adjusted link quality for the specific traffic class.
        // Something like:
        // RadioInterface::getInstance()->updateRoutingMetric(nodeId, trafficClass, adjustedLinkQuality);
    }
}

int AkitaTrafficClassPlugin::getLinkQuality(uint32_t nodeId) {
    // TODO: Implement logic to get link quality from Meshtastic API
    // Example (replace with actual Meshtastic API call):
    return 60; // Placeholder
}

void AkitaTrafficClassPlugin::transmitPackets() {
    std::vector<std::pair<int, uint32_t>> priorityList;
    for (auto const &pair : trafficClassPriorities) {
        priorityList.emplace_back(pair.second, pair.first);
    }
    std::sort(priorityList.begin(), priorityList.end());

    for (const auto &pair : priorityList) {
        uint32_t trafficClass = pair.second;
        int congestionWindow = getCongestionWindow(trafficClass);
        int packetsSent = 0;
        while (!trafficClassQueues[trafficClass].empty() && packetsSent < congestionWindow) {
            Packet packet = trafficClassQueues[trafficClass].front();
            trafficClassQueues[trafficClass].pop();

            if (isTrafficClassReliable(trafficClass)) {
                applyErrorCorrection(packet, trafficClass);
                applyForwardErrorCorrection(packet, trafficClass);
            }
            // TODO: Implement Airtime fairness.
            RadioInterface::getInstance()->sendPacket(packet);
            packetsSent++;
        }
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
    reassemblyTimers[trafficClass][fragmentId] = std::chrono::steady_clock::now() + std::chrono::seconds(5); // 5 second timeout
    // TODO: Implement logic to check if all fragments have been received, handle out-of-order fragments, and reassemble the packet.
    // TODO: Implement retransmission requests for missing fragments.
    std::cout << "DEBUG: Handling fragment reassembly" << std::endl;
}

void AkitaTrafficClassPlugin::applyErrorCorrection(Packet& packet, uint32_t trafficClass){
    // TODO: Implement error correction (e.g., checksum)
    std::cout << "DEBUG: Applying error correction" << std::endl;
}

void AkitaTrafficClassPlugin::applyForwardErrorCorrection(Packet& packet, uint32_t trafficClass){
    // TODO: Implement forward error correction (e.g., Reed-Solomon)
    std::cout << "DEBUG: Applying forward error correction" << std::endl;
}

void AkitaTrafficClassPlugin::handleRetransmission(uint32_t trafficClass, uint32_t fragmentId) {
    if (fragmentRetryCounts[trafficClass][fragmentId] < getRetries(trafficClass)) {
        for (const auto& fragment : fragmentBuffers[trafficClass][fragmentId]) {
            retransmissionQueues[trafficClass][fragmentId].push_back(fragment);
        }
        fragmentRetryCounts[trafficClass][fragmentId]++;
        fragmentTimers[trafficClass][fragmentId] = std::chrono::steady_clock::now() + std::chrono::milliseconds(2000); // 2 second retry delay
    } else {
        std::cout << "DEBUG: Max retransmissions reached" << std::endl;
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
    // Example implementation: Adjust priority based on battery level, link quality, node load, and queue length.

    for (auto& [trafficClass, priority] : trafficClassPriorities) {
        int batteryLevel = getBatteryLevel();
        int linkQuality = getLinkQuality(RadioInterface::getInstance()->getNodeId());
        int nodeLoad = getNodeLoad(RadioInterface::getInstance()->getNodeId());
        int queueLength = getNumPacketsInQueue(trafficClass);

        if (batteryLevel < 20) { // Low battery
            if (trafficClass != 0) { // Don't change priority of critical traffic class 0
                if (priority > 1) {
                    trafficClassPriorities[trafficClass] = std::max(1, priority - 1); // Reduce priority
                    std::cout << "DEBUG: Traffic class " << trafficClass << " priority reduced due to low battery." << std::endl;
                }
            }
        } else if (linkQuality < 30) { // Poor link quality
            if (trafficClass != 0) {
                if (priority > 1) {
                    trafficClassPriorities[trafficClass] = std::max(1, priority - 1); // Reduce priority
                    std::cout << "DEBUG: Traffic class " << trafficClass << " priority reduced due to poor link quality." << std::endl;
                }
            }
        } else if (nodeLoad > 80) { // High node load
            if (trafficClass != 0) {
                if (priority > 1) {
                    trafficClassPriorities[trafficClass] = std::max(1, priority - 1); // Reduce priority
                    std::cout << "DEBUG: Traffic class " << trafficClass << " priority reduced due to high node load." << std::endl;
                }
            }
        } else if (queueLength > 20 && priority > 1) { // Long queue
            if (trafficClass != 0) {
                trafficClassPriorities[trafficClass] = std::max(1, priority - 1); // Reduce priority
                std::cout << "DEBUG: Traffic class " << trafficClass << " priority reduced due to long queue." << std::endl;
            }
        } else {
            // Restore default priority if conditions improve
            if (trafficClassPriorities[trafficClass] != defaultTrafficClassPriorities[trafficClass]) {
                trafficClassPriorities[trafficClass] = defaultTrafficClassPriorities[trafficClass];
                std::cout << "DEBUG: Traffic class " << trafficClass << " priority restored." << std::endl;
            }
        }
    }
}

void AkitaTrafficClassPlugin::monitorQoS() {
    // TODO: Implement QoS monitoring
    std::cout << "DEBUG: QoS monitoring placeholder" << std::endl;
}

void AkitaTrafficClassPlugin::loadConfig(){
    //TODO: Implement loading config from device storage.
    std::cout << "DEBUG: Loading configuration placeholder" << std::endl;
}

void AkitaTrafficClassPlugin::checkReassemblyTimers(){
    auto now = std::chrono::steady_clock::now();
    for (auto& trafficClassMap : reassemblyTimers) {
        for (auto it = trafficClassMap.second.begin(); it != trafficClassMap.second.end();) {
            if (it->second <= now) {
                //TODO: Implement timeout logic for reassembly.
                std::cout << "DEBUG: Reassembly timeout" << std::endl;
                it = trafficClassMap.second.erase(it);
            } else {
                ++it;
            }
        }
    }
}
} // namespace meshtastic
