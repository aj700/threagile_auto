# Telematics Gateway ECU Design

## 1. System Overview
The Telematics Gateway ECU (T-Box) is the vehicle's primary interface to the external world and the **Vehicle Grandmaster Clock**. It manages cellular connectivity (4G/5G), V2X communications, and Global Navigation Satellite Systems (GNSS).

### Key Roles
1.  **Connectivity Gateway**: Secure entry point for Cloud, OTA, and Telematics.
2.  **Vehicle Time Master**: Securely sources time from GNSS, validates it, and distributes it to the entire vehicle network via Ethernet (gPTP) and CAN (AUTOSAR Time Sync).

## 2. Hardware Architecture
The system is built on a specialized Telematics SoC (e.g., Qualcomm Snapdragon Auto) with dedicated modem, V2X, and **Time Synchronization Hardware**.

| Component | Description | Safety/Security Level | Function |
| :--- | :--- | :--- | :--- |
| **Application Processor (AP)** | Multi-core ARM Cortex-A | QM / ASIL-B | Linux/Android. Runs Time Master Stack, Router, Telematics Apps. |
| **Modem Subsystem** | 5G/LTE Baseband | QM | Cellular connectivity. |
| **V2X Processor** | C-V2X / DSRC Radio | ASIL-B | Direct V2X communication. |
| **Security Controller** | HSM / SE | ASIL-D | Secure storage, Time Validation, V2X Keys. |
| **GNSS Receiver** | High-precision GPS/Galileo | ASIL-B | **Trusted Time Source** (PPS/NMEA). |
| **CAN Controller** | CAN-FD Interface | ASIL-B | **New**: dedicated link to Door/Unlock ECUs. |

## 3. Network Topology
*   **External Interfaces**:
    *   **Cellular / V2X**: WAN and Sidelink.
    *   **GNSS**: Time and Position Source.
*   **Internal Interfaces**:
    *   **Ethernet (1000BASE-T1)**: Backbone link to **Central Gateway ECU**. Carries **gPTP (802.1AS)** time sync.
    *   **CAN-FD (Private Bus)**: Connected to **Door/Unlock ECUs**. Carries **AUTOSAR Global Time** for synchronized unlock operations.

## 4. Software Diagram & Data Flow

```mermaid
graph TD
    subgraph "External World"
        Cloud[OEM Cloud]
        GPS_Sat[GNSS Satellites]
    end

    subgraph "Telematics Gateway ECU (Time Master)"
        style AP fill:#ffcccc,stroke:#333,stroke-width:2px,label:QM
        style HSM fill:#e6e6e6,stroke:#333,stroke-width:2px,label:Security
        style GNSS fill:#ccffcc,stroke:#333,stroke-width:2px,label:Time Source
        
        GNSS[GNSS Receiver]
        
        subgraph "Application Processor"
            TimeMaster[Global Time Master]
            TelematicsApp[Telematics Agent]
            Router[Network Router]
        end
        
        subgraph "Hardware Security"
            HSM[HSM / Secure Element]
        end
    end

    subgraph "Vehicle Internal"
        CentralGW[Central Gateway ECU]
        
        subgraph "Unlock Domain"
            DoorECU1[Door ECU Left]
            DoorECU2[Door ECU Right]
        end
    end

    %% Time Sourcing
    GPS_Sat -.->|RF Signals| GNSS
    GNSS ==>|pps / NMEA| TimeMaster
    
    %% Security
    TimeMaster -.->|Validate Time| HSM
    
    %% Time Distribution
    TimeMaster ==>|gPTP (Ethernet)| CentralGW
    TimeMaster ==>|AUTOSAR Time (CAN)| DoorECU1
    TimeMaster ==>|AUTOSAR Time (CAN)| DoorECU2
    
    %% Other Flows
    TelematicsApp <==>|Data| Cloud
    TelematicsApp -->|Data| Router
    Router <==>|Ethernet| CentralGW
```

## 5. Time Synchronization Strategy
1.  **Source**: GNSS Receiver provides high-precision pulse-per-second (PPS) and absolute time (NMEA/measurement).
2.  **Validation**: The HSM or Safe Environment validates the time source against internal drift or secondary checks (e.g., Cellular Network Time) to prevent spoofing.
3.  **Distribution**:
    *   **Ethernet**: The T-Box acts as the **gPTP Grandmaster**. The Central Gateway acts as a Time Bridge/Transparent Clock.
    *   **CAN**: The T-Box broadcasts Global Time messages (SYNC/FUP) to the secure CAN bus for the Door ECUs. This ensures unlock commands (which are timestamped) are processed synchronously and prevents replay attacks.

## 6. Key Assets & Threats
*   **Primary Asset: Trusted Time**: Manipulation of time can defeat certificate validation (TTL), replay protection, and log integrity.
*   **Threats**:
    *   **GNSS Spoofing**: Injecting false time to expire keys or facilitate replay.
    *   **Time-Delay Attacks**: Delaying PTP packets to confuse control loops.
