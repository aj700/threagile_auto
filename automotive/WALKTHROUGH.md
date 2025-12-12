# Automotive Starter Kit Walkthrough

I have created a custom Automotive Starter Kit for Threagile, enabling threat modeling of vehicle architectures.

## Created Files

### 1. Custom Technologies (`automotive/technologies.yaml`)
Defines domain-specific assets:
-   **Electronic Control Unit (ECU)**: Base controller type.
-   **CAN Bus**: Unencrypted, broadcast network protocol.
-   **Automotive Gateway**: Central security component.
-   **Telematics Control Unit (TCU)**: External connectivity interface.
-   **In-Vehicle Infotainment (IVI)**: User-facing system.

### 2. Sample Model (`automotive/automotive-model.yaml`)
A "Connected Car" architecture featuring:
-   **Flow**: OTA Update (Cloud -> TCU -> Gateway -> Engine ECU).
-   **Assets**: Firmware, GPS Data.
-   **Trust Boundary**: Physical Vehicle Boundary.

## Verification

I successfully executed Threagile using the custom kit:

```bash
$HOME/go_dist/go/bin/go run cmd/threagile/main.go analyze-model \
  --model automotive/automotive-model.yaml \
  --technology automotive/technologies.yaml \
  --output automotive-output \
  --app-dir . \
  --background report/template/background.pdf \
  --skip-risks-excel --skip-tags-excel
```

> **Note**: Excel generation was skipped due to a known issue with custom technology names in the current version, but the **PDF Report**, **data flow diagrams**, and **JSON exports** were generated successfully, correctly identifying risks like "Unencrypted Communication" on the CAN bus.
