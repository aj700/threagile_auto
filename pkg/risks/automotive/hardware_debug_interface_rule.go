package automotive

import (
	"github.com/threagile/threagile/pkg/types"
)

type UnsecuredHardwareDebugPortRule struct{}

func (r *UnsecuredHardwareDebugPortRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "unsecured-hardware-debug-port",
		Title:       "Unsecured Hardware Debug Interface (JTAG/SWD)",
		Description: "Hardware debug interfaces like JTAG or SWD are open and not secured. These ports provide low-level access to the device during development but can be used by attackers to extract firmware, dump memory, or hijack execution flow in production.",
		Impact:      "Full control over the device execution flow and firmware extraction. An attacker with physical access could reverse engineer the firmware, extract secrets (keys, certificates), or implant malware.",
		Function:    types.Operations,
		STRIDE:      types.ElevationOfPrivilege,
		Action:      "Hardware Hardening",
		Mitigation:  "Permanently disable debug interfaces (e.g. via eFuse) before production. If debug access is required for field diagnostics, implement strong cryptographic authentication (e.g. Challenge-Response) to unlock the JTAG port.",
		Check:       "Verify if JTAG/SWD ports are accessible on the PCB and if they are electronically disabled or password protected.",
		CWE:         1260, // CWE-1260: Improper Handling of Overlap Between Protected Memory Ranges (closest relative for debug access) or CWE-1191: On-Chip Debug and Test Interface With Improper Access Control
		ASVS:        "V1.1.2",
		CheatSheet:  "https://cheatsheetseries.owasp.org/cheatsheets/Embedded_Application_Security_Cheat_Sheet.html",
	}
}

func (r *UnsecuredHardwareDebugPortRule) SupportedTags() []string {
	return []string{"hardware", "ecu", "microcontroller", "device"}
}

func (r *UnsecuredHardwareDebugPortRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, technicalAsset := range input.TechnicalAssets {
		// Check if asset is of relevant type
		if technicalAsset.IsTaggedWithAny(r.SupportedTags()...) {
			risk := &types.Risk{
				CategoryId:                   r.Category().ID,
				Severity:                     types.CriticalSeverity,
				ExploitationLikelihood:       types.Likely,
				ExploitationImpact:           types.VeryHighImpact,
				Title:                        "<b>Unsecured Hardware Debug Port (JTAG/SWD)</b> on " + technicalAsset.Title,
				MostRelevantTechnicalAssetId: technicalAsset.Id,
				DataBreachProbability:        types.Probable,
				DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
			}
			// Check if JTAG is locked or no debug exists
			if technicalAsset.IsTaggedWithAny("jtag_locked", "no_debug") {
				risk.RiskStatus = types.Mitigated
			}
			risks = append(risks, risk)
		}
	}
	return risks, nil
}
