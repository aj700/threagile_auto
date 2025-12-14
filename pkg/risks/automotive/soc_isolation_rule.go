package automotive

import (
	"github.com/threagile/threagile/pkg/types"
)

type ImproperSoCIsolationRule struct{}

func (r *ImproperSoCIsolationRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "unsecured-soc-isolation",
		Title:       "Improper SoC Isolation (CWE-1189)",
		Description: "The System-on-Chip (SoC) does not appear to have sufficient isolation mechanisms (e.g. hardware virtualization, TrustZone, or physical separation) to prevent shared resource corruption between mixed-criticality domains.",
		Impact:      "Lack of isolation can allow a compromised non-safety core (e.g. QM / Linux) to interfere with safety-critical functions (ASIL-D), leading to loss of vehicle control.",
		Function:    types.Architecture,
		STRIDE:      types.Tampering,
		Action:      "Implement Hardware Enforced Isolation",
		Mitigation:  "Use hardware virtualization extensions, memory protection units (MPU), or physical core separation.",
		Check:       "Does the SoC host mixed-criticality workloads without certified isolation?",
		CWE:         1189,
	}
}

func (r *ImproperSoCIsolationRule) SupportedTags() []string {
	return []string{"hardware", "gateway"}
}

func (r *ImproperSoCIsolationRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, technicalAsset := range input.TechnicalAssets {
		// Target Gateway SoCs (which are usually hardware and handle mixed traffic)
		if technicalAsset.IsTaggedWithAny("hardware") && technicalAsset.IsTaggedWithAny("gateway") {
			risk := &types.Risk{
				CategoryId:                   r.Category().ID,
				Severity:                     types.CriticalSeverity,
				ExploitationLikelihood:       types.Likely,
				ExploitationImpact:           types.VeryHighImpact,
				Title:                        "<b>Improper SoC Isolation</b> at <b>" + technicalAsset.Title + "</b>",
				MostRelevantTechnicalAssetId: technicalAsset.Id,
				DataBreachProbability:        types.Probable,
				DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
			}
			// Check for mitigation tags
			if technicalAsset.IsTaggedWithAny("isolation", "virtualization", "partitioning") {
				risk.RiskStatus = types.Mitigated
			}
			risks = append(risks, risk)
		}
	}
	return risks, nil
}
