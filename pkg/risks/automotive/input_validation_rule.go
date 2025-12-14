package automotive

import (
	"github.com/threagile/threagile/pkg/types"
)

type MissingInputValidationRule struct{}

func (r *MissingInputValidationRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "missing-input-validation",
		Title:       "Missing Input Validation (CWE-20)",
		Description: "The asset appears to accept external input (ingress, diagnostics, API) but does not have explicit input validation controls documented.",
		Impact:      "Lack of input validation can lead to injection attacks (SQLi, Command Injection), buffer overflows, and crash scenarios (DoS).",
		Function:    types.Development,
		STRIDE:      types.Tampering,
		Action:      "Implement Strict Input Validation",
		Mitigation:  "Validate all inputs against a strict allow-list. Sanitize data at trust boundaries.",
		Check:       "Are all external inputs validated before processing?",
		CWE:         20,
	}
}

func (r *MissingInputValidationRule) SupportedTags() []string {
	return []string{"ingress", "diagnostics", "web", "api", "gateway"}
}

func (r *MissingInputValidationRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, technicalAsset := range input.TechnicalAssets {
		if technicalAsset.OutOfScope {
			continue
		}
		// Check for potential ingress points
		if technicalAsset.IsTaggedWithAny("ingress", "diagnostics", "web", "api", "gateway") {
			risk := &types.Risk{
				CategoryId:                   r.Category().ID,
				Severity:                     types.HighSeverity,
				ExploitationLikelihood:       types.Likely,
				ExploitationImpact:           types.HighImpact,
				Title:                        "<b>Missing Input Validation</b> at <b>" + technicalAsset.Title + "</b>",
				MostRelevantTechnicalAssetId: technicalAsset.Id,
				DataBreachProbability:        types.Probable,
				DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
			}
			// Check for mitigation
			if technicalAsset.IsTaggedWithAny("input-validation", "waf") {
				risk.RiskStatus = types.Mitigated
			}
			risks = append(risks, risk)
		}
	}
	return risks, nil
}
