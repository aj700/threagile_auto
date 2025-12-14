package automotive

import (
	"github.com/threagile/threagile/pkg/types"
)

// This logic applies the risk to ANY technical asset tagged with "automotive"
// It serves as a comprehensive catalog check.

type RiskTS000 struct{}

func (r *RiskTS000) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-s-000",
		Title:       "Spoofing",
		Description: "Spoofing (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTS000) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTS000) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTS000) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Spoofing</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTS001 struct{}

func (r *RiskTS001) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-s-001",
		Title:       "Identity spoofing to an asset using a login with password",
		Description: "Identity spoofing to an asset using a login with password (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTS001) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTS001) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTS001) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Identity spoofing to an asset using a login with password</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTS004 struct{}

func (r *RiskTS004) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-s-004",
		Title:       "Software package are not from an authorized source",
		Description: "Software package are not from an authorized source (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTS004) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTS004) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTS004) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Software package are not from an authorized source</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTS005 struct{}

func (r *RiskTS005) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-s-005",
		Title:       "Hardware components are not from an authorized source",
		Description: "Hardware components are not from an authorized source (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTS005) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTS005) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTS005) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Hardware components are not from an authorized source</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTS006 struct{}

func (r *RiskTS006) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-s-006",
		Title:       "Spoofing of information externally generated",
		Description: "Spoofing of information externally generated (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTS006) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTS006) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTS006) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Spoofing of information externally generated</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTS007 struct{}

func (r *RiskTS007) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-s-007",
		Title:       "Spoofing of information internally generated",
		Description: "Spoofing of information internally generated (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTS007) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTS007) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTS007) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Spoofing of information internally generated</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTS008 struct{}

func (r *RiskTS008) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-s-008",
		Title:       "Location Spoofing",
		Description: "Location Spoofing (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTS008) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTS008) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTS008) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Location Spoofing</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTS099 struct{}

func (r *RiskTS099) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-s-099",
		Title:       "Exploitation of spoofing weaknesses",
		Description: "Exploitation of spoofing weaknesses (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTS099) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTS099) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTS099) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Exploitation of spoofing weaknesses</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTT000 struct{}

func (r *RiskTT000) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-t-000",
		Title:       "Tampering",
		Description: "Tampering (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTT000) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTT000) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTT000) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Tampering</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTT001 struct{}

func (r *RiskTT001) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-t-001",
		Title:       "Manipulation of data from external (transfer)",
		Description: "Manipulation of data from external (transfer) (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTT001) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTT001) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTT001) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Manipulation of data from external (transfer)</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTT002 struct{}

func (r *RiskTT002) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-t-002",
		Title:       "Manipulation of data from internal (transfer)",
		Description: "Manipulation of data from internal (transfer) (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTT002) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTT002) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTT002) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Manipulation of data from internal (transfer)</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTT003 struct{}

func (r *RiskTT003) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-t-003",
		Title:       "Manipulation (computation)",
		Description: "Manipulation (computation) (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTT003) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTT003) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTT003) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Manipulation (computation)</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTT004 struct{}

func (r *RiskTT004) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-t-004",
		Title:       "Manipulation (memory)",
		Description: "Manipulation (memory) (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTT004) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTT004) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTT004) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Manipulation (memory)</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTT005 struct{}

func (r *RiskTT005) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-t-005",
		Title:       "Manipulation of Code",
		Description: "Manipulation of Code (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTT005) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTT005) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTT005) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Manipulation of Code</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTT006 struct{}

func (r *RiskTT006) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-t-006",
		Title:       "Parameter Injection",
		Description: "Parameter Injection (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTT006) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTT006) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTT006) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Parameter Injection</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTT007 struct{}

func (r *RiskTT007) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-t-007",
		Title:       "Code Injection",
		Description: "Code Injection (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTT007) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTT007) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTT007) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Code Injection</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTT008 struct{}

func (r *RiskTT008) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-t-008",
		Title:       "Command Injection",
		Description: "Command Injection (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTT008) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTT008) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTT008) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Command Injection</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTT010 struct{}

func (r *RiskTT010) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-t-010",
		Title:       "Replay attack",
		Description: "Replay attack (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTT010) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTT010) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTT010) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Replay attack</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTT011 struct{}

func (r *RiskTT011) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-t-011",
		Title:       "Configuration/Settings Manipulation",
		Description: "Configuration/Settings Manipulation (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTT011) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTT011) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTT011) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Configuration/Settings Manipulation</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTT012 struct{}

func (r *RiskTT012) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-t-012",
		Title:       "Protocol Manipulation",
		Description: "Protocol Manipulation (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTT012) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTT012) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTT012) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Protocol Manipulation</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTT099 struct{}

func (r *RiskTT099) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-t-099",
		Title:       "Exploitation of tampering weaknesses",
		Description: "Exploitation of tampering weaknesses (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTT099) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTT099) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTT099) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Exploitation of tampering weaknesses</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTR000 struct{}

func (r *RiskTR000) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-r-000",
		Title:       "Repudiation",
		Description: "Repudiation (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTR000) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTR000) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTR000) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Repudiation</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTR099 struct{}

func (r *RiskTR099) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-r-099",
		Title:       "Exploitation of repudiation weaknesses",
		Description: "Exploitation of repudiation weaknesses (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTR099) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTR099) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTR099) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Exploitation of repudiation weaknesses</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTI000 struct{}

func (r *RiskTI000) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-i-000",
		Title:       "Information Disclosure",
		Description: "Information Disclosure (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTI000) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTI000) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTI000) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Information Disclosure</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTI001 struct{}

func (r *RiskTI001) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-i-001",
		Title:       "Interception",
		Description: "Interception (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTI001) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTI001) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTI001) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Interception</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTI008 struct{}

func (r *RiskTI008) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-i-008",
		Title:       "Interception of Internal Data",
		Description: "Interception of Internal Data (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTI008) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTI008) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTI008) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Interception of Internal Data</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTI009 struct{}

func (r *RiskTI009) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-i-009",
		Title:       "Interception of External Data",
		Description: "Interception of External Data (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTI009) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTI009) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTI009) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Interception of External Data</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTI005 struct{}

func (r *RiskTI005) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-i-005",
		Title:       "Unintended Disclosure of PII Data",
		Description: "Unintended Disclosure of PII Data (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTI005) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTI005) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTI005) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Unintended Disclosure of PII Data</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTI006 struct{}

func (r *RiskTI006) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-i-006",
		Title:       "Software/Firmware Disclosure",
		Description: "Software/Firmware Disclosure (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTI006) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTI006) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTI006) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Software/Firmware Disclosure</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTI007 struct{}

func (r *RiskTI007) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-i-007",
		Title:       "Functional Observation",
		Description: "Functional Observation (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTI007) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTI007) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTI007) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Functional Observation</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTI002 struct{}

func (r *RiskTI002) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-i-002",
		Title:       "Reverse Engineering",
		Description: "Reverse Engineering (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTI002) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTI002) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTI002) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Reverse Engineering</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTD000 struct{}

func (r *RiskTD000) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-d-000",
		Title:       "Denial of Service",
		Description: "Denial of Service (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTD000) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTD000) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTD000) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Denial of Service</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTD001 struct{}

func (r *RiskTD001) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-d-001",
		Title:       "Disrupt transmission (wireless)",
		Description: "Disrupt transmission (wireless) (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTD001) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTD001) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTD001) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Disrupt transmission (wireless)</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTD002 struct{}

func (r *RiskTD002) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-d-002",
		Title:       "Disrupt transmission (wired)",
		Description: "Disrupt transmission (wired) (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTD002) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTD002) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTD002) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Disrupt transmission (wired)</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTD003 struct{}

func (r *RiskTD003) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-d-003",
		Title:       "Disrupt computation",
		Description: "Disrupt computation (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTD003) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTD003) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTD003) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Disrupt computation</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTD004 struct{}

func (r *RiskTD004) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-d-004",
		Title:       "Flooding",
		Description: "Flooding (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTD004) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTD004) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTD004) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Flooding</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTD005 struct{}

func (r *RiskTD005) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-d-005",
		Title:       "Jamming",
		Description: "Jamming (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTD005) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTD005) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTD005) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Jamming</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTD006 struct{}

func (r *RiskTD006) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-d-006",
		Title:       "GPS jamming",
		Description: "GPS jamming (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTD006) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTD006) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTD006) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>GPS jamming</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTD007 struct{}

func (r *RiskTD007) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-d-007",
		Title:       "Excessive Allocation of Resources",
		Description: "Excessive Allocation of Resources (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTD007) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTD007) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTD007) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Excessive Allocation of Resources</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTD008 struct{}

func (r *RiskTD008) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-d-008",
		Title:       "Resource Leak Exposure and Depletion",
		Description: "Resource Leak Exposure and Depletion (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTD008) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTD008) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTD008) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Resource Leak Exposure and Depletion</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTE000 struct{}

func (r *RiskTE000) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-e-000",
		Title:       "Elevation of privilege",
		Description: "Elevation of privilege (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTE000) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTE000) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTE000) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Elevation of privilege</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTE001 struct{}

func (r *RiskTE001) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-e-001",
		Title:       "Privilege escalation (access)",
		Description: "Privilege escalation (access) (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTE001) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTE001) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTE001) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Privilege escalation (access)</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTE002 struct{}

func (r *RiskTE002) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-e-002",
		Title:       "Privilege escalation (processing)",
		Description: "Privilege escalation (processing) (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTE002) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTE002) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTE002) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Privilege escalation (processing)</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTE003 struct{}

func (r *RiskTE003) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-e-003",
		Title:       "Privilege abuse",
		Description: "Privilege abuse (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTE003) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTE003) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTE003) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Privilege abuse</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTE004 struct{}

func (r *RiskTE004) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-e-004",
		Title:       "Man-in-the-Middle Attack",
		Description: "Man-in-the-Middle Attack (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTE004) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTE004) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTE004) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Man-in-the-Middle Attack</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTE005 struct{}

func (r *RiskTE005) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-e-005",
		Title:       "Development Channels Open",
		Description: "Development Channels Open (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTE005) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTE005) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTE005) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Development Channels Open</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTC1 struct{}

func (r *RiskTC1) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-tc-1",
		Title:       "Non-Repudiation Mechanism (Software) Bypass ",
		Description: "Non-Repudiation Mechanism (Software) Bypass  (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTC1) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTC1) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTC1) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Non-Repudiation Mechanism (Software) Bypass </b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTM001 struct{}

func (r *RiskTM001) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-m-001",
		Title:       "Manipulate Environment",
		Description: "Manipulate Environment (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTM001) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTM001) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTM001) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Manipulate Environment</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTM002 struct{}

func (r *RiskTM002) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-m-002",
		Title:       "Adversarial Machine Learning",
		Description: "Adversarial Machine Learning (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTM002) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTM002) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTM002) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Adversarial Machine Learning</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTM003 struct{}

func (r *RiskTM003) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-m-003",
		Title:       "Analog Sensor Attacks",
		Description: "Analog Sensor Attacks (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTM003) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTM003) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTM003) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Analog Sensor Attacks</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTM004 struct{}

func (r *RiskTM004) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-m-004",
		Title:       "Downgrade to Insecure Protocols",
		Description: "Downgrade to Insecure Protocols (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTM004) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTM004) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTM004) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Downgrade to Insecure Protocols</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTM005 struct{}

func (r *RiskTM005) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-m-005",
		Title:       "Jamming or Denial of Service",
		Description: "Jamming or Denial of Service (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTM005) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTM005) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTM005) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Jamming or Denial of Service</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTM006 struct{}

func (r *RiskTM006) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-m-006",
		Title:       "Manipulate Communication",
		Description: "Manipulate Communication (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTM006) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTM006) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTM006) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Manipulate Communication</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTM007 struct{}

func (r *RiskTM007) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-m-007",
		Title:       "Relay Communications",
		Description: "Relay Communications (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTM007) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTM007) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTM007) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Relay Communications</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTM008 struct{}

func (r *RiskTM008) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-m-008",
		Title:       "Rogue Cellular Base Station",
		Description: "Rogue Cellular Base Station (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTM008) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTM008) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTM008) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Rogue Cellular Base Station</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTM009 struct{}

func (r *RiskTM009) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-m-009",
		Title:       "Rogue Wi-Fi Access Point",
		Description: "Rogue Wi-Fi Access Point (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTM009) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTM009) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTM009) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Rogue Wi-Fi Access Point</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTIA001 struct{}

func (r *RiskTIA001) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-ia-001",
		Title:       "Initial Access",
		Description: "Initial Access (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTIA001) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTIA001) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTIA001) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Initial Access</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTIA002 struct{}

func (r *RiskTIA002) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-ia-002",
		Title:       "Browser Compromise",
		Description: "Browser Compromise (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTIA002) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTIA002) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTIA002) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Browser Compromise</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTIA003 struct{}

func (r *RiskTIA003) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-ia-003",
		Title:       "Exploit Via Radio Interface",
		Description: "Exploit Via Radio Interface (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTIA003) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTIA003) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTIA003) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Exploit Via Radio Interface</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTIA004 struct{}

func (r *RiskTIA004) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-ia-004",
		Title:       "Exploit Via Removable Media",
		Description: "Exploit Via Removable Media (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTIA004) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTIA004) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTIA004) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Exploit Via Removable Media</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTIA005 struct{}

func (r *RiskTIA005) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-ia-005",
		Title:       "Malicious App",
		Description: "Malicious App (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTIA005) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTIA005) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTIA005) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Malicious App</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTIA006 struct{}

func (r *RiskTIA006) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-ia-006",
		Title:       "Phishing",
		Description: "Phishing (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTIA006) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTIA006) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTIA006) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Phishing</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTIA007 struct{}

func (r *RiskTIA007) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-ia-007",
		Title:       "Physical Modification",
		Description: "Physical Modification (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTIA007) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTIA007) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTIA007) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Physical Modification</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTIA008 struct{}

func (r *RiskTIA008) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-ia-008",
		Title:       "Supply Chain Compromise",
		Description: "Supply Chain Compromise (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTIA008) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTIA008) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTIA008) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Supply Chain Compromise</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTEx001 struct{}

func (r *RiskTEx001) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-ex-001",
		Title:       "Execution",
		Description: "Execution (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTEx001) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTEx001) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTEx001) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Execution</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTEx002 struct{}

func (r *RiskTEx002) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-ex-002",
		Title:       "Command and Scripting Interpreter",
		Description: "Command and Scripting Interpreter (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTEx002) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTEx002) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTEx002) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Command and Scripting Interpreter</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTEx003 struct{}

func (r *RiskTEx003) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-ex-003",
		Title:       "Native API",
		Description: "Native API (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTEx003) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTEx003) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTEx003) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Native API</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTP001 struct{}

func (r *RiskTP001) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-p-001",
		Title:       "Persistence",
		Description: "Persistence (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTP001) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTP001) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTP001) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Persistence</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTP002 struct{}

func (r *RiskTP002) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-p-002",
		Title:       "Abuse UDS For Persistence",
		Description: "Abuse UDS For Persistence (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTP002) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTP002) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTP002) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Abuse UDS For Persistence</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTP003 struct{}

func (r *RiskTP003) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-p-003",
		Title:       "Disable Software Update",
		Description: "Disable Software Update (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTP003) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTP003) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTP003) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Disable Software Update</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTP004 struct{}

func (r *RiskTP004) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-p-004",
		Title:       "Modify OS Kernel, Boot Partition, or System Partition",
		Description: "Modify OS Kernel, Boot Partition, or System Partition (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTP004) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTP004) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTP004) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Modify OS Kernel, Boot Partition, or System Partition</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTP005 struct{}

func (r *RiskTP005) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-p-005",
		Title:       "Modify TEE",
		Description: "Modify TEE (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTP005) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTP005) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTP005) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Modify TEE</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTPe001 struct{}

func (r *RiskTPe001) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-pe-001",
		Title:       "Privilege Escalation",
		Description: "Privilege Escalation (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTPe001) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTPe001) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTPe001) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Privilege Escalation</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTPe002 struct{}

func (r *RiskTPe002) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-pe-002",
		Title:       "Abuse Elevation Control Mechanism",
		Description: "Abuse Elevation Control Mechanism (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTPe002) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTPe002) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTPe002) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Abuse Elevation Control Mechanism</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTPe003 struct{}

func (r *RiskTPe003) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-pe-003",
		Title:       "Exploit Co-Located Computing Device for Privilege Escalation",
		Description: "Exploit Co-Located Computing Device for Privilege Escalation (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTPe003) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTPe003) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTPe003) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Exploit Co-Located Computing Device for Privilege Escalation</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTPe004 struct{}

func (r *RiskTPe004) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-pe-004",
		Title:       "Exploit OS Vulnerability",
		Description: "Exploit OS Vulnerability (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTPe004) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTPe004) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTPe004) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Exploit OS Vulnerability</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTPe005 struct{}

func (r *RiskTPe005) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-pe-005",
		Title:       "Exploit TEE Vulnerability",
		Description: "Exploit TEE Vulnerability (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTPe005) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTPe005) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTPe005) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Exploit TEE Vulnerability</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTPe006 struct{}

func (r *RiskTPe006) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-pe-006",
		Title:       "Hardware Fault Injection",
		Description: "Hardware Fault Injection (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTPe006) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTPe006) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			// Check for mitigation: CWE-1256 (tamper-protection)
			risk := r.createRisk(parsedModel, technicalAsset)
			if technicalAsset.IsTaggedWithAny("tamper-protection", "hardware-hardening") {
				risk.RiskStatus = types.Mitigated
			}
			risks = append(risks, risk)
		}
	}
	return risks, nil
}
func (r *RiskTPe006) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Hardware Fault Injection</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTPe007 struct{}

func (r *RiskTPe007) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-pe-007",
		Title:       "Process Injection",
		Description: "Process Injection (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTPe007) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTPe007) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTPe007) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Process Injection</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTPe008 struct{}

func (r *RiskTPe008) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-pe-008",
		Title:       "Reporgram Co-Located Computing Device for Privilege Escalation",
		Description: "Reporgram Co-Located Computing Device for Privilege Escalation (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTPe008) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTPe008) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTPe008) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Reporgram Co-Located Computing Device for Privilege Escalation</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTDe001 struct{}

func (r *RiskTDe001) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-de-001",
		Title:       "Defense Evasion",
		Description: "Defense Evasion (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTDe001) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTDe001) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTDe001) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Defense Evasion</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTDe002 struct{}

func (r *RiskTDe002) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-de-002",
		Title:       "Bypass Code Signing",
		Description: "Bypass Code Signing (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTDe002) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTDe002) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTDe002) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Bypass Code Signing</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTDe003 struct{}

func (r *RiskTDe003) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-de-003",
		Title:       "Disable Firewall",
		Description: "Disable Firewall (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTDe003) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTDe003) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTDe003) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Disable Firewall</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTDe004 struct{}

func (r *RiskTDe004) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-de-004",
		Title:       "Bypass UDS Security Access",
		Description: "Bypass UDS Security Access (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTDe004) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTDe004) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTDe004) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Bypass UDS Security Access</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTDe005 struct{}

func (r *RiskTDe005) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-de-005",
		Title:       "Bypass Mandatory Access Control",
		Description: "Bypass Mandatory Access Control (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTDe005) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTDe005) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTDe005) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Bypass Mandatory Access Control</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTCa001 struct{}

func (r *RiskTCa001) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-ca-001",
		Title:       "Credential Access",
		Description: "Credential Access (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTCa001) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTCa001) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTCa001) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Credential Access</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTCa002 struct{}

func (r *RiskTCa002) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-ca-002",
		Title:       "Capture SMS Message",
		Description: "Capture SMS Message (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTCa002) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTCa002) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTCa002) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Capture SMS Message</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTCa003 struct{}

func (r *RiskTCa003) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-ca-003",
		Title:       "Exploiit TEE Vulnerability",
		Description: "Exploiit TEE Vulnerability (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTCa003) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTCa003) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTCa003) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Exploiit TEE Vulnerability</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTCa004 struct{}

func (r *RiskTCa004) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-ca-004",
		Title:       "Input Capture",
		Description: "Input Capture (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTCa004) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTCa004) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTCa004) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Input Capture</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTCa005 struct{}

func (r *RiskTCa005) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-ca-005",
		Title:       "Input Prompt",
		Description: "Input Prompt (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTCa005) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTCa005) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTCa005) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Input Prompt</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTCa006 struct{}

func (r *RiskTCa006) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-ca-006",
		Title:       "Network Sniffing",
		Description: "Network Sniffing (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTCa006) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTCa006) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTCa006) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Network Sniffing</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTCa007 struct{}

func (r *RiskTCa007) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-ca-007",
		Title:       "OS Credential Dumping",
		Description: "OS Credential Dumping (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTCa007) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTCa007) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTCa007) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>OS Credential Dumping</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTCa008 struct{}

func (r *RiskTCa008) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-ca-008",
		Title:       "Unsecured Credentials",
		Description: "Unsecured Credentials (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTCa008) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTCa008) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTCa008) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Unsecured Credentials</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTCa009 struct{}

func (r *RiskTCa009) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-ca-009",
		Title:       "URI Hijacking",
		Description: "URI Hijacking (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTCa009) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTCa009) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTCa009) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>URI Hijacking</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTDi001 struct{}

func (r *RiskTDi001) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-di-001",
		Title:       "Discovery",
		Description: "Discovery (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTDi001) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTDi001) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTDi001) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Discovery</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTDi002 struct{}

func (r *RiskTDi002) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-di-002",
		Title:       "File and Directory Discovery",
		Description: "File and Directory Discovery (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTDi002) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTDi002) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTDi002) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>File and Directory Discovery</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTDi003 struct{}

func (r *RiskTDi003) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-di-003",
		Title:       "Location Tracking",
		Description: "Location Tracking (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTDi003) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTDi003) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTDi003) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Location Tracking</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTDi004 struct{}

func (r *RiskTDi004) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-di-004",
		Title:       "Network Service Scanning",
		Description: "Network Service Scanning (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTDi004) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTDi004) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTDi004) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Network Service Scanning</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTDi005 struct{}

func (r *RiskTDi005) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-di-005",
		Title:       "Process Discovery",
		Description: "Process Discovery (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTDi005) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTDi005) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTDi005) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Process Discovery</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTDi006 struct{}

func (r *RiskTDi006) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-di-006",
		Title:       "Software Discovery",
		Description: "Software Discovery (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTDi006) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTDi006) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTDi006) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Software Discovery</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTDi007 struct{}

func (r *RiskTDi007) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-di-007",
		Title:       "System Information Discovery",
		Description: "System Information Discovery (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTDi007) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTDi007) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTDi007) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>System Information Discovery</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTDi008 struct{}

func (r *RiskTDi008) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-di-008",
		Title:       "System Network Configuration Discovery",
		Description: "System Network Configuration Discovery (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTDi008) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTDi008) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTDi008) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>System Network Configuration Discovery</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTDi009 struct{}

func (r *RiskTDi009) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-di-009",
		Title:       "System Network Connections Discovery",
		Description: "System Network Connections Discovery (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTDi009) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTDi009) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTDi009) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>System Network Connections Discovery</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTLm001 struct{}

func (r *RiskTLm001) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-lm-001",
		Title:       "Lateral Movement",
		Description: "Lateral Movement (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTLm001) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTLm001) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTLm001) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Lateral Movement</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTLm002 struct{}

func (r *RiskTLm002) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-lm-002",
		Title:       "Abuse UDS for Lateral Movement",
		Description: "Abuse UDS for Lateral Movement (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTLm002) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTLm002) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTLm002) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Abuse UDS for Lateral Movement</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTLm003 struct{}

func (r *RiskTLm003) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-lm-003",
		Title:       "Bridge Vehicle Networks",
		Description: "Bridge Vehicle Networks (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTLm003) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTLm003) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTLm003) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Bridge Vehicle Networks</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTLm004 struct{}

func (r *RiskTLm004) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-lm-004",
		Title:       "Exploit ECU for Lateral Movement",
		Description: "Exploit ECU for Lateral Movement (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTLm004) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTLm004) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTLm004) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Exploit ECU for Lateral Movement</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTLm005 struct{}

func (r *RiskTLm005) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-lm-005",
		Title:       "Remote Services",
		Description: "Remote Services (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTLm005) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTLm005) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTLm005) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Remote Services</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTLm006 struct{}

func (r *RiskTLm006) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-lm-006",
		Title:       "Reprogram ECU for Lateral Movement",
		Description: "Reprogram ECU for Lateral Movement (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTLm006) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTLm006) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTLm006) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Reprogram ECU for Lateral Movement</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTCo001 struct{}

func (r *RiskTCo001) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-co-001",
		Title:       "Collection",
		Description: "Collection (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTCo001) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTCo001) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTCo001) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Collection</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTCo002 struct{}

func (r *RiskTCo002) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-co-002",
		Title:       "Abuse UDS for Collection",
		Description: "Abuse UDS for Collection (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTCo002) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTCo002) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTCo002) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Abuse UDS for Collection</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTCo003 struct{}

func (r *RiskTCo003) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-co-003",
		Title:       "Access Personal Information",
		Description: "Access Personal Information (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTCo003) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTCo003) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTCo003) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Access Personal Information</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTCo004 struct{}

func (r *RiskTCo004) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-co-004",
		Title:       "Access Vehicle Telemetry",
		Description: "Access Vehicle Telemetry (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTCo004) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTCo004) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTCo004) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Access Vehicle Telemetry</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTCo005 struct{}

func (r *RiskTCo005) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-co-005",
		Title:       "Capture Camera or Audio",
		Description: "Capture Camera or Audio (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTCo005) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTCo005) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTCo005) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Capture Camera or Audio</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTCo006 struct{}

func (r *RiskTCo006) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-co-006",
		Title:       "Capture SMS Message",
		Description: "Capture SMS Message (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTCo006) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTCo006) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTCo006) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Capture SMS Message</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTCo007 struct{}

func (r *RiskTCo007) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-co-007",
		Title:       "Data from Local System",
		Description: "Data from Local System (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTCo007) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTCo007) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTCo007) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Data from Local System</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTCo008 struct{}

func (r *RiskTCo008) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-co-008",
		Title:       "Input Capture",
		Description: "Input Capture (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTCo008) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTCo008) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTCo008) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Input Capture</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTCo009 struct{}

func (r *RiskTCo009) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-co-009",
		Title:       "Location Tracking",
		Description: "Location Tracking (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTCo009) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTCo009) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTCo009) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Location Tracking</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTCo010 struct{}

func (r *RiskTCo010) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-co-010",
		Title:       "Network Information Discovery",
		Description: "Network Information Discovery (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTCo010) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTCo010) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTCo010) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Network Information Discovery</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTCo011 struct{}

func (r *RiskTCo011) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-co-011",
		Title:       "Network Traffic Capture or Redirection",
		Description: "Network Traffic Capture or Redirection (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTCo011) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTCo011) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTCo011) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Network Traffic Capture or Redirection</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTCo012 struct{}

func (r *RiskTCo012) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-co-012",
		Title:       "Screen Capture",
		Description: "Screen Capture (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTCo012) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTCo012) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTCo012) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Screen Capture</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTCac001 struct{}

func (r *RiskTCac001) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-cac-001",
		Title:       "Command and Control",
		Description: "Command and Control (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTCac001) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTCac001) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTCac001) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Command and Control</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTCac002 struct{}

func (r *RiskTCac002) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-cac-002",
		Title:       "Aftermarket Customer, or Dealer Equipment",
		Description: "Aftermarket Customer, or Dealer Equipment (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTCac002) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTCac002) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTCac002) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Aftermarket Customer, or Dealer Equipment</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTCac003 struct{}

func (r *RiskTCac003) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-cac-003",
		Title:       "Cellular Communication",
		Description: "Cellular Communication (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTCac003) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTCac003) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTCac003) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Cellular Communication</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTCac004 struct{}

func (r *RiskTCac004) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-cac-004",
		Title:       "Internet Communication",
		Description: "Internet Communication (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTCac004) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTCac004) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTCac004) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Internet Communication</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTCac005 struct{}

func (r *RiskTCac005) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-cac-005",
		Title:       "Recieve-Only Communication Channel",
		Description: "Recieve-Only Communication Channel (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTCac005) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTCac005) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTCac005) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Recieve-Only Communication Channel</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTCac006 struct{}

func (r *RiskTCac006) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-cac-006",
		Title:       "Short Range Wireless Communication",
		Description: "Short Range Wireless Communication (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTCac006) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTCac006) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTCac006) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Short Range Wireless Communication</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTCac007 struct{}

func (r *RiskTCac007) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-cac-007",
		Title:       "Standard Cryptographic Protocol",
		Description: "Standard Cryptographic Protocol (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTCac007) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTCac007) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTCac007) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Standard Cryptographic Protocol</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTExf001 struct{}

func (r *RiskTExf001) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-exf-001",
		Title:       "Exfiltration",
		Description: "Exfiltration (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTExf001) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTExf001) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTExf001) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Exfiltration</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTExf002 struct{}

func (r *RiskTExf002) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-exf-002",
		Title:       "Aftermarket, Customer, or Dealer Equipment",
		Description: "Aftermarket, Customer, or Dealer Equipment (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTExf002) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTExf002) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTExf002) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Aftermarket, Customer, or Dealer Equipment</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTExf003 struct{}

func (r *RiskTExf003) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-exf-003",
		Title:       "Cellular Communication",
		Description: "Cellular Communication (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTExf003) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTExf003) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTExf003) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Cellular Communication</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTExf004 struct{}

func (r *RiskTExf004) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-exf-004",
		Title:       "Internet Communication",
		Description: "Internet Communication (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTExf004) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTExf004) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTExf004) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Internet Communication</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTExf005 struct{}

func (r *RiskTExf005) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-exf-005",
		Title:       "Removeable Media",
		Description: "Removeable Media (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTExf005) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTExf005) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTExf005) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Removeable Media</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTExf006 struct{}

func (r *RiskTExf006) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-exf-006",
		Title:       "Short Range Wireless Communication",
		Description: "Short Range Wireless Communication (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTExf006) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTExf006) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTExf006) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Short Range Wireless Communication</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTExf007 struct{}

func (r *RiskTExf007) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-exf-007",
		Title:       "Standard Cryptographic Protocol",
		Description: "Standard Cryptographic Protocol (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTExf007) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTExf007) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTExf007) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Standard Cryptographic Protocol</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTAvf001 struct{}

func (r *RiskTAvf001) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-avf-001",
		Title:       "Affect Vehicle Function",
		Description: "Affect Vehicle Function (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTAvf001) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTAvf001) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTAvf001) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Affect Vehicle Function</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTAvf002 struct{}

func (r *RiskTAvf002) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-avf-002",
		Title:       "Adversarial Machine Learning",
		Description: "Adversarial Machine Learning (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTAvf002) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTAvf002) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTAvf002) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Adversarial Machine Learning</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTAvf003 struct{}

func (r *RiskTAvf003) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-avf-003",
		Title:       "Abuse UDS for Affecting Vehicle Function",
		Description: "Abuse UDS for Affecting Vehicle Function (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTAvf003) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTAvf003) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTAvf003) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Abuse UDS for Affecting Vehicle Function</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTAvf004 struct{}

func (r *RiskTAvf004) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-avf-004",
		Title:       "CAN Bus Denial of Service",
		Description: "CAN Bus Denial of Service (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTAvf004) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTAvf004) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTAvf004) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>CAN Bus Denial of Service</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTAvf005 struct{}

func (r *RiskTAvf005) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-avf-005",
		Title:       "Local Function",
		Description: "Local Function (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTAvf005) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTAvf005) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTAvf005) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Local Function</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTAvf006 struct{}

func (r *RiskTAvf006) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-avf-006",
		Title:       "Modify Bus Message",
		Description: "Modify Bus Message (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTAvf006) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTAvf006) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTAvf006) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Modify Bus Message</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

type RiskTAvf007 struct{}

func (r *RiskTAvf007) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-t-avf-007",
		Title:       "Unintended Vehicle Network Message",
		Description: "Unintended Vehicle Network Message (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *RiskTAvf007) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *RiskTAvf007) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		if technicalAsset.IsTaggedWithAny("automotive") {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}
func (r *RiskTAvf007) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>Unintended Vehicle Network Message</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

func GetAllAutomotiveRisks() []types.RiskRule {
	return []types.RiskRule{
		&RiskTS000{},
		&RiskTS001{},
		&RiskTS004{},
		&RiskTS005{},
		&RiskTS006{},
		&RiskTS007{},
		&RiskTS008{},
		&RiskTS099{},
		&RiskTT000{},
		&RiskTT001{},
		&RiskTT002{},
		&RiskTT003{},
		&RiskTT004{},
		&RiskTT005{},
		&RiskTT006{},
		&RiskTT007{},
		&RiskTT008{},
		&RiskTT010{},
		&RiskTT011{},
		&RiskTT012{},
		&RiskTT099{},
		&RiskTR000{},
		&RiskTR099{},
		&RiskTI000{},
		&RiskTI001{},
		&RiskTI008{},
		&RiskTI009{},
		&RiskTI005{},
		&RiskTI006{},
		&RiskTI007{},
		&RiskTI002{},
		&RiskTD000{},
		&RiskTD001{},
		&RiskTD002{},
		&RiskTD003{},
		&RiskTD004{},
		&RiskTD005{},
		&RiskTD006{},
		&RiskTD007{},
		&RiskTD008{},
		&RiskTE000{},
		&RiskTE001{},
		&RiskTE002{},
		&RiskTE003{},
		&RiskTE004{},
		&RiskTE005{},
		&RiskTC1{},
		&RiskTM001{},
		&RiskTM002{},
		&RiskTM003{},
		&RiskTM004{},
		&RiskTM005{},
		&RiskTM006{},
		&RiskTM007{},
		&RiskTM008{},
		&RiskTM009{},
		&RiskTIA001{},
		&RiskTIA002{},
		&RiskTIA003{},
		&RiskTIA004{},
		&RiskTIA005{},
		&RiskTIA006{},
		&RiskTIA007{},
		&RiskTIA008{},
		&RiskTEx001{},
		&RiskTEx002{},
		&RiskTEx003{},
		&RiskTP001{},
		&RiskTP002{},
		&RiskTP003{},
		&RiskTP004{},
		&RiskTP005{},
		&RiskTPe001{},
		&RiskTPe002{},
		&RiskTPe003{},
		&RiskTPe004{},
		&RiskTPe005{},
		&RiskTPe006{},
		&RiskTPe007{},
		&RiskTPe008{},
		&RiskTDe001{},
		&RiskTDe002{},
		&RiskTDe003{},
		&RiskTDe004{},
		&RiskTDe005{},
		&RiskTCa001{},
		&RiskTCa002{},
		&RiskTCa003{},
		&RiskTCa004{},
		&RiskTCa005{},
		&RiskTCa006{},
		&RiskTCa007{},
		&RiskTCa008{},
		&RiskTCa009{},
		&RiskTDi001{},
		&RiskTDi002{},
		&RiskTDi003{},
		&RiskTDi004{},
		&RiskTDi005{},
		&RiskTDi006{},
		&RiskTDi007{},
		&RiskTDi008{},
		&RiskTDi009{},
		&RiskTLm001{},
		&RiskTLm002{},
		&RiskTLm003{},
		&RiskTLm004{},
		&RiskTLm005{},
		&RiskTLm006{},
		&RiskTCo001{},
		&RiskTCo002{},
		&RiskTCo003{},
		&RiskTCo004{},
		&RiskTCo005{},
		&RiskTCo006{},
		&RiskTCo007{},
		&RiskTCo008{},
		&RiskTCo009{},
		&RiskTCo010{},
		&RiskTCo011{},
		&RiskTCo012{},
		&RiskTCac001{},
		&RiskTCac002{},
		&RiskTCac003{},
		&RiskTCac004{},
		&RiskTCac005{},
		&RiskTCac006{},
		&RiskTCac007{},
		&RiskTExf001{},
		&RiskTExf002{},
		&RiskTExf003{},
		&RiskTExf004{},
		&RiskTExf005{},
		&RiskTExf006{},
		&RiskTExf007{},
		&RiskTAvf001{},
		&RiskTAvf002{},
		&RiskTAvf003{},
		&RiskTAvf004{},
		&RiskTAvf005{},
		&RiskTAvf006{},
		&RiskTAvf007{},
		&UnsecuredHardwareDebugPortRule{},
		&ImproperSoCIsolationRule{},
		&MissingInputValidationRule{},
	}
}
