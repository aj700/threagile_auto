package main

import (
	"encoding/xml"
	"fmt"
	"os"
	"regexp"
	"strings"
	"text/template"
)

type RootNodes struct {
	XMLName         xml.Name         `xml:"RootNodes"`
	ThreatsCatalogs []ThreatsCatalog `xml:"ThreatsCatalog"`
}

type ThreatsCatalog struct {
	Name          string        `xml:"name,attr"`
	ThreatClasses []ThreatClass `xml:"ThreatClasses>ThreatClass"`
}

type ThreatClass struct {
	ID    string `xml:"id,attr"` // Map localRef:id to this
	Name  string `xml:"name,attr"`
	Title string `xml:"title,attr"`
}

type ParsedRisk struct {
	ID          string
	CleanID     string
	Title       string
	Description string
}

func main() {
	xmlFile, err := os.Open("input/threat_catalog.xsam")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer xmlFile.Close()

	var root RootNodes
	if err := xml.NewDecoder(xmlFile).Decode(&root); err != nil {
		fmt.Println("Error decoding XML:", err)
		return
	}

	var parsedRisks []ParsedRisk
	seenIDs := make(map[string]bool)

	// Regex to clean IDs for Go struct names (remove dots, etc)
	reg, _ := regexp.Compile("[^a-zA-Z0-9]+")

	for _, catalog := range root.ThreatsCatalogs {
		for _, threat := range catalog.ThreatClasses {
			// cleanID for Go Struct name
			cleanID := reg.ReplaceAllString(threat.Name, "")
			if cleanID == "" {
				cleanID = reg.ReplaceAllString(threat.ID, "")
			}
            
            // Handle duplicate CleanIDs if necessary, or just skip
            if seenIDs[cleanID] {
                continue
            }
            seenIDs[cleanID] = true

			parsedRisks = append(parsedRisks, ParsedRisk{
				ID:          strings.ToLower(strings.ReplaceAll(threat.Name, ".", "-")),
				CleanID:     cleanID,
				Title:       threat.Title,
				Description: threat.Title,
			})
		}
	}

	tmpl := `package automotive
import (
	"github.com/threagile/threagile/pkg/types"
)
// This logic applies the risk to ANY technical asset tagged with "automotive"
// It serves as a comprehensive catalog check.
{{range .}}
type Risk{{.CleanID}} struct {}
func (r *Risk{{.CleanID}}) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "automotive-{{.ID}}",
		Title:       "{{.Title}}",
		Description: "{{.Description}} (Imported from XSAM)",
		Impact:      "Potential impact depending on the specific automotive context.",
		Function:    types.BusinessSide,
		STRIDE:      types.Tampering,
		Action:      "Review automotive standards",
		Mitigation:  "Apply automotive security controls (e.g. UN R155)",
		Check:       "Is this threat applicable?",
	}
}
func (r *Risk{{.CleanID}}) SupportedTags() []string {
	return []string{"automotive"}
}
func (r *Risk{{.CleanID}}) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
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
func (r *Risk{{.CleanID}}) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, types.MediumImpact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           types.MediumImpact,
		Title:                        "<b>{{.Title}}</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
{{end}}
func GetAllAutomotiveRisks() []types.RiskRule {
	return []types.RiskRule{
		{{range .}}&Risk{{.CleanID}}{},
		{{end}}
	}
}
`

	t := template.Must(template.New("risks").Parse(tmpl))
	outFile, err := os.Create("pkg/risks/automotive/generated_risks.go")
	if err != nil {
		fmt.Println("Error creating output file:", err)
		return
	}
	defer outFile.Close()

	if err := t.Execute(outFile, parsedRisks); err != nil {
		fmt.Println("Error executing template:", err)
	}
    fmt.Println("Successfully generated risks.")
}
