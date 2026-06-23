package agentcard

import "strings"


// AgentCard represents an A2A Agent Card for capability discovery.
type AgentCard struct {
	Name           string       `json:"name"`
	DID            string       `json:"did"`
	Description    string       `json:"description,omitempty"`
	URL            string       `json:"url"`
	Capabilities   Capabilities `json:"capabilities"`
	Authentication AuthInfo     `json:"authentication"`
}

// Capabilities describes what an agent can do.
type Capabilities struct {
	Skills       []Skill  `json:"skills"`
	Protocols    []string `json:"protocols"`
	ContentTypes []string `json:"contentTypes"`
}

// Skill describes a single capability an agent supports.
type Skill struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// AuthInfo describes how to authenticate with this agent.
type AuthInfo struct {
	Methods []AuthMethod `json:"methods"`
}

// AuthMethod describes a single authentication method.
type AuthMethod struct {
	Type               string `json:"type"`
	DID                string `json:"did"`
	VerificationMethod string `json:"verificationMethod"`
}

// NewAgentCard creates an Agent Card for the given agent.
// The skills, protocols, and content types define what the agent
// can do and how peers can interact with it.
func NewAgentCard(name, did, description, url string, skills []Skill) *AgentCard {
	if skills == nil {
		skills = []Skill{}
	}
	if description == "" {
		description = "Agente " + name + " - Nó da rede A2A"
	}

	return &AgentCard{
		Name:        name,
		DID:         did,
		Description: description,
		URL:         url,
		Capabilities: Capabilities{
			Skills: skills,
			Protocols: []string{
				"a2a-task-protocol/1.0",
				"didcomm/v2",
			},
			ContentTypes: []string{
				"text/plain",
				"application/json",
				"application/didcomm-signed+json",
				"application/didcomm-encrypted+json",
			},
		},
		Authentication: AuthInfo{
			Methods: []AuthMethod{
				{
					Type:               "didcomm-v2",
					DID:                did,
					VerificationMethod: did + "#key-1",
				},
			},
		},
	}
}
// DefaultSkills returns the default set of skills for a Key Guard agent.
func DefaultSkills() []Skill {
	return []Skill{
		{
			ID:          "messaging",
			Name:        "Messaging",
			Description: "Envio e recebimento de mensagens P2P seguras",
		},
	}
}

// ParseSkills parses a comma-separated list of skill IDs and maps them to Skill structs.
func ParseSkills(skillsStr string) []Skill {
	if skillsStr == "" {
		return DefaultSkills()
	}
	allMocks := map[string]Skill{
		"messaging": {
			ID:          "messaging",
			Name:        "Messaging",
			Description: "Envio e recebimento de mensagens P2P seguras",
		},
		"academic-enrollment": {
			ID:          "academic-enrollment",
			Name:        "Matrícula Acadêmica",
			Description: "Inscrição e matrícula em disciplinas acadêmicas",
		},
		"course-consultation": {
			ID:          "course-consultation",
			Name:        "Consulta de Curso",
			Description: "Acesso a notas, frequência e histórico escolar do aluno",
		},
		"personal-data-management": {
			ID:          "personal-data-management",
			Name:        "Gestão de Dados Pessoais",
			Description: "Atualização cadastral e controle de dados pessoais do aluno",
		},
		"meal-consultation": {
			ID:          "meal-consultation",
			Name:        "Consulta de Cardápio",
			Description: "Consulta ao cardápio diário e horários de funcionamento do RU",
		},
		"balance-recharge": {
			ID:          "balance-recharge",
			Name:        "Recarga de Saldo",
			Description: "Gerenciamento de saldo e recargas do cartão do RU",
		},
		"access-validation": {
			ID:          "access-validation",
			Name:        "Validação de Acesso",
			Description: "Controle de acesso físico e catraca do Restaurante Universitário",
		},
	}
	var result []Skill
	parts := strings.Split(skillsStr, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if s, ok := allMocks[p]; ok {
			result = append(result, s)
		}
	}
	if len(result) == 0 {
		return DefaultSkills()
	}
	return result
}
