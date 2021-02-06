package ffs

//Structs for FFS Queries
type Query struct {
	Groups      []Group `json:"groups"`
	GroupClause string  `json:"groupClause,omitempty"`
	PgNum       int     `json:"pgNum,omitempty"`
	PgSize      int     `json:"pgSize,omitempty"`
	PgToken     string `json:"pgToken"`
	SrtDir      string  `json:"srtDir,omitempty"`
	SrtKey      string  `json:"srtKey,omitempty"`
}

type Group struct {
	Filters      []SearchFilter `json:"filters"`
	FilterClause string         `json:"filterClause,omitempty"`
}

type SearchFilter struct {
	Operator string `json:"operator"`
	Term     string `json:"term"`
	Value    string `json:"value"`
}

type QueryProblem struct {
	BadFilter   SearchFilter `json:"badFilter,omitempty"`
	Description string       `json:"description,omitempty"`
	Type        string       `json:"type,omitempty"`
}
