module dsfgo

go 1.21

require github.com/ldsec/lattigo/v2 v2.2.0

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stretchr/testify v1.7.0 // indirect
	golang.org/x/crypto v0.0.0-20210317152858-513c2a44f670 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
)

replace github.com/ldsec/lattigo/v2 v2.2.0 => github.com/ldsec/lattigo/v2 v2.2.1-0.20210923173451-d9eb44f2c43f

require veritas/vche v0.0.0

replace veritas/vche => ../../external/veritas
