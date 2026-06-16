module github.com/usetero/policy-go/examples

go 1.25.0

require (
	github.com/usetero/policy-go/backend/teroscan v0.0.0-00010101000000-000000000000
	github.com/usetero/policy-go/policy v0.0.0-00010101000000-000000000000
)

require github.com/flier/gohs v1.2.3 // indirect

require (
	github.com/usetero/policy-go/backend/hyperscan v0.0.0-00010101000000-000000000000
	github.com/usetero/policy-go/proto v0.0.0-00010101000000-000000000000
	go.opentelemetry.io/proto/otlp v1.9.0 // indirect
	golang.org/x/net v0.47.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
	golang.org/x/text v0.31.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260120221211-b8f7ae30c516 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260120174246-409b4a993575 // indirect
	google.golang.org/grpc v1.78.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/usetero/policy-go/policy => ../policy

replace github.com/usetero/policy-go/backend/teroscan => ../backend/teroscan

replace github.com/usetero/policy-go/proto => ../proto

replace github.com/usetero/policy-go/backend/hyperscan => ../backend/hyperscan
