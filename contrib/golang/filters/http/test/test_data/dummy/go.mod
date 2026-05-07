module example.com/dummy

go 1.24.6

require github.com/envoyproxy/envoy v1.38.0

require google.golang.org/protobuf v1.36.11 // indirect

replace github.com/envoyproxy/envoy => ../../../../../../../
