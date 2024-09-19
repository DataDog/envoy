load(
    "//bazel:envoy_build_system.bzl",
    "envoy_package",
)
load(
    "//test/extensions:extensions_build_system.bzl",
    "envoy_extension_cc_test",
)

licenses(["notice"])  # Apache 2

envoy_package()

envoy_extension_cc_test(
    name = "proxy_protocol_tlv_processor_test",
    srcs = ["proxy_protocol_tlv_processor.cc"],
    extension_names = ["envoy.filters.http.proxy_protocol_tlv_processor"],
    deps = [
        "//source/extensions/filters/http/proxy_protocol_tlv_processor",
        "//test/mocks/http:http_mocks",
        "//test/mocks/network:network_mocks",
        "//test/mocks/server:factory_context_mocks",
        "//test/test_common:test_runtime_lib",
    ],
)
