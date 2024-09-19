load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

# External authorization L7 HTTP filter
# Public docs: TODO(saumoh): Docs needed in docs/root/configuration/http/http_filters

envoy_extension_package()

envoy_cc_library(
    name = "proxy_protocol_tlv_processor",
    srcs = ["proxy_protocol_tlv_processor.cc"],
    hdrs = ["proxy_protocol_tlv_processor.h"],
    deps = [
        "//source/common/common:base64_lib",
        "//source/common/http:codes_lib",
        "//source/common/network:proxy_protocol_filter_state_lib",
        "//source/extensions/filters/http:well_known_names",
        "//source/extensions/filters/http/common:pass_through_filter_lib",
        "@envoy_api//envoy/data/core/v3:pkg_cc_proto",
        "@envoy_api//envoy/extensions/filters/http/proxy_protocol_tlv_processor/v3:pkg_cc_proto",
    ],
)

envoy_cc_extension(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    deps = [
        ":proxy_protocol_tlv_processor",
        "//source/extensions/filters/http/common:factory_base_lib",
        "@envoy_api//envoy/extensions/filters/http/proxy_protocol_tlv_processor/v3:pkg_cc_proto",
    ],
)
