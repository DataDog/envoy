#pragma once

#include "envoy/extensions/filters/http/proxy_protocol_tlv_processor/v3/proxy_protocol_tlv_processor.pb.h"
#include "envoy/extensions/filters/http/proxy_protocol_tlv_processor/v3/proxy_protocol_tlv_processor.pb.validate.h"

#include "source/extensions/filters/http/common/factory_base.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ProxyProtocolTlvProcessor {

/**
 * Config registration for the proxy protocol tlv to http header filter. @see
 * NamedHttpFilterConfigFactory.
 */
class ProxyProtocolTlvProcessorFilterConfig
    : public Common::FactoryBase<envoy::extensions::filters::http::proxy_protocol_tlv_processor::
                                     v3::ProxyProtocolTlvProcessor> {
public:
  ProxyProtocolTlvProcessorFilterConfig()
      : FactoryBase("envoy.filters.http.proxy_protocol_tlv_processor") {}

private:
  Http::FilterFactoryCb createFilterFactoryFromProtoTyped(
      const envoy::extensions::filters::http::proxy_protocol_tlv_processor::v3::
          ProxyProtocolTlvProcessor& proto_config,
      const std::string& stats_prefix, Server::Configuration::FactoryContext& context) override;
};

} // namespace ProxyProtocolTlvProcessor
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
