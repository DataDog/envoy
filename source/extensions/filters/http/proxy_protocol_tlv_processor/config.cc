#include "source/extensions/filters/http/proxy_protocol_tlv_processor/config.h"

#include "envoy/extensions/filters/http/proxy_protocol_tlv_processor/v3/proxy_protocol_tlv_processor.pb.h"
#include "envoy/extensions/filters/http/proxy_protocol_tlv_processor/v3/proxy_protocol_tlv_processor.pb.validate.h"
#include "envoy/registry/registry.h"

#include "source/extensions/filters/http/proxy_protocol_tlv_processor/proxy_protocol_tlv_processor.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ProxyProtocolTlvProcessor {

Http::FilterFactoryCb ProxyProtocolTlvProcessorFilterConfig::createFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::http::proxy_protocol_tlv_processor::v3::
        ProxyProtocolTlvProcessor& proto_config,
    const std::string&, Server::Configuration::FactoryContext&) {
  auto config = std::make_shared<FilterConfig>(proto_config);
  return [config](Http::FilterChainFactoryCallbacks& callbacks) -> void {
    auto filter = new ProxyProtocolTlvProcessorFilter(config);
    callbacks.addStreamFilter(Http::StreamFilterSharedPtr{filter});
  };
}

/**
 * Static registration for the filter. @see RegisterFactory.
 */
REGISTER_FACTORY(ProxyProtocolTlvProcessorFilterConfig,
                 Server::Configuration::NamedHttpFilterConfigFactory);

} // namespace ProxyProtocolTlvProcessor
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
