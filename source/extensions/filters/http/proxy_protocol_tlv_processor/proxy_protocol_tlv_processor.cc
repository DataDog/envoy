#include "source/extensions/filters/http/proxy_protocol_tlv_processor/proxy_protocol_tlv_processor.h"

#include "envoy/data/core/v3/tlv_metadata.pb.h"

#include "source/common/common/base64.h"
#include "source/common/network/proxy_protocol_filter_state.h"
#include "source/extensions/filters/http/well_known_names.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ProxyProtocolTlvProcessor {

FilterConfig::FilterConfig(const envoy::extensions::filters::http::proxy_protocol_tlv_processor::
                               v3::ProxyProtocolTlvProcessor& proto_config)
    : tlvs_(proto_config.tlvs().begin(), proto_config.tlvs().end()),
      header_prefix_(proto_config.header_prefix()),
      metadata_namespace_(proto_config.metadata_namespace()),
      set_headers_(proto_config.set_headers()), set_metadata_(proto_config.set_metadata()) {
  if (header_prefix_.empty()) {
    header_prefix_ = "ppv2_tlv_";
  }
  if (metadata_namespace_.empty()) {
    metadata_namespace_ = HttpFilterNames::get().ProxyProtocolTlvProcessor;
  }
}

ProxyProtocolTlvProcessorFilter::ProxyProtocolTlvProcessorFilter(
    std::shared_ptr<FilterConfig> config)
    : config_(std::move(config)) {}

const Network::ProxyProtocolData& ProxyProtocolTlvProcessorFilter::getProxyProtocolData() const {
  auto data = decoder_callbacks_->streamInfo()
                  .filterState()
                  ->getDataReadOnly<Network::ProxyProtocolFilterState>(
                      Network::ProxyProtocolFilterState::key());
  ASSERT(data != nullptr);
  return data->value();
}

bool ProxyProtocolTlvProcessorFilter::doesProxyProtoDataExist() const {
  return decoder_callbacks_->streamInfo().filterState()->hasData<Network::ProxyProtocolFilterState>(
      Network::ProxyProtocolFilterState::key());
}

Http::FilterHeadersStatus
ProxyProtocolTlvProcessorFilter::decodeHeaders(Http::RequestHeaderMap& headers, bool) {
  // Nothing to do.
  if (!(config_->shouldSetHeaders() || config_->shouldSetMetadata())) {
    return Http::FilterHeadersStatus::Continue;
  }

  // No Proxy Protocol filter state.
  if (!doesProxyProtoDataExist()) {
    return Http::FilterHeadersStatus::Continue;
  }

  envoy::data::core::v3::TlvsMetadata tlvs_typed_metadata;
  ProtobufWkt::Struct tlvs_untyped_metadata;

  const auto& proxy_proto_data = getProxyProtocolData();

  bool have_tlvs_to_set_metadata = false;
  for (const auto& tlv : proxy_proto_data.tlv_vector_) {
    if (config_->tlvs().count(tlv.type) == 0) {
      continue;
    }

    std::vector<char> sanitised_tlv_value;
    sanitised_tlv_value.reserve(tlv.value.size());

    for (const auto c : tlv.value) {
      if (!std::isprint(c)) {
        sanitised_tlv_value.push_back('!');
      } else {
        sanitised_tlv_value.push_back(c);
      }
    }

    if (config_->shouldSetHeaders()) {
      const std::string val =
          Base64::encode(sanitised_tlv_value.data(), sanitised_tlv_value.size());
      headers.setCopy(Http::LowerCaseString(config_->headerPrefix() + std::to_string(tlv.type)),
                      val);
    }
    // Set both typed and untyped metadata since it seems like Envoy is migrating
    // from one to another
    if (config_->shouldSetMetadata()) {
      have_tlvs_to_set_metadata = true;
      // Typed metadata
      Protobuf::BytesValue tlv_byte_value;
      tlv_byte_value.set_value(sanitised_tlv_value.data(), sanitised_tlv_value.size());
      tlvs_typed_metadata.mutable_typed_metadata()->insert(
          {std::to_string(tlv.type), tlv_byte_value.value()});

      // Untyped metadata
      ProtobufWkt::Value metadata_value;
      metadata_value.set_string_value(sanitised_tlv_value.data(), sanitised_tlv_value.size());
      tlvs_untyped_metadata.mutable_fields()->insert({std::to_string(tlv.type), metadata_value});
    }
  }
  if (config_->shouldSetMetadata() && have_tlvs_to_set_metadata) {
    ProtobufWkt::Any typed_metadata;
    typed_metadata.PackFrom(tlvs_typed_metadata);
    decoder_callbacks_->streamInfo().setDynamicTypedMetadata(config_->metadataNamespace(),
                                                             typed_metadata);
    decoder_callbacks_->streamInfo().setDynamicMetadata(config_->metadataNamespace(),
                                                        tlvs_untyped_metadata);
  }
  return Http::FilterHeadersStatus::Continue;
}

} // namespace ProxyProtocolTlvProcessor
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
