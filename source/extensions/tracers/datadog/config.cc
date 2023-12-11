#include "source/extensions/tracers/datadog/config.h"

#include <datadog/http_client.h>
#include <datadog/json.hpp>
#include <datadog/tracer_config.h>

#include <memory>

#include "envoy/config/trace/v3/datadog.pb.h"
#include "envoy/config/trace/v3/datadog.pb.validate.h"
#include "envoy/extensions/upstreams/http/v3/http_protocol_options.pb.h"
#include "envoy/registry/registry.h"

#include "source/common/version/version.h"
#include "source/common/http/utility.h"
#include "source/extensions/tracers/datadog/agent_http_client.h"
#include "source/extensions/tracers/datadog/logger.h"
#include "source/extensions/tracers/datadog/tracer.h"

namespace Envoy {
namespace Extensions {
namespace Tracers {
namespace Datadog {

class NoopHTTPClient : public datadog::tracing::HTTPClient {
  public:
    datadog::tracing::Expected<void> post(const URL&, HeadersSetter, std::string, ResponseHandler, ErrorHandler) override {
      return {};
    };
    void drain(std::chrono::steady_clock::time_point) override {};
    nlohmann::json config_json() const override {
      return {};
    };
};

DatadogTracerFactory::DatadogTracerFactory() : FactoryBase("envoy.tracers.datadog") {}

datadog::tracing::TracerConfig
DatadogTracerFactory::makeConfig(const envoy::config::trace::v3::DatadogConfig& proto_config, Envoy::Upstream::ClusterManager& cluster_manager) {
  ENVOY_LOG(debug, "DatadogTracerFactory::makeConfig");
  datadog::tracing::TracerConfig config;
  config.defaults.version = "envoy " + Envoy::VersionInfo::version();
  config.defaults.name = "envoy.proxy";
  if (proto_config.service_name().empty()) {
    config.defaults.service = "envoy";
  } else {
    config.defaults.service = proto_config.service_name();
  }
  config.logger = std::make_shared<Logger>(ENVOY_LOGGER());
  auto& collector_cluster = proto_config.collector_cluster();
  config.agent.http_client = std::make_shared<NoopHTTPClient>();

  datadog::tracing::Expected<datadog::tracing::FinalizedTracerConfig> maybe_config =
      datadog::tracing::finalize_config(config);
  if (datadog::tracing::Error* error = maybe_config.if_error()) {
    datadog::tracing::StringView prefix =
        "makeConfig: Unable to configure Datadog tracer. Tracing is now disabled. Error: ";
    config.logger->log_error(error->with_prefix(prefix));
    return {};
  }

  auto& agent_config = std::get<datadog::tracing::FinalizedDatadogAgentConfig>(maybe_config.value().collector);
  
  if (cluster_manager.getThreadLocalCluster(collector_cluster) == nullptr) {
    // Make sure we run this on main thread.
    TRY_ASSERT_MAIN_THREAD {
      envoy::config::cluster::v3::Cluster cluster;
      const envoy::config::cluster::v3::Cluster::DiscoveryType cluster_type = envoy::config::cluster::v3::Cluster::LOGICAL_DNS;
      absl::string_view host_port;
      absl::string_view path;
      Http::Utility::extractHostPathFromUri(agent_config.url.authority, host_port, path);
      const auto host_attributes = Http::Utility::parseAuthority(host_port);
      const auto host = host_attributes.host_;
      const auto port = host_attributes.port_ ? host_attributes.port_.value() : 8126;

      cluster.set_name(collector_cluster);
      cluster.set_type(cluster_type);
      cluster.mutable_connect_timeout()->set_seconds(5);
      cluster.mutable_load_assignment()->set_cluster_name(collector_cluster);
      auto* endpoint = cluster.mutable_load_assignment()
                           ->add_endpoints()
                           ->add_lb_endpoints()
                           ->mutable_endpoint();
      auto* addr = endpoint->mutable_address();
      addr->mutable_socket_address()->set_address(host);
      addr->mutable_socket_address()->set_port_value(port);
      cluster.set_lb_policy(envoy::config::cluster::v3::Cluster::ROUND_ROBIN);
      envoy::extensions::upstreams::http::v3::HttpProtocolOptions protocol_options;
      auto* http_protocol_options =
          protocol_options.mutable_explicit_http_config()->mutable_http_protocol_options();
      http_protocol_options->set_accept_http_10(true);
      (*cluster.mutable_typed_extension_protocol_options())
          ["envoy.extensions.upstreams.http.v3.HttpProtocolOptions"]
              .PackFrom(protocol_options);

      // Add tls transport socket if cluster supports https over port 443.
      if (agent_config.url.scheme == "https") {
        auto* socket = cluster.mutable_transport_socket();
        envoy::extensions::transport_sockets::tls::v3::UpstreamTlsContext tls_socket;
        socket->set_name("envoy.transport_sockets.tls");
        socket->mutable_typed_config()->PackFrom(tls_socket);
      }

      // TODO(suniltheta): use random number generator here for cluster version.
      cluster_manager.addOrUpdateCluster(cluster, "1");

      const auto cluster_type_str = envoy::config::cluster::v3::Cluster::DiscoveryType_descriptor()
                                        ->FindValueByNumber(cluster_type)
                                        ->name();
      ENVOY_LOG_MISC(info,
                     "Added a {} internal cluster [name: {}, address:{}] to fetch aws "
                     "credentials",
                     cluster_type_str, collector_cluster, host_port);
    }
    END_TRY
    CATCH(const EnvoyException& e, {
      ENVOY_LOG_MISC(error, "Failed to add internal cluster {}: {}", collector_cluster, e.what());
      return {};
    });
  }
  return config;
}

std::string DatadogTracerFactory::makeCollectorReferenceHost(
    const envoy::config::trace::v3::DatadogConfig& proto_config) {
  ENVOY_LOG(debug, "DatadogTracerFactory::makeCollectorReferenceHost");
  std::string collector_reference_host = proto_config.collector_hostname();
  if (collector_reference_host.empty()) {
    collector_reference_host = proto_config.collector_cluster();
  }
  return collector_reference_host;
}

Tracing::DriverSharedPtr DatadogTracerFactory::createTracerDriverTyped(
    const envoy::config::trace::v3::DatadogConfig& proto_config,
    Server::Configuration::TracerFactoryContext& context) {
  // ENVOY_LOG(debug, "DatadogTracerFactory::createTracerDriverTyped");
  auto& factory_context = context.serverFactoryContext();
  return std::make_shared<Tracer>(
      proto_config.collector_cluster(), makeCollectorReferenceHost(proto_config),
      makeConfig(proto_config, factory_context.clusterManager()), factory_context.clusterManager(),
      factory_context.scope(), factory_context.threadLocal());
}

/**
 * Static registration for the Datadog tracer. @see RegisterFactory.
 */
REGISTER_FACTORY(DatadogTracerFactory, Server::Configuration::TracerFactory);

} // namespace Datadog
} // namespace Tracers
} // namespace Extensions
} // namespace Envoy
