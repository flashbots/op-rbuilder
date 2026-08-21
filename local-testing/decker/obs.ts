// Observability overlay for decker.ts: Prometheus scraping op-rbuilder (+
// chain-monitor, when enabled) and Grafana provisioning.
//
// Loki/Tempo/Alloy are deferred and will be wired as follow up.
import type { ContainerDef, ContainerResult, Ctx, Pod, Prototype, Recipe } from "../../.decker/utils/types.ts";

// Resolved against this module's file.
const GRAFANA_DIR = new URL("../grafana/", import.meta.url);

function readLocal(relPath: string): string {
  return Deno.readTextFileSync(new URL(relPath, GRAFANA_DIR));
}

// Read once at module load instead of per-render.
const DASHBOARD_PROVIDER_YML = readLocal("dashboards.yaml");
const OP_RBUILDER_DASHBOARD_JSON = readLocal("dashboards/op-rbuilder.json");

const GRAFANA_HTTP_PORT = 3000;

function buildGrafanaContainer(def: ContainerDef, ctx: Ctx): ContainerResult {
  const prometheusRef = def.refs?.prometheus;
  if (!prometheusRef) throw new Error(`grafana ${def.name}: missing refs.prometheus`);

  const datasourcesYml = `apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: ${ctx.url(prometheusRef, "http")}
    uid: prometheus
    isDefault: true
    editable: false
    jsonData:
      timeInterval: "5s"
      httpMethod: POST
`;

  return {
    container: {
      image: "docker.io/grafana/grafana:13.0.1",
      env: {
        // Passwordless dev access
        GF_AUTH_ANONYMOUS_ENABLED: "true",
        GF_AUTH_ANONYMOUS_ORG_ROLE: "Admin",
        GF_AUTH_DISABLE_LOGIN_FORM: "true",
        GF_AUTH_BASIC_ENABLED: "false",
        GF_USERS_DEFAULT_THEME: "dark",
        GF_LOG_LEVEL: "warn",
      },
      ports: { http: GRAFANA_HTTP_PORT },
    },
    configs: [
      { filename: "datasources.yml", content: datasourcesYml, mountPath: "/etc/grafana/provisioning/datasources/datasources.yml" },
      { filename: "dashboards.yml", content: DASHBOARD_PROVIDER_YML, mountPath: "/etc/grafana/provisioning/dashboards/dashboards.yml" },
      { filename: "op-rbuilder.json", content: OP_RBUILDER_DASHBOARD_JSON, mountPath: "/var/lib/grafana/dashboards/op-rbuilder.json" },
    ],
  };
}

const grafanaPrototype: Prototype = {
  ports: { http: GRAFANA_HTTP_PORT },
  buildContainer: buildGrafanaContainer,
  webui: { label: "Grafana (op-rbuilder dashboard)" },
};

// Appended to the opstack recipe `pods`.
export function obsPods(base: Recipe): Pod[] {
  const hasChainMonitor = base.pods.some((p) => p.name === "chain-monitor");
  const scrape = [
    { job: "op-rbuilder", ref: "op-rbuilder", port: "metrics" },
    ...(hasChainMonitor ? [{ job: "chain-monitor", ref: "chain-monitor", port: "http", path: "/metrics" }] : []),
  ];
  return [
    {
      name: "prometheus",
      containers: [{ name: "prometheus", prototype: "prometheus", config: { scrape } }],
    },
    {
      name: "grafana",
      containers: [{ name: "grafana", prototype: grafanaPrototype, refs: { prometheus: "prometheus" } }],
    },
  ];
}
