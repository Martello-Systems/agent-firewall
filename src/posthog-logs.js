import { OTLPLogExporter } from "@opentelemetry/exporter-logs-otlp-http";
import { resourceFromAttributes } from "@opentelemetry/resources";
import { BatchLogRecordProcessor, LoggerProvider } from "@opentelemetry/sdk-logs";

const projectToken = process.env.POSTHOG_PROJECT_TOKEN;
const host = process.env.POSTHOG_HOST;

let loggerProvider = null;
export let posthogLog = null;

if (projectToken && host) {
  try {
    const logsUrl = new URL("i/v1/logs", `${host.replace(/\/?$/, "/")}`).toString();
    loggerProvider = new LoggerProvider({
      resource: resourceFromAttributes({
        "service.name": "agent-firewall",
      }),
      processors: [
        new BatchLogRecordProcessor(
          new OTLPLogExporter({
            url: logsUrl,
            headers: { Authorization: `Bearer ${projectToken}` },
            timeoutMillis: 2000,
          })
        ),
      ],
    });
    // Use the provider directly: the global OpenTelemetry logger may be a no-op.
    posthogLog = loggerProvider.getLogger("agent-firewall.posthog");
  } catch {
    // PostHog logs must never stop the CLI from processing firewall decisions.
    loggerProvider = null;
  }
}

export async function shutdownPostHogLogs(timeoutMs = 3000) {
  if (!loggerProvider) return;

  let timeout;
  try {
    await Promise.race([
      loggerProvider.shutdown().catch(() => {}),
      new Promise((resolve) => {
        timeout = setTimeout(resolve, timeoutMs);
      }),
    ]);
  } catch {
    // Delivery failures must not change the command's exit status.
  } finally {
    if (timeout) clearTimeout(timeout);
  }
}
