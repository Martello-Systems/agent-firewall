import { PostHog } from "posthog-node";

const projectToken = process.env.POSTHOG_PROJECT_TOKEN;
const host = process.env.POSTHOG_HOST;

function warnForMissingConfiguration(variableName) {
  if (process.env.NODE_ENV !== "production") {
    process.stderr.write(
      `[agent-firewall] ${variableName} variable required by PostHog is missing or un-configured, this causes events to be silently missed. This error stops appearing once ${variableName} is configured\n`
    );
  }
}

if (!projectToken) warnForMissingConfiguration("POSTHOG_PROJECT_TOKEN");
if (!host) warnForMissingConfiguration("POSTHOG_HOST");

export const posthog =
  projectToken && host
    ? new PostHog(projectToken, {
        host,
        enableExceptionAutocapture: true,
      })
    : null;
