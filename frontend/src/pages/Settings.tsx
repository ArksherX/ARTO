import Placeholder from "../components/Placeholder";

export default function Settings() {
  return (
    <Placeholder
      title="Settings"
      endpoint="/api/v1/auth/api-keys"
      note="Global settings: theme, API-key generation/rotation, and per-service configuration — consolidated here instead of a copy in each pillar."
    />
  );
}
