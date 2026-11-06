import { useCallback, useState } from "react";
import type { ReactNode } from "react";

import { ModeProvider } from "./context/ModeContext";
import { AppShell } from "./shell/AppShell";
import type { SectionId } from "./shell/sections";
import { OverviewScreen } from "./screens/OverviewScreen";
import { EventExplorerScreen } from "./screens/EventExplorerScreen";
import { NetworkAnalyzerScreen } from "./screens/NetworkAnalyzerScreen";
import { AlertsScreen } from "./screens/AlertsScreen";
import { InvestigationsScreen } from "./screens/InvestigationsScreen";
import { DataSourcesScreen } from "./screens/DataSourcesScreen";
import { SettingsScreen } from "./screens/SettingsScreen";

function renderSection(
  section: SectionId,
  onNavigate: (next: SectionId) => void,
  onOpenInvestigation: (investigationId: number) => void,
  investigationFocus: number | null,
): ReactNode {
  switch (section) {
    case "events":
      return <EventExplorerScreen />;
    case "network":
      return <NetworkAnalyzerScreen />;
    case "alerts":
      return <AlertsScreen onOpenInvestigation={onOpenInvestigation} />;
    case "investigations":
      return <InvestigationsScreen focusId={investigationFocus} />;
    case "sources":
      return <DataSourcesScreen />;
    case "settings":
      return <SettingsScreen />;
    case "overview":
    default:
      return <OverviewScreen onNavigate={onNavigate} />;
  }
}

export function App() {
  const [section, setSection] = useState<SectionId>("overview");
  const [investigationFocus, setInvestigationFocus] = useState<number | null>(null);

  const openInvestigation = useCallback((investigationId: number) => {
    setInvestigationFocus(investigationId);
    setSection("investigations");
  }, []);

  return (
    <ModeProvider>
      <AppShell section={section} onSelect={setSection}>
        {renderSection(section, setSection, openInvestigation, investigationFocus)}
      </AppShell>
    </ModeProvider>
  );
}
