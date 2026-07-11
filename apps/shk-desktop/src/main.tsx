import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { I18nProvider, useI18n } from "./i18n";
import "./styles.css";

function AppShell() {
  const { messages } = useI18n();
  return (
    <ErrorBoundary
      title={messages.errorBoundary.title}
      description={messages.errorBoundary.description}
      reloadLabel={messages.errorBoundary.reload}
    >
      <App />
    </ErrorBoundary>
  );
}

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <I18nProvider>
      <AppShell />
    </I18nProvider>
  </React.StrictMode>,
);
