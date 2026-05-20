import type { Severity } from "../scan";

export type Locale = "en" | "ja";

export type Messages = {
  app: {
    selectFolder: string;
  };
  common: {
    close: string;
    language: string;
  };
  sidebar: {
    newProject: string;
    projects: string;
    projectsAria: string;
    runsLocally: string;
    emptyHintLine1: string;
    emptyHintLine2: string;
    openFolder: string;
    renameAria: string;
    actionableCount: string;
    menuAria: string;
    rename: string;
    copyPath: string;
    removeConfirm: string;
    removeProject: string;
  };
  topBar: {
    projectBreadcrumb: string;
    welcome: string;
    openFolder: string;
  };
  welcome: {
    title: string;
    subtitle: string;
    actions: string;
    openProject: string;
    shortcuts: string;
    viewGuide: string;
    recentProjects: string;
    showAll: string;
  };
  scan: {
    project: string;
    scanning: string;
    rescan: string;
    runScan: string;
    scanFailed: string;
    lastScan: string;
    detected: string;
    suppressed: string;
    deduplicated: string;
    actionableBanner: string;
    actionableHint: string;
    cleanResult: string;
    cleanHint: string;
    noActionable: string;
    lowSeverityHint: string;
    readyTitle: string;
    readyHint: string;
  };
  findings: {
    listAria: string;
    title: string;
    allFindings: string;
    filteredCount: string;
    noMatch: string;
    lineTag: string;
    confidence: string;
    bySeverity: string;
    countSuffix: string;
  };
  help: {
    title: string;
    quickStart: string;
    step1: string;
    step2: string;
    step3: string;
    shortcuts: string;
    shortcutOpen: string;
    shortcutRescan: string;
    shortcutClose: string;
    footer: string;
  };
  workspace: {
    tabs: {
      overview: string;
      findings: string;
      setup: string;
    };
    loadingStatus: string;
    policyRequired: string;
  };
  setup: {
    statusReady: string;
    statusMissing: string;
    statusNeedsAttention: string;
    policy: {
      title: string;
      description: string;
      create: string;
      createStrict: string;
      recreate: string;
    };
    ignore: {
      title: string;
      description: string;
      applySelected: string;
      policyRequired: string;
      targetsLabel: string;
      targetExists: string;
      targetNew: string;
      targetNames: Record<string, string>;
    };
    recommendedFixes: {
      title: string;
      description: string;
      applySelected: string;
      ignoreTargetsLabel: string;
      available: string;
      fixLabels: Record<string, string>;
    };
    gitHook: {
      title: string;
      description: string;
      install: string;
      notRepo: string;
    };
    aiHooks: {
      title: string;
      description: string;
      install: string;
      claudeDeny: string;
      codexSandbox: string;
      installClaudeDeny: string;
      installCodexSandbox: string;
    };
    npm: {
      title: string;
      description: string;
      apply: string;
      notApplicable: string;
    };
    skills: {
      title: string;
      description: string;
      install: string;
    };
    doctor: {
      title: string;
      subtitle: string;
      issues: string;
      gitHook: string;
      aiHooks: string;
      ignore: string;
      claudeDeny: string;
      codexConfig: string;
      env: string;
      npm: string;
    };
    action: {
      failed: string;
    };
  };
  severity: Record<Severity, string>;
  time: {
    notScanned: string;
    justNow: string;
    minutesAgo: string;
    hoursAgo: string;
    daysAgo: string;
    weeksAgo: string;
    monthsAgo: string;
    yearsAgo: string;
  };
};
