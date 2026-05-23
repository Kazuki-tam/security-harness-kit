import type { Severity } from "../scan";

export type Locale = "en" | "ja";

export type Messages = {
  app: {
    selectFolder: string;
    selectFolderForIde: string;
  };
  common: {
    close: string;
    cancel: string;
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
    openInIde: string;
    openInIdeWith: string;
    preferredIde: string;
    updates: {
      check: string;
      checking: string;
      installing: string;
      upToDate: string;
      available: string;
      failed: string;
    };
    ideNames: Record<"cursor" | "vscode" | "antigravity", string>;
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
    progressTitle: string;
    progressHint: string;
    progressSlowHint: string;
    elapsed: string;
    scanningFiles: string;
    previousResultsVisible: string;
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
    step4: string;
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
    openSetup: string;
    setupTabBadge: string;
  };
  audit: {
    title: string;
    subtitle: string;
    loading: string;
    refresh: string;
    noLog: string;
    openSetup: string;
    parseErrors: string;
    blockedEvents: string;
    hookAuditEvents: string;
    maxSeverity: string;
    noBlockedYet: string;
    recentBlocked: string;
    updated: string;
    findingsCount: string;
    bannerTitle: string;
    bannerHint: string;
    overviewTabBadge: string;
    openFindings: string;
    moreEvents: string;
    moreEventsHint: string;
    reasonLabels: Record<string, string>;
    toolNames: Record<string, string>;
    actionCategories: Record<string, string>;
    severityLabels: Record<string, string>;
  };
  setup: {
    statusReady: string;
    statusMissing: string;
    statusNeedsAttention: string;
    statusApplied: string;
    statusRemoved: string;
    statusPending: string;
    quickSetup: {
      title: string;
      description: string;
      apply: string;
      applyWithPolicy: string;
      reapply: string;
      badgeComplete: string;
      badgePending: string;
      policyWillCreate: string;
      customizeToggle: string;
      customizeHint: string;
      openAdvanced: string;
      allCompleteHint: string;
      nothingSelected: string;
      steps: Record<"policy" | "ignore" | "git" | "ai" | "npm" | "skills", string>;
    };
    advanced: {
      title: string;
      description: string;
      pendingHint: string;
    };
    hints: {
      policyFirst: string;
      notGitRepo: string;
      gitHookAlreadyOk: string;
      ignoreAlreadyOk: string;
      aiAlreadyOk: string;
      aiNoChanges: string;
      npmAlreadyOk: string;
      npmNoChanges: string;
      selectIgnoreTarget: string;
      selectAiSetting: string;
    };
    policy: {
      title: string;
      description: string;
      create: string;
      createStrict: string;
      recreate: string;
      recreateHint: string;
      strictHint: string;
      recreateConfirmTitle: string;
      recreateConfirmBody: string;
    };
    ignore: {
      title: string;
      description: string;
      applySelected: string;
      policyRequired: string;
      targetsLabel: string;
      missingLabel: string;
      targetExists: string;
      targetNew: string;
      targetNames: Record<string, string>;
      patternDescriptions: Record<string, string>;
    };
    recommendedFixes: {
      title: string;
      description: string;
      applySelected: string;
      ignoreTargetsLabel: string;
      available: string;
      selectionHint: string;
      rowSelected: string;
      rowSkipped: string;
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
      applySelected: string;
      syncSelected: string;
      removeSelected: string;
      selectionHint: string;
      scanHooksGroup: string;
      scanHooksHint: string;
      scanHooksToolHint: string;
      claudeDeny: string;
      claudeDenyHint: string;
      claudeSandbox: string;
      claudeSandboxHint: string;
      codexSandbox: string;
      codexSandboxHint: string;
      toolNames: Record<string, string>;
      installClaudeDeny: string;
      installCodexSandbox: string;
      removeConfirmTitle: string;
      removeConfirmBody: string;
      cliNotFoundTitle: string;
      cliNotFoundBody: string;
    };
    npm: {
      title: string;
      description: string;
      apply: string;
      remove: string;
      enableLabel: string;
      enabledHint: string;
      disabledHint: string;
      notApplicable: string;
      statusPartial: string;
      removeConfirmTitle: string;
      removeConfirmBody: string;
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
      openSetup: string;
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
      succeeded: string;
      partial: string;
      resultTitles: Record<string, string>;
      resultDetails: Record<string, string>;
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
