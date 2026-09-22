import "@testing-library/jest-dom/vitest";

import { vi } from "vitest";

// jsdom does not implement layout observation.

vi.stubGlobal(
  "ResizeObserver",
  class {
    observe() {}
    unobserve() {}
    disconnect() {}
  },
);
