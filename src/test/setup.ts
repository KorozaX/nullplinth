import "@testing-library/jest-dom/vitest";

// Tauri IPC is not available in jsdom: tests that render screens must stub the
// service layer themselves (see src/test/fakeApi.ts pattern in component tests).
