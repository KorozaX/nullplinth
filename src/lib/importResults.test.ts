import { describe, expect, it } from "vitest";

import { captureSuccessMessage, importSuccessMessage } from "./importResults";

describe("import notifications", () => {
  it("pluralizes event counts accurately", () => {
    expect(importSuccessMessage(1, 0)).toBe("Successfully imported 1 event into NULLPLINTH.");
    expect(importSuccessMessage(0, 0)).toBe("Successfully imported 0 events into NULLPLINTH.");
    expect(importSuccessMessage(1200, 0)).toBe("Successfully imported 1,200 events into NULLPLINTH.");
    expect(importSuccessMessage(2, 1)).toBe(
      "Successfully imported 2 events into NULLPLINTH. Skipped 1 record.",
    );
    expect(importSuccessMessage(2, 5)).toBe(
      "Successfully imported 2 events into NULLPLINTH. Skipped 5 records.",
    );
  });

  it("reports capture packet counts", () => {
    expect(captureSuccessMessage("demo.pcap", 1)).toBe("Imported 1 packet from demo.pcap into NULLPLINTH.");
    expect(captureSuccessMessage("demo.pcap", 42)).toBe("Imported 42 packets from demo.pcap into NULLPLINTH.");
  });
});
