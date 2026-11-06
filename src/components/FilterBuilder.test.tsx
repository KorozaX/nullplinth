import { useState } from "react";
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { FilterBuilder } from "./FilterBuilder";
import { EVENT_FIELDS } from "../lib/filterFields";
import type { FilterRow } from "../types/contracts";

function Harness() {
  const [rows, setRows] = useState<FilterRow[]>([]);
  return (
    <div>
      <FilterBuilder fields={EVENT_FIELDS} value={rows} onChange={setRows} />
      <p data-testid="row-count">{rows.length}</p>
    </div>
  );
}

describe("FilterBuilder", () => {
  it("adds and removes filter rows", async () => {
    const user = userEvent.setup();
    render(<Harness />);

    expect(screen.getByText(/No filters/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Add filter" }));
    expect(screen.getByTestId("row-count")).toHaveTextContent("1");
    expect(screen.getByLabelText("Filter 1 field")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Add filter" }));
    expect(screen.getByLabelText("Filter 2 field")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Remove filter 1" }));
    expect(screen.queryByLabelText("Filter 2 field")).not.toBeInTheDocument();
    expect(screen.getByTestId("row-count")).toHaveTextContent("1");
  });

  it("validates numeric and IP values", async () => {
    const user = userEvent.setup();
    render(<Harness />);

    await user.click(screen.getByRole("button", { name: "Add filter" }));
    await user.selectOptions(screen.getByLabelText("Filter 1 field"), "dstPort");
    await user.type(screen.getByLabelText("Filter 1 value"), "abc");
    expect(await screen.findByText("Value must be a whole number")).toBeInTheDocument();

    await user.clear(screen.getByLabelText("Filter 1 value"));
    await user.type(screen.getByLabelText("Filter 1 value"), "443");
    expect(screen.queryByText("Value must be a whole number")).not.toBeInTheDocument();

    await user.selectOptions(screen.getByLabelText("Filter 1 field"), "srcIp");
    await user.type(screen.getByLabelText("Filter 1 value"), "not-an-ip");
    expect(await screen.findByText("Enter a valid IP address")).toBeInTheDocument();

    await user.clear(screen.getByLabelText("Filter 1 value"));
    await user.type(screen.getByLabelText("Filter 1 value"), "10.0.0.5");
    expect(screen.queryByText("Enter a valid IP address")).not.toBeInTheDocument();

    await user.selectOptions(screen.getByLabelText("Filter 1 operator"), "inCidr");
    expect(await screen.findByText("Enter a subnet such as 10.0.0.0/8")).toBeInTheDocument();
  });
});
