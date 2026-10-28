import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { evalResults } from "../test/fixtures";
import { EvalPanel } from "./EvalPanel";

describe("EvalPanel", () => {
  it("leads with the unseen test split", () => {
    render(<EvalPanel data={evalResults} />);
    expect(screen.getByRole("radio", { name: /Test \(unseen, 69\)/ })).toBeChecked();
    expect(screen.getByText("97.6%")).toBeInTheDocument();
    expect(screen.getByText("17.9%")).toBeInTheDocument();
  });

  it("shows per-category results in the right group", () => {
    render(<EvalPanel data={evalResults} />);
    expect(screen.getByText("Secrets & API keys")).toBeInTheDocument();
    expect(screen.getByText("10/11")).toBeInTheDocument();
    expect(screen.getByText("6/10")).toBeInTheDocument();
  });

  it("switches to the dev split", async () => {
    render(<EvalPanel data={evalResults} />);
    await userEvent.click(screen.getByRole("radio", { name: /Dev/ }));
    expect(screen.getByText("100.0%")).toBeInTheDocument();
  });
});
