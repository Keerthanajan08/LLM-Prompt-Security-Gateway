import { render, screen } from "@testing-library/react";

import { stats } from "../test/fixtures";
import { StatsPanel } from "./StatsPanel";

describe("StatsPanel", () => {
  it("shows the live counters", () => {
    render(<StatsPanel stats={stats} error={null} />);
    expect(screen.getByText("62.5%")).toBeInTheDocument();
    expect(screen.getByText("5 blocked")).toBeInTheDocument();
    expect(screen.getByText("2")).toBeInTheDocument();
  });

  it("shows a dash for block rate before any traffic", () => {
    render(<StatsPanel stats={{ ...stats, total_checked: 0 }} error={null} />);
    expect(screen.getByText("–")).toBeInTheDocument();
  });

  it("explains a failure to load", () => {
    render(<StatsPanel stats={null} error="502 Bad Gateway" />);
    expect(screen.getByText(/Couldn't load stats: 502 Bad Gateway/)).toBeInTheDocument();
  });
});
