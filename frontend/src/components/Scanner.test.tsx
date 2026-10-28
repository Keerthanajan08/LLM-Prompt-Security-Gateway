import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { CARD_PROMPT, answered, blocked, mockFetch, notSent } from "../test/fixtures";
import { Scanner } from "./Scanner";

afterEach(() => vi.unstubAllGlobals());

describe("Scanner", () => {
  it("screens a prompt and highlights what was found", async () => {
    const fetchMock = mockFetch({ body: blocked });
    const onResult = vi.fn();
    render(<Scanner onResult={onResult} />);

    await userEvent.type(screen.getByLabelText("Prompt"), CARD_PROMPT);
    await userEvent.click(screen.getByRole("button", { name: "Screen" }));

    expect(await screen.findByText("BLOCKED")).toBeInTheDocument();
    expect(screen.getByText("Never reaches the LLM")).toBeInTheDocument();
    // The flagged span is shown in place, from the user's own text.
    const mark = document.querySelector("mark");
    expect(mark).toHaveTextContent("4111 1111 1111 1111");
    expect(screen.getByText(/credit card \(Payment & financial, global pack\)/)).toBeInTheDocument();

    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe("/check");
    expect(JSON.parse(init.body)).toEqual({ prompt: CARD_PROMPT });
    expect(onResult).toHaveBeenCalledWith({ mode: "check", text: CARD_PROMPT, check: blocked });
  });

  it("explains that a blocked prompt never reached the LLM", async () => {
    const fetchMock = mockFetch({ body: notSent });
    render(<Scanner onResult={vi.fn()} />);
    await userEvent.click(screen.getByRole("radio", { name: "Screen + send to LLM" }));
    await userEvent.click(screen.getByRole("button", { name: "Card number" }));

    expect(await screen.findByText(/the LLM never saw it/)).toBeInTheDocument();
    expect(fetchMock.mock.calls[0]![0]).toBe("/query");
  });

  it("shows the LLM's answer and that the answer was screened too", async () => {
    mockFetch({ body: answered });
    render(<Scanner onResult={vi.fn()} />);
    await userEvent.click(screen.getByRole("radio", { name: "Screen + send to LLM" }));
    await userEvent.click(screen.getByRole("button", { name: "Safe question" }));

    expect(await screen.findByText(answered.answer!)).toBeInTheDocument();
    expect(screen.getByText("Answer screened too:")).toBeInTheDocument();
    expect(screen.getAllByText("SAFE")).toHaveLength(2);
  });

  it("shows the API's error message", async () => {
    mockFetch({ status: 413, body: { detail: "Prompt too large: 90000 characters" } });
    render(<Scanner onResult={vi.fn()} />);
    await userEvent.click(screen.getByRole("button", { name: "Safe question" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Prompt too large");
  });
});
