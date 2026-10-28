import { categoryLabel, ms, pct, ruleLabel } from "./format";

describe("format", () => {
  it("formats numbers", () => {
    expect(pct(0.976)).toBe("97.6%");
    expect(ms(32.41)).toBe("32.4 ms");
    expect(ms(1500)).toBe("1.50 s");
  });

  it("labels categories and rules", () => {
    expect(categoryLabel("hard_negative")).toBe("Tricky but safe prompts");
    expect(categoryLabel("something_new")).toBe("something new");
    expect(ruleLabel("aws_access_key_id")).toBe("aws access key id");
  });
});
