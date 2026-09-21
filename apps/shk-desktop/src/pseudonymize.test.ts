import { describe, expect, it } from "vitest";
import { en } from "./i18n/messages/en";
import {
  fileExtension,
  isPseudonymizableFile,
  isTableFile,
  isTableInputKind,
  kindDisplayLabel,
  outputFilterFor,
  pseudonymizeSuggestedOutputName,
  pseudonymizeSuggestedOutputPath,
  restoreMapSuggestedPath,
  suggestCustomLabel,
  validateCustomLabel,
} from "./pseudonymize";

describe("pseudonymize file helpers", () => {
  it("classifies files by extension", () => {
    expect(fileExtension("/tmp/Orders.CSV")).toBe("csv");
    expect(fileExtension("README")).toBe("");
    expect(fileExtension("/tmp/.hidden")).toBe("");
    expect(isPseudonymizableFile("/tmp/a.xlsx")).toBe(true);
    expect(isPseudonymizableFile("/tmp/a.pdf")).toBe(false);
    expect(isPseudonymizableFile("/tmp/a.json")).toBe(false);
    expect(isTableFile("a.tsv")).toBe(true);
    expect(isTableFile("a.docx")).toBe(false);
    expect(isTableInputKind("table-xlsx")).toBe(true);
    expect(isTableInputKind("text-office")).toBe(false);
  });

  it("suggests output names that keep the extension", () => {
    expect(pseudonymizeSuggestedOutputName("/data/orders.csv")).toBe("orders.pseudo.csv");
    expect(pseudonymizeSuggestedOutputName("/data/Book.XLSX")).toBe("Book.pseudo.XLSX");
    expect(pseudonymizeSuggestedOutputName("notes")).toBe("notes.pseudo");
    expect(pseudonymizeSuggestedOutputPath("/data/orders.csv")).toBe("/data/orders.pseudo.csv");
    expect(pseudonymizeSuggestedOutputPath("C:\\data\\orders.csv")).toBe(
      "C:\\data\\orders.pseudo.csv",
    );
    expect(pseudonymizeSuggestedOutputPath("orders.csv")).toBe("orders.pseudo.csv");
  });

  it("places the restore map next to the output without the pseudo marker", () => {
    expect(restoreMapSuggestedPath("/data/orders.pseudo.csv")).toBe("/data/orders.shk-map");
    expect(restoreMapSuggestedPath("/data/custom-name.xlsx")).toBe("/data/custom-name.shk-map");
    expect(restoreMapSuggestedPath("out")).toBe("out.shk-map");
  });

  it("pins the save filter to the input family", () => {
    expect(outputFilterFor("/x/a.csv")).toEqual({ name: "CSV", extensions: ["csv"] });
    expect(outputFilterFor("/x/a.pptx")).toEqual({ name: "PPTX", extensions: ["pptx"] });
    expect(outputFilterFor("/x/README")).toEqual({ name: "File", extensions: ["*"] });
  });
});

describe("custom labels", () => {
  it("validates against the engine's rules", () => {
    expect(validateCustomLabel("member_id")).toBe("ok");
    expect(validateCustomLabel("a")).toBe("ok");
    expect(validateCustomLabel("Member")).toBe("invalid");
    expect(validateCustomLabel("1st")).toBe("invalid");
    expect(validateCustomLabel("x".repeat(34))).toBe("invalid");
    expect(validateCustomLabel("x".repeat(33))).toBe("ok");
    expect(validateCustomLabel("")).toBe("invalid");
    expect(validateCustomLabel("email")).toBe("reserved");
    expect(validateCustomLabel("name")).toBe("reserved");
  });

  it("suggests a label from the header", () => {
    expect(suggestCustomLabel("Member ID")).toBe("member_id");
    expect(suggestCustomLabel("  Order-No. ")).toBe("order_no");
    expect(suggestCustomLabel("123abc")).toBe("abc");
    expect(suggestCustomLabel("会員番号")).toBe("value");
    expect(suggestCustomLabel("Email")).toBe("value");
    expect(suggestCustomLabel("x".repeat(50))).toBe("x".repeat(33));
  });

  it("renders friendly kind names", () => {
    const m = en.mask.pseudonymize;
    expect(kindDisplayLabel("email", m)).toBe("Email address");
    expect(kindDisplayLabel("custom:member_id", m)).toBe("Other (member_id)");
    expect(kindDisplayLabel("mystery", m)).toBe("mystery");
  });
});
