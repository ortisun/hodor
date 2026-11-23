import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { modulesOf, QrCode } from "./QrCode";

afterEach(cleanup);

describe("the QR code of an authenticator application", () => {
  const address = "otpauth://totp/acme:ana%40example.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=acme&algorithm=SHA1&digits=6&period=30";

  it("is a square of squares with the three finder patterns in its corners", () => {
    const modules = modulesOf(address);
    const size = modules.length;
    expect(size).toBeGreaterThanOrEqual(21);
    expect((size - 17) % 4).toBe(0);
    for (const row of modules) {
      expect(row.length).toBe(size);
    }
    // Each finder pattern starts with a dark row of seven.
    const corners: Array<[number, number]> = [
      [0, 0],
      [0, size - 7],
      [size - 7, 0],
    ];
    for (const [top, left] of corners) {
      for (let offset = 0; offset < 7; offset += 1) {
        expect(modules[top]?.[left + offset]).toBe(true);
      }
    }
  });

  it("is drawn as a picture with words for a screen reader, and holds the same squares every time", () => {
    render(<QrCode value={address} label="QR code" />);
    const picture = screen.getByRole("img", { name: "QR code" });
    const dark = modulesOf(address).flat().filter(Boolean).length;
    // One light background, then one square per dark module.
    expect(picture.querySelectorAll("rect").length).toBe(dark + 1);
    expect(modulesOf(address)).toEqual(modulesOf(address));
  });
});
