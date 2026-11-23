import qrcode from "qrcode-generator";
import { useMemo } from "react";

interface QrCodeProps {
  /** What the code holds: the `otpauth://` address of an authenticator application. */
  value: string;
  /** What a screen reader says instead of the picture. */
  label: string;
}

/** The squares of a QR code, row by row: `true` is dark. */
export function modulesOf(value: string): boolean[][] {
  // Type number 0 chooses the smallest code that holds the value; level M
  // survives a smudged screen.
  const code = qrcode(0, "M");
  code.addData(value, "Byte");
  code.make();
  const size = code.getModuleCount();
  return Array.from({ length: size }, (_, row) => Array.from({ length: size }, (_, column) => code.isDark(row, column)));
}

/**
 * A QR code drawn in the page as an SVG of squares: no picture is fetched
 * and no markup is made from text, so the Content Security Policy stays as
 * it is.
 */
export function QrCode({ value, label }: QrCodeProps) {
  const modules = useMemo(() => modulesOf(value), [value]);
  // Four squares of light around the code, as the standard asks.
  const margin = 4;
  const size = modules.length + margin * 2;
  return (
    <svg
      className="auth-qr"
      role="img"
      aria-label={label}
      viewBox={`0 0 ${size} ${size}`}
      width={size * 5}
      height={size * 5}
      shapeRendering="crispEdges"
    >
      <rect width={size} height={size} fill="#ffffff" />
      {modules.flatMap((row, y) =>
        row.map((dark, x) =>
          dark ? <rect key={`${x}-${y}`} x={x + margin} y={y + margin} width={1} height={1} fill="#000000" /> : null,
        ),
      )}
    </svg>
  );
}
