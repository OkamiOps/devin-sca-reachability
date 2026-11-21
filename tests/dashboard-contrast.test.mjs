import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const css = await readFile(new URL("../src/sca_reachability/static/styles.css", import.meta.url), "utf8");
const tokens = block => Object.fromEntries([...block.matchAll(/--([\w-]+):\s*(#[\da-f]+)/gi)].map(([, name, value]) => [name, value]));
const light = tokens(css.match(/:root\s*\{([^}]+)\}/)[1]);
const dark = { ...light, ...tokens(css.match(/:root\[data-theme="dark"\]\s*\{([^}]+)\}/)[1]) };

function luminance(hex) {
  let digits = hex.slice(1);
  if (digits.length === 3) digits = [...digits].map(value => value + value).join("");
  const channels = [0, 2, 4].map(index => parseInt(digits.slice(index, index + 2), 16) / 255)
    .map(channel => channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4);
  return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722;
}
function contrast(first, second) {
  const values = [luminance(first), luminance(second)].sort((a, b) => b - a);
  return (values[0] + 0.05) / (values[1] + 0.05);
}

for (const [theme, palette] of Object.entries({ light, dark })) {
  test(`${theme} text/badges/placeholders >=4.5 and input/select borders >=3`, t => {
    const surfaces = ["bg", "surface", "soft", "warm", "green-soft", "red-soft"];
    const muted = surfaces.map(background => contrast(palette["text-muted"], palette[background]));
    const text = surfaces.map(background => contrast(palette.text, palette[background]));
    const semanticPairs = [
      ["accent", "bg"], ["accent", "surface"], ["accent", "soft"], ["accent", "warm"],
      ["green", "green-soft"], ["red", "red-soft"], ["red", "bg"], ["red", "surface"],
      ["primary-action-fg", "primary-action"], ["accent-fg", "accent"],
    ];
    const semantic = semanticPairs.map(([foreground, background]) => {
      const ratio = contrast(palette[foreground], palette[background]);
      assert.ok(ratio >= 4.5, `${theme} ${foreground}/${background}: ${ratio}`);
      return ratio;
    });
    for (const ratio of [...muted, ...text]) assert.ok(ratio >= 4.5, `${theme} text ratio ${ratio}`);
    const placeholder = contrast(palette["text-muted"], palette.surface);
    const borders = ["bg", "surface", "soft"].map(background => contrast(palette["control-border"], palette[background]));
    for (const ratio of borders) assert.ok(ratio >= 3, `${theme} form border ratio ${ratio}`);
    assert.match(css, /input::placeholder \{ color: var\(--text-muted\); opacity: 1;/);
    assert.match(css, /input, select \{ border: 1px solid var\(--control-border\)/);
    t.diagnostic(`${theme}: normal text min=${Math.min(...text).toFixed(4)}; secondary/neutral min=${Math.min(...muted).toFixed(4)}; semantic badges/actions min=${Math.min(...semantic).toFixed(4)}; placeholder=${placeholder.toFixed(4)}; form border min=${Math.min(...borders).toFixed(4)}`);
  });
}
