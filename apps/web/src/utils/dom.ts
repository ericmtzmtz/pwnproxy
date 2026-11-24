/**
 * DOM builders for the `.astro` pages that render data coming from a target.
 *
 * These pages cannot use JSX, and building HTML strings out of URLs, headers,
 * payloads or server messages turns any of them into XSS — the API token lives
 * in `localStorage`. So the rule is: create nodes, set `textContent`. Nothing
 * here (nor in its callers) touches `innerHTML`; `tests/architecture/test_web_xss.py`
 * enforces it.
 */

/** `document.createElement` with an optional class list and text. */
export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className?: string,
  text?: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

/** The SVG shapes the icons in this UI use. */
export type IconShape =
  | "path"
  | "circle"
  | "line"
  | "polyline"
  | "polygon"
  | "rect";

/**
 * An inline SVG icon from literal attributes.
 *
 * Icons are static decoration written in the code, never data, so the shape
 * list is a fixed union and the attributes are the literal ones the markup used
 * to have.
 */
export function svgIcon(
  shapes: [IconShape, Record<string, string>][],
  className: string,
): SVGSVGElement {
  const namespace = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(namespace, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "2");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("class", className);
  for (const [tag, attributes] of shapes) {
    const shape = document.createElementNS(namespace, tag);
    for (const [name, value] of Object.entries(attributes)) shape.setAttribute(name, value);
    svg.append(shape);
  }
  return svg;
}
