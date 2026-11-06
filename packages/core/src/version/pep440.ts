const PEP440 = new RegExp(
  "^\\s*v?" +
    "(?:(?<epoch>[0-9]+)!)?" +
    "(?<release>[0-9]+(?:\\.[0-9]+)*)" +
    "(?<pre>[-_.]?(?<preLabel>alpha|a|beta|b|preview|pre|c|rc)[-_.]?(?<preNum>[0-9]+)?)?" +
    "(?<post>(?:-(?<postNum1>[0-9]+))|(?:[-_.]?(?<postLabel>post|rev|r)[-_.]?(?<postNum2>[0-9]+)?))?" +
    "(?<dev>[-_.]?(?<devLabel>dev)[-_.]?(?<devNum>[0-9]+)?)?" +
    "(?:\\+(?<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?" +
    "\\s*$",
  "i",
);

type PreLabel = "a" | "b" | "rc";

export interface Pep440Version {
  epoch: number;
  release: number[];
  pre: [PreLabel, number] | null;
  post: number | null;
  dev: number | null;
  local: Array<number | string> | null;
}

function preLabel(raw: string): PreLabel {
  const label = raw.toLowerCase();
  if (label === "alpha" || label === "a") return "a";
  if (label === "beta" || label === "b") return "b";
  return "rc";
}

/** Returns null for anything that is not a valid PEP 440 version. */
export function parsePep440(input: string): Pep440Version | null {
  const match = PEP440.exec(input);
  const g = match?.groups;
  if (!g) return null;

  const release = (g["release"] ?? "").split(".").map(Number);
  const epoch = g["epoch"] ? Number(g["epoch"]) : 0;
  if (![epoch, ...release].every(Number.isSafeInteger)) return null;

  const num = (value: string | undefined): number => (value ? Number(value) : 0);

  return {
    epoch,
    release,
    pre: g["preLabel"] ? [preLabel(g["preLabel"]), num(g["preNum"])] : null,
    post: g["postNum1"] !== undefined
      ? Number(g["postNum1"])
      : g["postLabel"]
        ? num(g["postNum2"])
        : null,
    dev: g["devLabel"] ? num(g["devNum"]) : null,
    local: g["local"]
      ? g["local"].toLowerCase().split(/[-_.]/).map((seg) => (/^[0-9]+$/.test(seg) ? Number(seg) : seg))
      : null,
  };
}

const cmp = (a: number, b: number): -1 | 0 | 1 => (a < b ? -1 : a > b ? 1 : 0);

function stripTrailingZeros(release: number[]): number[] {
  let end = release.length;
  while (end > 1 && release[end - 1] === 0) end--;
  return release.slice(0, end);
}

function compareRelease(a: number[], b: number[]): -1 | 0 | 1 {
  const x = stripTrailingZeros(a);
  const y = stripTrailingZeros(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const r = cmp(x[i] ?? 0, y[i] ?? 0);
    if (r !== 0) return r;
  }
  return 0;
}

const PRE_ORDER: Record<PreLabel, number> = { a: 0, b: 1, rc: 2 };

/** Rank of the pre-release slot: dev-only sorts before any pre-release, no pre-release sorts after all. */
function comparePre(a: Pep440Version, b: Pep440Version): -1 | 0 | 1 {
  const rank = (v: Pep440Version): number =>
    v.pre === null ? (v.post === null && v.dev !== null ? -1 : 1) : 0;
  const ra = rank(a);
  const rb = rank(b);
  if (ra !== rb) return cmp(ra, rb);
  if (a.pre && b.pre) {
    const r = cmp(PRE_ORDER[a.pre[0]], PRE_ORDER[b.pre[0]]);
    return r !== 0 ? r : cmp(a.pre[1], b.pre[1]);
  }
  return 0;
}

function compareOptional(a: number | null, b: number | null, nullIsLow: boolean): -1 | 0 | 1 {
  if (a === b) return 0;
  if (a === null) return nullIsLow ? -1 : 1;
  if (b === null) return nullIsLow ? 1 : -1;
  return cmp(a, b);
}

function compareLocal(a: Pep440Version["local"], b: Pep440Version["local"]): -1 | 0 | 1 {
  if (a === null && b === null) return 0;
  if (a === null) return -1;
  if (b === null) return 1;
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i];
    const y = b[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    if (typeof x === typeof y) {
      const r = typeof x === "number" ? cmp(x, y as number) : x < (y as string) ? -1 : x > (y as string) ? 1 : 0;
      if (r !== 0) return r;
    } else {
      return typeof x === "number" ? 1 : -1;
    }
  }
  return 0;
}

export function comparePep440Parsed(a: Pep440Version, b: Pep440Version): -1 | 0 | 1 {
  return (
    cmp(a.epoch, b.epoch) ||
    compareRelease(a.release, b.release) ||
    comparePre(a, b) ||
    compareOptional(a.post, b.post, true) ||
    compareOptional(a.dev, b.dev, false) ||
    compareLocal(a.local, b.local)
  );
}

/** -1 | 0 | 1, or null when either side is not a valid PEP 440 version. */
export function comparePep440(a: string, b: string): -1 | 0 | 1 | null {
  const x = parsePep440(a);
  const y = parsePep440(b);
  return x && y ? comparePep440Parsed(x, y) : null;
}
