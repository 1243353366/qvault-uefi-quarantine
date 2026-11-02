// A second runtime at the edge: validate a payload against the contract, knowing nothing
// about the decision. If the contract can be honoured here, a Go collector or a shell report
// generator can honour it too, without moving the verdict engine.
import { readFileSync } from "node:fs";

const schema = JSON.parse(readFileSync(new URL("../contract/verdict.schema.json", import.meta.url)));
const payload = JSON.parse(readFileSync(process.argv[2], "utf8"));

const problems = [];
for (const key of schema.required) if (!(key in payload)) problems.push(`missing ${key}`);
for (const [key, spec] of Object.entries(schema.properties)) {
  if (!(key in payload)) continue;
  const value = payload[key];
  if (spec.enum && !spec.enum.includes(value)) problems.push(`${key}=${JSON.stringify(value)} not in enum`);
  if (spec.const !== undefined && value !== spec.const) problems.push(`${key} must be ${JSON.stringify(spec.const)}`);
  if (spec.type && !spec.enum) {
    const types = Array.isArray(spec.type) ? spec.type : [spec.type];
    const actual = Array.isArray(value) ? "array" : value === null ? "null" : typeof value;
    const ok = types.some((t) => (t === "integer" ? Number.isInteger(value) : t === actual));
    if (!ok) problems.push(`${key} should be ${types.join("|")}, is ${actual}`);
  }
}
for (const key of Object.keys(payload)) if (!(key in schema.properties)) problems.push(`unexpected ${key}`);

if (problems.length) { console.error(problems.join("\n")); process.exit(1); }
console.log("contract ok");
