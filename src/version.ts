import { readFileSync } from "node:fs";

/** Read from package.json so the CLI, MCP server info and audit records never drift. */
export const VERSION: string = (JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string }).version;
