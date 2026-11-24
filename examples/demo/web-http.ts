import { startWebHttp } from "./servers.js";

const server = await startWebHttp(Number(process.env.PORT ?? 9801));
process.stderr.write(`demo web MCP server listening on ${server.url}\n`);
const stop = () => void server.close().then(() => process.exit(0));
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
