import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createCorpServer } from "./servers.js";

await createCorpServer().connect(new StdioServerTransport());
