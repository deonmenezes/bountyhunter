"use strict";

/**
 * Minimal MCP (Model Context Protocol) stdio-transport server, zero deps.
 *
 * Implements just enough of the 2025-06-18 stdio transport + JSON-RPC 2.0
 * surface for `initialize`, `tools/list`, and `tools/call`, since every
 * Mantis capability server is a thin tool table on top of this file.
 */

function createServer({ name, version, tools }) {
  const toolsByName = new Map(tools.map((tool) => [tool.name, tool]));

  function send(message) {
    process.stdout.write(`${JSON.stringify(message)}\n`);
  }

  function replyResult(id, result) {
    if (id === undefined || id === null) return;
    send({ jsonrpc: "2.0", id, result });
  }

  function replyError(id, code, message) {
    if (id === undefined || id === null) return;
    send({ jsonrpc: "2.0", id, error: { code, message } });
  }

  async function handleRequest(message) {
    const { id, method, params } = message;

    if (method === "initialize") {
      replyResult(id, {
        protocolVersion: "2025-06-18",
        capabilities: { tools: {} },
        serverInfo: { name, version },
      });
      return;
    }

    if (
      method === "notifications/initialized" ||
      method === "notifications/cancelled"
    ) {
      return;
    }

    if (method === "tools/list") {
      replyResult(id, {
        tools: tools.map((tool) => ({
          name: tool.name,
          description: tool.description,
          inputSchema: tool.inputSchema,
        })),
      });
      return;
    }

    if (method === "tools/call") {
      const tool = toolsByName.get(params && params.name);
      if (!tool) {
        replyError(id, -32602, `Unknown tool: ${params && params.name}`);
        return;
      }
      try {
        const result = await tool.handler((params && params.arguments) || {});
        const text =
          typeof result === "string" ? result : JSON.stringify(result, null, 2);
        replyResult(id, { content: [{ type: "text", text }], isError: false });
      } catch (err) {
        const text = err && err.message ? err.message : String(err);
        replyResult(id, { content: [{ type: "text", text }], isError: true });
      }
      return;
    }

    replyError(id, -32601, `Method not found: ${method}`);
  }

  let buffer = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk) => {
    buffer += chunk;
    let newlineIndex = buffer.indexOf("\n");
    while (newlineIndex !== -1) {
      const line = buffer.slice(0, newlineIndex).trim();
      buffer = buffer.slice(newlineIndex + 1);
      if (line) {
        let message;
        try {
          message = JSON.parse(line);
        } catch (err) {
          send({
            jsonrpc: "2.0",
            id: null,
            error: { code: -32700, message: `Parse error: ${err.message}` },
          });
          newlineIndex = buffer.indexOf("\n");
          continue;
        }
        handleRequest(message).catch((err) => {
          replyError(message.id, -32603, `Internal error: ${err.message}`);
        });
      }
      newlineIndex = buffer.indexOf("\n");
    }
  });

  process.stdin.on("end", () => process.exit(0));
}

module.exports = { createServer };
