// @ts-check
const { LanguageClient } = require("vscode-languageclient/node");
const tmpdir = require("os").tmpdir();

module.exports = {
  /** @param {import("vscode").ExtensionContext} context*/
  activate(context) {
    /** @type {import("vscode-languageclient/node").ServerOptions} */
    const serverOptions = {
      run: {
        command: "iq-lsp",
      },
      debug: {
        command: "iq-lsp",
        // args: ["--file", `${tmpdir}/lsp.log`, "--level", "TRACE"],
      },
    };

    /** @type {import("vscode-languageclient/node").LanguageClientOptions} */
    const clientOptions = {
      documentSelector: [{ scheme: "file", pattern: "**/pom.xml" }],
    };

    const client = new LanguageClient(
      "iq-lsp",
      "IQ Language Server",
      serverOptions,
      clientOptions
    );

    client.start();
  },
};
