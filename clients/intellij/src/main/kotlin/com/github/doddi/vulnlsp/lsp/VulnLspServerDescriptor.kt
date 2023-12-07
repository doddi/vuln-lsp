package com.github.doddi.vulnlsp.lsp

import com.intellij.execution.configurations.GeneralCommandLine
import com.intellij.lang.annotation.HighlightSeverity
import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.platform.lsp.api.ProjectWideLspServerDescriptor
import com.intellij.platform.lsp.api.customization.LspCompletionSupport
import com.intellij.platform.lsp.api.customization.LspDiagnosticsSupport
import org.eclipse.lsp4j.Diagnostic

class VulnLspServerDescriptor(project: Project) : ProjectWideLspServerDescriptor(project, "VulnLsp") {
    override fun createCommandLine(): GeneralCommandLine {
        return GeneralCommandLine().apply {
            withParentEnvironmentType(GeneralCommandLine.ParentEnvironmentType.CONSOLE)
            withCharset(Charsets.UTF_8)
            withExePath("vuln-lsp")
            withParameters("dummy", "--log-level=debug")
        }
    }

    override fun isSupportedFile(file: VirtualFile) = file.extension == "xml"

    override val lspGoToDefinitionSupport = false

}
