/**
 * Copyright 2016-2017 The Reaktivity Project
 *
 * The Reaktivity Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package org.reaktivity.maven.plugin.democa.internal;

import java.io.File;
import java.io.FileWriter;
import java.util.List;

import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import org.apache.maven.shared.utils.cli.WriterStreamConsumer;
import org.apache.maven.shared.utils.cli.javatool.JavaToolResult;
import org.apache.maven.toolchain.Toolchain;
import org.apache.maven.toolchain.ToolchainManager;
import org.codehaus.mojo.keytool.KeyTool;
import org.codehaus.mojo.keytool.KeyToolRequest;
import org.codehaus.mojo.keytool.requests.KeyToolDeleteRequest;
import org.codehaus.mojo.keytool.requests.KeyToolExportCertificateRequest;
import org.codehaus.mojo.keytool.requests.KeyToolGenerateCertificateRequest;
import org.codehaus.mojo.keytool.requests.KeyToolGenerateCertificateRequestRequest;
import org.codehaus.mojo.keytool.requests.KeyToolGenerateKeyPairRequest;
import org.codehaus.mojo.keytool.requests.KeyToolImportCertificateRequest;

public abstract class AbstractMojo extends org.apache.maven.plugin.AbstractMojo
{
    @Component
    private MavenSession session;

    @Component(role = KeyTool.class)
    private KeyTool keyTool;

    @Component
    private ToolchainManager toolchainManager;

    @Parameter(defaultValue = "${project}", readonly = true)
    protected MavenProject project;

    @Parameter(defaultValue = "${project.build.directory}/generated-test-resources/democa")
    protected File outputDirectory;

    @Parameter(defaultValue = "democa")
    protected String caName;

    @Parameter(defaultValue = "generated")
    protected String caPass;

    @Parameter(defaultValue = "generated")
    protected String caKeyPass;

    @Parameter(defaultValue = "generated")
    protected String certPass;

    @Parameter(defaultValue = "generated")
    protected String certKeyPass;

    @Parameter(defaultValue = "false")
    protected boolean skipIfExists;

    @Override
    public final void execute() throws MojoExecutionException, MojoFailureException
    {
        if (toolchainManager != null)
        {
            Toolchain toolchain = toolchainManager.getToolchainFromBuildContext("jdk", session);

            if (toolchain != null)
            {
                keyTool.setToolchain(toolchain);
            }
        }

        outputDirectory.mkdirs();

        executeImpl();
    }

    protected abstract void executeImpl() throws MojoExecutionException, MojoFailureException;

    protected final void doGenerateKeyPair(
        File keyStore,
        String storePassword,
        String keyPassword,
        String aliasName,
        String keyAlgorithm,
        String keySize,
        String signatureAlgorithm,
        String distinguishedName,
        String startDate,
        List<String> extension,
        String validity) throws Exception
    {
        KeyToolGenerateKeyPairRequest request = new KeyToolGenerateKeyPairRequest();
        request.setKeystore(keyStore.getPath());
        request.setStorepass(storePassword);
        request.setKeypass(keyPassword);
        request.setAlias(aliasName);
        request.setKeyalg(keyAlgorithm);
        request.setKeysize(keySize);
        request.setKeypass(keyPassword);
        request.setSigalg(signatureAlgorithm);
        request.setDname(distinguishedName);
        request.setStartdate(startDate);
        request.setExts(extension);
        request.setValidity(validity);

        executeRequest(request, "Unable to generate keypair");
    }

    protected void doExportCertificateAsPem64(
        File keyStore,
        String storePassword,
        String aliasName,
        File certificate) throws Exception
    {
        KeyToolExportCertificateRequest request = new KeyToolExportCertificateRequest();
        request.setKeystore(keyStore.getPath());
        request.setStorepass(storePassword);
        request.setAlias(aliasName);
        request.setRfc(true);
        request.setSystemOutStreamConsumer(new WriterStreamConsumer(new FileWriter(certificate)));

        executeRequest(request, "Unable to export certificate");
    }

    protected void doImportCertificate(
        File keyStore,
        String storePassword,
        String keyPassword,
        String aliasName,
        File certificate) throws Exception
    {
        KeyToolImportCertificateRequest request = new KeyToolImportCertificateRequest();
        request.setKeystore(keyStore.getPath());
        request.setStorepass(storePassword);
        request.setKeypass(keyPassword);
        request.setAlias(aliasName);
        request.setNoprompt(true);
        request.setFile(certificate.getPath());

        executeRequest(request, "Unable to import certificate");
    }

    protected void doGenerateCertificateRequest(
        File keyStore,
        String storePassword,
        String keyPassword,
        String aliasName,
        File certificateRequest) throws Exception
    {
        KeyToolGenerateCertificateRequestRequest request = new KeyToolGenerateCertificateRequestRequest();
        request.setKeystore(keyStore.getPath());
        request.setStorepass(storePassword);
        request.setKeypass(keyPassword);
        request.setAlias(aliasName);
        request.setSystemOutStreamConsumer(new WriterStreamConsumer(new FileWriter(certificateRequest)));

        executeRequest(request, "Unable to generate certificate request");
    }

    protected void doGenerateCertificateAsPem64(
        File keyStore,
        String storePassword,
        String keyPassword,
        String aliasName,
        List<String> extensions,
        String validity,
        File certificateRequest,
        File certificate) throws Exception
    {
        KeyToolGenerateCertificateRequest request = new KeyToolGenerateCertificateRequest();
        request.setKeystore(keyStore.getPath());
        request.setStorepass(storePassword);
        request.setKeypass(keyPassword);
        request.setAlias(aliasName);
        request.setExts(extensions);
        request.setValidity(validity);
        request.setRfc(true);
        request.setInfile(certificateRequest);
        request.setOutfile(certificate);

        executeRequest(request, "Unable to generate certificate");
    }

    protected void doDelete(
        File keyStore,
        String storePassword,
        String aliasName) throws Exception
    {
        KeyToolDeleteRequest request = new KeyToolDeleteRequest();
        request.setKeystore(keyStore.getPath());
        request.setStorepass(storePassword);
        request.setAlias(aliasName);

        executeRequest(request, "Unable to delete alias");
    }

    private void executeRequest(
        KeyToolRequest request,
        String failMessage) throws Exception
    {
        JavaToolResult result = keyTool.execute(request);
        if (result.getExitCode() != 0)
        {
            throw new MojoFailureException(failMessage + " " + result.getCommandline());
        }
    }
}
