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

import static java.util.Collections.singletonList;
import static org.apache.maven.plugins.annotations.LifecyclePhase.GENERATE_TEST_RESOURCES;
import static org.apache.maven.plugins.annotations.ResolutionScope.TEST;

import java.io.File;

import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

@Mojo(name = "generate-certificate-authority",
      defaultPhase = GENERATE_TEST_RESOURCES,
      requiresDependencyResolution = TEST,
      requiresProject = true)
public final class GenerateCertificateAuthorityMojo extends AbstractMojo
{
    @Parameter(defaultValue = "cacerts")
    protected String cacertsName;

    @Parameter(defaultValue = "generated")
    protected String cacertsPass;

    @Parameter(defaultValue = "generated")
    protected String cacertsKeyPass;

    @Parameter(required = true)
    private String caDistinguishedName;

    @Parameter
    private String caStartDate;

    @Parameter(defaultValue = "365")
    private String caValidity;

    @Parameter(defaultValue = "RSA")
    private String caKeyAlgorithm;

    @Parameter
    private String caKeySize;

    @Parameter
    private String caSignatureAlgorithm;

    private String caExtension = "bc:c";

    @Override
    protected void executeImpl() throws MojoExecutionException, MojoFailureException
    {
        try
        {
            File caKeyStore = new File(outputDirectory, caName);

            if (skipIfExists && caKeyStore.exists())
            {
                getLog().warn("Certificate file exists, skipping");
            }
            else
            {
                doGenerateKeyPair(caKeyStore, caPass, caKeyPass, caName, caKeyAlgorithm, caKeySize,
                        caSignatureAlgorithm, caDistinguishedName, caStartDate, singletonList(caExtension), caValidity);

                File caCertificate = new File(outputDirectory, String.format("%s.crt", caName));
                doExportCertificateAsPem64(caKeyStore, caPass, caName, caCertificate);

                File cacertsKeyStore = new File(outputDirectory, cacertsName);
                doImportCertificate(cacertsKeyStore, cacertsPass, cacertsKeyPass, caName, caCertificate);
            }
        }
        catch (Exception ex)
        {
            throw new MojoFailureException("Unable to generate certificate authority", ex);
        }
    }
}
