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

import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;
import static org.apache.maven.plugins.annotations.LifecyclePhase.GENERATE_TEST_RESOURCES;
import static org.apache.maven.plugins.annotations.ResolutionScope.TEST;

import java.io.File;
import java.util.List;

import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

@Mojo(name = "generate-server-certificate",
      defaultPhase = GENERATE_TEST_RESOURCES,
      requiresDependencyResolution = TEST,
      requiresProject = true)
public final class GenerateServerCertificateMojo extends AbstractMojo
{
    @Parameter(required = true)
    private String certServerName;

    @Parameter(required = true)
    private String certDistinguishedName;

    @Parameter(defaultValue = "365")
    private String certValidity;

    @Parameter(defaultValue = "RSA")
    private String certKeyAlgorithm;

    @Parameter
    private String certSignatureAlgorithm;

    @Parameter
    private String certStartDate;

    @Parameter
    private String certKeySize;

    @Parameter
    private String certExtension;

    @Override
    protected void executeImpl() throws MojoExecutionException, MojoFailureException
    {
        try
        {
            File certKeyStore = new File(outputDirectory, certServerName);

            if (skipIfExists && certKeyStore.exists())
            {
                getLog().warn("Certificate Authority file exists, skipping");
            }
            else
            {
                doGenerateKeyPair(certKeyStore, certPass, certKeyPass, certServerName, certKeyAlgorithm, certKeySize,
                        certSignatureAlgorithm, certDistinguishedName, certStartDate, singletonList(certExtension), certValidity);

                File certRequest = new File(outputDirectory, String.format("%s.csr", certServerName));
                doGenerateCertificateRequest(certKeyStore, certPass, certKeyPass, certServerName, certRequest);

                File caKeyStore = new File(outputDirectory, caName);
                File certificate = new File(outputDirectory, String.format("%s.crt", certServerName));
                //  TODO:  -ext eku:c=serverAuth
                List<String> certExtensions = asList("ku:c=dig,keyenc", String.format("san=dns:%s", certServerName));
                doGenerateCertificateAsPem64(caKeyStore, caPass, caKeyPass, caName, certExtensions,
                        certValidity, certRequest, certificate);

                File caCertificate = new File(outputDirectory, String.format("%s.crt", caName));
                doImportCertificate(certKeyStore, certPass, certKeyPass, caName, caCertificate);
                doImportCertificate(certKeyStore, certPass, certKeyPass, certServerName, certificate);
                doDelete(certKeyStore, certPass, caName);
            }
        }
        catch (Exception ex)
        {
            throw new MojoFailureException("Unable to generate server certificate", ex);
        }
    }
}
