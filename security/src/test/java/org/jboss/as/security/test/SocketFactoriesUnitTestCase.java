/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2011, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.jboss.as.security.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;

import org.jboss.as.security.net.ssl.SecurityDomainServerSocketFactory;
import org.jboss.as.security.net.ssl.SecurityDomainSocketFactory;
import org.jboss.logging.Logger;
import org.jboss.security.JBossJSSESecurityDomain;
import org.junit.Test;

/**
 * Test for {@code SecurityDomainSocketFactory} and {@code SecurityDomainServerSocketFactory}.
 *
 * @author <a href="mailto:mmoyses@redhat.com">Marcus Moyses</a>
 */
public class SocketFactoriesUnitTestCase {

    private static final Logger log = Logger.getLogger(SocketFactoriesUnitTestCase.class);

    @Test
    public void test() throws Exception {
        JBossJSSESecurityDomain clientSecurityDomain = new JBossJSSESecurityDomain("client");
        clientSecurityDomain.setKeyStorePassword("changeit");
        clientSecurityDomain.setKeyStoreURL(getClass().getClassLoader().getResource("keystore/client.keystore").toString());
        clientSecurityDomain.setClientAlias("test");
        clientSecurityDomain.reloadKeyAndTrustStore();
        SecurityDomainSocketFactory clientSF = new SecurityDomainSocketFactory(clientSecurityDomain);

        JBossJSSESecurityDomain serverSecurityDomain = new JBossJSSESecurityDomain("server");
        serverSecurityDomain.setKeyStorePassword("changeit");
        serverSecurityDomain.setKeyStoreURL(getClass().getClassLoader().getResource("keystore/server.keystore").toString());
        serverSecurityDomain.setServerAlias("test");
        serverSecurityDomain.setClientAuth(true);
        serverSecurityDomain.reloadKeyAndTrustStore();
        SecurityDomainServerSocketFactory serverSF = new SecurityDomainServerSocketFactory(serverSecurityDomain);

        final ServerSocket ss = serverSF.createServerSocket(9000);
        final Socket cs = clientSF.createSocket(InetAddress.getLocalHost(), 9000);
        Thread clientThread = new Thread() {
            public void run() {
                try {
                    OutputStream os = cs.getOutputStream();
                    os.write("HelloWorld".getBytes());
                    os.close();
                } catch (IOException ioe) {
                    log.error(ioe.getMessage(), ioe);
                } finally {
                    try {
                        cs.close();
                    } catch (IOException ioe) {
                        log.error("Error closing client socket", ioe);
                    }
                }
            }
        };
        clientThread.start();
        Socket s = ss.accept();
        try {
            InputStream is = s.getInputStream();
            byte[] data = new byte[10];
            is.read(data);
            is.close();
            String helloWorld = new String(data);
            assertEquals("Communication failed", "HelloWorld", helloWorld);
        } catch (Exception e) {
            fail(e.getMessage());
        } finally {
            s.close();
        }
    }

}
