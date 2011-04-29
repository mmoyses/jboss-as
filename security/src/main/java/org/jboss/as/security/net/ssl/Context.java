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

package org.jboss.as.security.net.ssl;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import org.jboss.logging.Logger;
import org.jboss.security.JSSESecurityDomain;

/**
 * Utility class with a static method that returns an initialized JSSE SSLContext for a given JSSESecurityDomain.
 *
 * @author <a href="mailto:mmoyses@redhat.com">Marcus Moyses</a>
 * @author Scott.Stark@jboss.org
 * @author <a href="mailto:reverbel@ime.usp.br">Francisco Reverbel</a>
 */
class Context {

    private static Logger log = Logger.getLogger(Context.class);

    static SSLContext forDomain(JSSESecurityDomain securityDomain) throws IOException {
        SSLContext sslCtx = null;
        try {
            sslCtx = SSLContext.getInstance("TLS");
            KeyManager[] keyMgrs = securityDomain.getKeyManagers();
            if (keyMgrs == null)
                throw new IOException("KeyManager[] is null for security domain: " + securityDomain.getSecurityDomain());
            TrustManager[] trustMgrs = securityDomain.getTrustManagers();
            sslCtx.init(keyMgrs, trustMgrs, null);
            return sslCtx;
        } catch (NoSuchAlgorithmException e) {
            log.error("Failed to get SSLContext for TLS algorithm", e);
            throw new IOException("Failed to get SSLContext for TLS algorithm");
        } catch (KeyManagementException e) {
            log.error("Failed to init SSLContext", e);
            throw new IOException("Failed to init SSLContext");
        } catch (SecurityException e) {
            log.error("Failed to init SSLContext", e);
            throw new IOException("Failed to init SSLContext");
        }
    }
}