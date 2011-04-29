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
import java.io.Serializable;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.WeakHashMap;

import javax.naming.InitialContext;
import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;

import org.jboss.logging.Logger;
import org.jboss.security.JSSESecurityDomain;
import org.jboss.security.SecurityConstants;

/**
 * A {@code SSLSocketFactory} implementation that uses a {@code JSSESecurityDomain} to confiure SSL.
 *
 * @author <a href="mailto:mmoyses@redhat.com">Marcus Moyses</a>
 * @author Scott.Stark@jboss.org
 */
public class SecurityDomainServerSocketFactory extends SSLServerSocketFactory implements Serializable {

    private static final long serialVersionUID = -4484953981968236871L;

    protected static final Logger log = Logger.getLogger(SecurityDomainServerSocketFactory.class);

    private transient SSLContext sslCtx;

    private transient JSSESecurityDomain securityDomain;

    private static WeakHashMap<String, SSLSession> sessionMap = new WeakHashMap<String, SSLSession>();

    public SecurityDomainServerSocketFactory() {
        if (log.isTraceEnabled())
            log.trace("Creating socket factory: " + this.getClass().getName());
        this.securityDomain = getJSSESecurityDomain();
    }

    public SecurityDomainServerSocketFactory(JSSESecurityDomain securityDomain) throws IOException {
        if (log.isTraceEnabled())
            log.trace("Creating socket factory: " + this.getClass().getName());
        this.securityDomain = securityDomain;
    }

    /**
     * Static method required.
     *
     * @return an instance of {@code SecurityDomainServerSocketFactory} or <code>null</code> if the security domain is null.
     */
    public static ServerSocketFactory getDefault() {
        SecurityDomainServerSocketFactory sf = new SecurityDomainServerSocketFactory();
        return sf;
    }

    /**
     * Returns the JSSESecurityDomain
     *
     * @return the security domain
     */
    public JSSESecurityDomain getSecurityDomain() {
        return securityDomain;
    }

    /**
     * Sets the JSSESecurityDomain
     *
     * @param securityDomain the security domain to set
     */
    public void setSecurityDomain(JSSESecurityDomain securityDomain) {
        this.securityDomain = securityDomain;
    }

    /** {@inheritDoc} */
    @Override
    public String[] getDefaultCipherSuites() {
        String[] cipherSuites = {};
        try {
            initSSLContext();
            SSLServerSocketFactory factory = sslCtx.getServerSocketFactory();
            cipherSuites = factory.getDefaultCipherSuites();
        } catch (IOException e) {
            log.error("Failed to get default SSLServerSocketFactory", e);
        }
        return cipherSuites;
    }

    /** {@inheritDoc} */
    @Override
    public String[] getSupportedCipherSuites() {
        String[] cipherSuites = {};
        try {
            initSSLContext();
            SSLServerSocketFactory factory = sslCtx.getServerSocketFactory();
            cipherSuites = factory.getSupportedCipherSuites();
        } catch (IOException e) {
            log.error("Failed to get default SSLServerSocketFactory", e);
        }
        return cipherSuites;
    }

    /** {@inheritDoc} */
    @Override
    public ServerSocket createServerSocket() throws IOException {
        initSSLContext();
        SSLServerSocketFactory factory = sslCtx.getServerSocketFactory();
        SSLServerSocket socket = (SSLServerSocket) factory.createServerSocket();
        socket.setNeedClientAuth(securityDomain.isClientAuth());
        if (securityDomain.getProtocols() != null)
            socket.setEnabledProtocols(securityDomain.getProtocols());
        if (securityDomain.getCipherSuites() != null)
            socket.setEnabledCipherSuites(securityDomain.getCipherSuites());

        SecurityDomainServerSocket serverSocket = new SecurityDomainServerSocket(socket);
        return serverSocket;
    }

    /** {@inheritDoc} */
    @Override
    public ServerSocket createServerSocket(int port) throws IOException {
        return createServerSocket(port, 50, null);
    }

    /** {@inheritDoc} */
    @Override
    public ServerSocket createServerSocket(int port, int backlog) throws IOException {
        return createServerSocket(port, backlog, null);
    }

    /** {@inheritDoc} */
    @Override
    public ServerSocket createServerSocket(int port, int backlog, InetAddress ifAddress) throws IOException {
        initSSLContext();
        SSLServerSocketFactory factory = sslCtx.getServerSocketFactory();
        SSLServerSocket socket = (SSLServerSocket) factory.createServerSocket(port, backlog, ifAddress);
        socket.setNeedClientAuth(securityDomain.isClientAuth());
        if (securityDomain.getProtocols() != null)
            socket.setEnabledProtocols(securityDomain.getProtocols());
        if (securityDomain.getCipherSuites() != null)
            socket.setEnabledCipherSuites(securityDomain.getCipherSuites());

        SecurityDomainServerSocket serverSocket = new SecurityDomainServerSocket(socket);
        return serverSocket;
    }

    static synchronized SSLSession putSSLSession(String sessionID, SSLSession session) {
        SSLSession prevSession = (SSLSession) sessionMap.put(sessionID, session);
        return prevSession;
    }

    private void initSSLContext() throws IOException {
        if (sslCtx != null)
            return;
        sslCtx = Context.forDomain(securityDomain);
    }

    /**
     * Constructs a {@code JSSESecurityDomain} based on the system property defined in getSystemPropertyName().
     *
     * @return an instance of {@code JSSESecurityDomain} or <code>null</code> if an error occurred.
     */
    protected JSSESecurityDomain getJSSESecurityDomain() {
        final String name = getSystemPropertyName();
        String secDomain = AccessController.doPrivileged(new PrivilegedAction<String>() {
            public String run() {
                return System.getProperty(name);
            }
        });
        if (secDomain != null) {
            try {
                InitialContext iniCtx = new InitialContext();
                JSSESecurityDomain sd = (JSSESecurityDomain) iniCtx.lookup(SecurityConstants.JAAS_CONTEXT_ROOT + secDomain
                        + "/jsse");
                if (log.isDebugEnabled())
                    log.debug("Created Security Domain object from " + secDomain + ":" + sd.toString());
                return sd;
            } catch (Exception e) {
                log.error("Failed to create Security Domain '" + secDomain + "'", e);
            }
        }
        return null;
    }

    /**
     * Name of the system property with the security domain name. By default "org.jboss.security.ssl.server.domain.name".
     * Override this method if you want different {@code ServerSocketFactory}s each using a different security domain. Need to
     * overwrite the static method getDefault() as well.
     *
     * @return a <code>String</code> if the property name
     */
    protected String getSystemPropertyName() {
        return "org.jboss.security.ssl.server.domain.name";
    }

    public void create() throws Exception {
        // NOOP
    }

}
