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
import java.net.Socket;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Properties;

import javax.naming.InitialContext;
import javax.net.SocketFactory;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.jboss.logging.Logger;
import org.jboss.security.JSSESecurityDomain;
import org.jboss.security.SecurityConstants;

/**
 * {@code SSLSocketFactory} that uses a JSSESecurityDomain to configure SSL.
 *
 * @author <a href="mailto:mmoyses@redhat.com">Marcus Moyses</a>
 * @author Scott.Stark@jboss.org
 * @author <a href="mailto:reverbel@ime.usp.br">Francisco Reverbel</a>
 */
public class SecurityDomainSocketFactory extends SSLSocketFactory implements HandshakeCompletedListener, Serializable {

    private static final long serialVersionUID = 1590842128863416623L;

    public static final String HANDSHAKE_COMPLETE_LISTENER = "org.jboss.security.ssl.HandshakeCompletedListener";

    protected static final Logger log = Logger.getLogger(SecurityDomainSocketFactory.class);

    private transient SSLContext sslCtx;

    private transient JSSESecurityDomain securityDomain;

    public SecurityDomainSocketFactory() {
        if (log.isTraceEnabled())
            log.trace("Creating socket factory: " + this.getClass().getName());
        this.securityDomain = getJSSESecurityDomain();
    }

    public SecurityDomainSocketFactory(JSSESecurityDomain securityDomain) {
        if (log.isTraceEnabled())
            log.trace("Creating socket factory: " + this.getClass().getName());
        this.securityDomain = securityDomain;
    }

    /**
     * Static method required.
     *
     * @return an instance of {@code SecurityDomainSocketFactory} or <code>null</code> if the security domain is null.
     */
    public static SocketFactory getDefault() {
        SecurityDomainSocketFactory sf = new SecurityDomainSocketFactory();
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
            SSLSocketFactory factory = sslCtx.getSocketFactory();
            cipherSuites = factory.getDefaultCipherSuites();
        } catch (IOException ioe) {
            log.error("Failed to get default SSLSocketFactory", ioe);
        }
        return cipherSuites;
    }

    /** {@inheritDoc} */
    @Override
    public String[] getSupportedCipherSuites() {
        String[] cipherSuites = {};
        try {
            initSSLContext();
            SSLSocketFactory factory = sslCtx.getSocketFactory();
            cipherSuites = factory.getSupportedCipherSuites();
        } catch (IOException ioe) {
            log.error("Failed to get default SSLSocketFactory", ioe);
        }
        return cipherSuites;
    }

    /** {@inheritDoc} */
    @Override
    public Socket createSocket() throws IOException {
        initSSLContext();
        SSLSocketFactory factory = sslCtx.getSocketFactory();
        SSLSocket socket = (SSLSocket) factory.createSocket();
        if (securityDomain.getProtocols() != null)
            socket.setEnabledProtocols(securityDomain.getProtocols());
        if (securityDomain.getCipherSuites() != null)
            socket.setEnabledCipherSuites(securityDomain.getCipherSuites());
        socket.addHandshakeCompletedListener(this);
        socket.setNeedClientAuth(securityDomain.isClientAuth());
        return socket;
    }

    /** {@inheritDoc} */
    @Override
    public Socket createSocket(String host, int port) throws IOException {
        InetAddress address = InetAddress.getByName(host);
        return this.createSocket(address, port);
    }

    /** {@inheritDoc} */
    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        return this.createSocket(host, port, null, 0);
    }

    /** {@inheritDoc} */
    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
        InetAddress address = InetAddress.getByName(host);
        return this.createSocket(address, port, localHost, localPort);
    }

    /** {@inheritDoc} */
    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        initSSLContext();
        SSLSocketFactory factory = sslCtx.getSocketFactory();
        SSLSocket socket = (SSLSocket) factory.createSocket(address, port, localAddress, localPort);
        if (securityDomain.getProtocols() != null)
            socket.setEnabledProtocols(securityDomain.getProtocols());
        if (securityDomain.getCipherSuites() != null)
            socket.setEnabledCipherSuites(securityDomain.getCipherSuites());
        socket.addHandshakeCompletedListener(this);
        socket.setNeedClientAuth(securityDomain.isClientAuth());
        return socket;
    }

    /** {@inheritDoc} */
    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        initSSLContext();
        SSLSocketFactory factory = sslCtx.getSocketFactory();
        SSLSocket socket = (SSLSocket) factory.createSocket(s, host, port, autoClose);
        if (securityDomain.getProtocols() != null)
            socket.setEnabledProtocols(securityDomain.getProtocols());
        if (securityDomain.getCipherSuites() != null)
            socket.setEnabledCipherSuites(securityDomain.getCipherSuites());
        socket.addHandshakeCompletedListener(this);
        socket.setNeedClientAuth(securityDomain.isClientAuth());
        return socket;
    }

    private void initSSLContext() throws IOException {
        if (sslCtx != null)
            return;
        sslCtx = Context.forDomain(securityDomain);
    }

    /** {@inheritDoc} */
    @Override
    public void handshakeCompleted(HandshakeCompletedEvent event) {
        if (log.isTraceEnabled()) {
            String cipher = event.getCipherSuite();
            SSLSession session = event.getSession();
            String peerHost = session.getPeerHost();
            log.debug("SSL handshakeCompleted, cipher=" + cipher + ", peerHost=" + peerHost);
        }

        /*
         * See if there is a HANDSHAKE_COMPLETE_LISTENER. This is not done from within a privileged action as access to the SSL
         * session through the callback is not considered an implementation detail.
         */
        try {
            Properties env = System.getProperties();
            HandshakeCompletedListener listener = (HandshakeCompletedListener) env.get(HANDSHAKE_COMPLETE_LISTENER);
            if (listener != null)
                listener.handshakeCompleted(event);
        } catch (Throwable e) {
            log.debug("Failed to foward handshakeCompleted", e);
        }
    }

    /**
     * Constructs a {@code JSSESecurityDomain} based on the system property defined in getSystemPropertyName().
     *
     * @return an instance of {@code SecurityDomain} or <code>null</code> if an error occurred.
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
     * Name of the system property with the security domain name. By default "org.jboss.security.ssl.domain.name". Override this
     * method if you want different {@code SocketFactory}s each using a different security domain. Need to overwrite the static
     * method getDefault() as well.
     *
     * @return a <code>String</code> if the property name
     */
    protected String getSystemPropertyName() {
        return "org.jboss.security.ssl.domain.name";
    }

}
