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
import java.io.UnsupportedEncodingException;
import java.net.Socket;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

/**
 * A wrapper around SSLServerSocket that intercepts the accept call to add a HandshakeCompletedListener to the resulting
 * SSLSocket so that we can build a session id to SSLSession map.
 *
 * @author <a href="mailto:mmoyses@redhat.com">Marcus Moyses</a>
 * @author Scott.Stark@jboss.org
 */
class SecurityDomainServerSocket extends SSLServerSocket implements HandshakeCompletedListener {

    private SSLServerSocket delegate;

    SecurityDomainServerSocket(SSLServerSocket delegate) throws IOException {
        this.delegate = delegate;
    }

    /** {@inheritDoc} */
    @Override
    public void handshakeCompleted(HandshakeCompletedEvent event) {
        SSLSession session = event.getSession();
        String sessionID = null;
        byte[] id = session.getId();
        try {
            sessionID = new String(id, "UTF-8");
        } catch (UnsupportedEncodingException uee) {
            sessionID = new String(id);
        }
        SecurityDomainServerSocketFactory.putSSLSession(sessionID, session);
    }

    /** {@inheritDoc} */
    @Override
    public Socket accept() throws IOException {
        SSLSocket socket = (SSLSocket) delegate.accept();
        socket.addHandshakeCompletedListener(this);
        return socket;
    }

    /** {@inheritDoc} */
    @Override
    public boolean getEnableSessionCreation() {
        return delegate.getEnableSessionCreation();
    }

    /** {@inheritDoc} */
    @Override
    public String[] getEnabledCipherSuites() {
        return delegate.getEnabledCipherSuites();
    }

    /** {@inheritDoc} */
    @Override
    public String[] getEnabledProtocols() {
        return delegate.getEnabledProtocols();
    }

    /** {@inheritDoc} */
    @Override
    public boolean getNeedClientAuth() {
        return delegate.getNeedClientAuth();
    }

    /** {@inheritDoc} */
    @Override
    public String[] getSupportedCipherSuites() {
        return delegate.getSupportedCipherSuites();
    }

    /** {@inheritDoc} */
    @Override
    public String[] getSupportedProtocols() {
        return delegate.getSupportedProtocols();
    }

    /** {@inheritDoc} */
    @Override
    public boolean getUseClientMode() {
        return delegate.getUseClientMode();
    }

    /** {@inheritDoc} */
    @Override
    public boolean getWantClientAuth() {
        return delegate.getWantClientAuth();
    }

    /** {@inheritDoc} */
    @Override
    public void setEnableSessionCreation(boolean flag) {
        delegate.setEnableSessionCreation(flag);
    }

    /** {@inheritDoc} */
    @Override
    public void setEnabledCipherSuites(String[] suites) {
        delegate.setEnabledCipherSuites(suites);
    }

    /** {@inheritDoc} */
    @Override
    public void setEnabledProtocols(String[] protocols) {
        delegate.setEnabledProtocols(protocols);
    }

    /** {@inheritDoc} */
    @Override
    public void setNeedClientAuth(boolean need) {
        delegate.setNeedClientAuth(need);
    }

    /** {@inheritDoc} */
    @Override
    public void setUseClientMode(boolean mode) {
        delegate.setUseClientMode(mode);
    }

    /** {@inheritDoc} */
    @Override
    public void setWantClientAuth(boolean want) {
        delegate.setWantClientAuth(want);
    }

}
