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

package org.jboss.as.security.service;

import java.lang.reflect.Constructor;

import org.jboss.as.security.SecurityExtension;
import org.jboss.as.security.net.ssl.SecurityDomainServerSocketFactory;
import org.jboss.as.security.plugins.SecurityDomainContext;
import org.jboss.logging.Logger;
import org.jboss.msc.inject.Injector;
import org.jboss.msc.service.Service;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.StartContext;
import org.jboss.msc.service.StartException;
import org.jboss.msc.service.StopContext;
import org.jboss.msc.value.InjectedValue;
import org.jboss.security.JSSESecurityDomain;

/**
 * Service to instantiate a {@code SecurityDomainServerSocketFactory} given a {@code JSSESecurityDomain}.
 *
 * @author <a href="mailto:mmoyses@redhat.com">Marcus Moyses</a>
 */
public class SecurityDomainServerSocketFactoryService implements Service<SecurityDomainServerSocketFactory> {

    // append the security domain name when creating the service
    public static final ServiceName SERVICE_NAME = SecurityExtension.JBOSS_SECURITY.append("server-socket-factory");

    protected static final Logger log = Logger.getLogger(SecurityDomainServerSocketFactoryService.class);

    private final InjectedValue<SecurityDomainContext> securityDomainContextValue = new InjectedValue<SecurityDomainContext>();

    private final Class<SecurityDomainServerSocketFactory> socketFactoryClass;

    private SecurityDomainServerSocketFactory socketFactory;

    public SecurityDomainServerSocketFactoryService(Class<SecurityDomainServerSocketFactory> socketFactoryClass) {
        this.socketFactoryClass = socketFactoryClass;
    }

    /** {@inheritDoc} */
    @Override
    public void start(StartContext context) throws StartException {
        SecurityDomainContext sdc = securityDomainContextValue.getValue();
        JSSESecurityDomain securityDomain = sdc.getJSSE();
        try {
            Constructor<SecurityDomainServerSocketFactory> ctr = socketFactoryClass.getConstructor(JSSESecurityDomain.class);
            socketFactory = ctr.newInstance(securityDomain);
        } catch (Exception e) {
            log.error("Could not instantiate class", e);
            throw new StartException(e);
        }
    }

    /** {@inheritDoc} */
    @Override
    public void stop(StopContext context) {
        socketFactory = null;
    }

    /** {@inheritDoc} */
    @Override
    public SecurityDomainServerSocketFactory getValue() throws IllegalStateException, IllegalArgumentException {
        return socketFactory;
    }

    /**
     * Target {@code Injector}
     *
     * @return target
     */
    public Injector<SecurityDomainContext> getSecurityDomainContextInjector() {
        return securityDomainContextValue;
    }

}
