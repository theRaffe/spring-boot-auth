package no.bluebit.demo.auth.provider;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import javax.naming.ldap.InitialLdapContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Value;
import java.text.ParseException;

import java.util.ArrayList;
import java.util.List;
import java.util.Hashtable;
import java.text.MessageFormat;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private static final Logger logger = LoggerFactory.getLogger(CustomAuthenticationProvider.class);

    @Value("${ldap.domain}")
    private String DOMAIN;

    @Value("${ldap.url}")
    private String URL;

     @Value("${ldap.context.factory}")
    private String INITIAL_CONTEXT_FACTORY;

    @Value("${ldap.security.authentication}")
    private String SECURITY_AUTHENTICATION;

    public CustomAuthenticationProvider() {
        logger.info("*** CustomAuthenticationProvider created");
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        /*if(authentication.getName().equals("admin")  && authentication.getCredentials().equals("admin")) {
            List<GrantedAuthority> grantedAuths = new ArrayList<>();
            grantedAuths.add(new SimpleGrantedAuthority("ROLE_USER"));
            grantedAuths.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
            return new UsernamePasswordAuthenticationToken(authentication.getName(), authentication.getCredentials(), grantedAuths);
        } else {
            throw new BadCredentialsException("1000");
        }
        */
        final String username = authentication.getName();
        final String password =  authentication.getCredentials().toString();

        final Hashtable<String, String> env = new Hashtable<String, String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, INITIAL_CONTEXT_FACTORY);
        env.put(Context.SECURITY_AUTHENTICATION, SECURITY_AUTHENTICATION);
        env.put(Context.SECURITY_PRINCIPAL, username);
        env.put(Context.SECURITY_CREDENTIALS, password);
        env.put(Context.PROVIDER_URL, URL);
        logger.info(MessageFormat.format("map context: {0}", env.toString()));

        try {
            DirContext ctx = new InitialDirContext(env);
            List<GrantedAuthority> grantedAuths = new ArrayList<>();
            grantedAuths.add(new SimpleGrantedAuthority("ROLE_USER"));
            grantedAuths.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
            return new UsernamePasswordAuthenticationToken(authentication.getName(), authentication.getCredentials(), grantedAuths);
        } catch (NamingException ne) {
            logger.error(MessageFormat.format("NamingException: {0}", ne));
            throw new BadCredentialsException("1000");
        } catch (Exception pe) {
            logger.error(MessageFormat.format("ParseException", pe));
            throw new BadCredentialsException("1000", pe);
        }

    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

}
