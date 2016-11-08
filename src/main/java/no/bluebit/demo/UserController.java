package no.bluebit.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mobile.device.Device;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import no.bluebit.demo.security.JwtTokenUtil;

import java.text.MessageFormat;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private static final Logger logger = LoggerFactory.getLogger(UserController.class);

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private UserDetailsService userDetailsService;

    @RequestMapping(method=RequestMethod.POST, value = "login")
    public ResponseEntity<?> login(@RequestBody Credentials credentials, Device device) {
        try {
            Authentication token = new UsernamePasswordAuthenticationToken(credentials.getUsername(), credentials.getPassword());
            Authentication auth = authenticationManager.authenticate(token);

            SecurityContextHolder.getContext().setAuthentication(auth);
            final UserDetails userDetails = userDetailsService.loadUserByUsername(credentials.getUsername());
            final String jwt = jwtTokenUtil.generateToken(userDetails, device);

            return new ResponseEntity<>(jwt, HttpStatus.OK);
        }
        catch (Exception ex) {
            logger.error(MessageFormat.format("An exception occurred at authentication: {0}", ex.getCause()));
            return new ResponseEntity<>(String.format("{\"error\": \"%s\"}", ex.getMessage()), HttpStatus.INTERNAL_SERVER_ERROR);
        }
        
    }

}
