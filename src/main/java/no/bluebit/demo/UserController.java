package no.bluebit.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    AuthenticationManager authenticationManager;

    @RequestMapping(method=RequestMethod.POST, value = "login")
    public ResponseEntity<?> login(@RequestBody Credentials credentials) {
        try {
            Authentication token = new UsernamePasswordAuthenticationToken(credentials.getUsername(), credentials.getPassword());
            Authentication auth = authenticationManager.authenticate(token);

            SecurityContextHolder.getContext().setAuthentication(auth);

            return new ResponseEntity<>(token, HttpStatus.OK);
        }
        catch (Exception ex) {
            return new ResponseEntity<>(String.format("{\"error\": \"%s\"}", ex.getMessage()), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

}
