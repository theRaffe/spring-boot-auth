package no.bluebit.demo.security.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import no.bluebit.demo.model.security.Authority;
import no.bluebit.demo.model.security.AuthorityName;
import no.bluebit.demo.model.security.User;
import no.bluebit.demo.security.JwtUserFactory;
//import com.izzi.security.repository.UserRepository;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Created by stephan on 20.03.16.
 */
@Service
public class JwtUserDetailsServiceImpl implements UserDetailsService {

    static final List<User> lsUsers;

    static {
        lsUsers = new ArrayList<User>();
        List<Authority> ls1 = new ArrayList<Authority>();
        ls1.add(new Authority((long) 1, AuthorityName.ROLE_ADMIN));
        ls1.add(new Authority((long) 2, AuthorityName.ROLE_USER));

        List<Authority> ls2 = new ArrayList<Authority>();
        ls2.add(new Authority((long) 2, AuthorityName.ROLE_USER));

        lsUsers.add(new User((long) 1, "admin", "adminpass", "admin", "admin", "admin@admin.com", true, new Date(), ls1));
        lsUsers.add(new User((long) 2, "user", "password", "admin", "admin", "enable@user.com", true, new Date(), ls2));
        lsUsers.add(new User((long) 3, "rafael.briones.ext", "nopass", "admin", "admin", "admin@admin.com", true, new Date(), ls1));
    }

    /*Autowired
    private UserRepository userRepository;
    */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //User user = userRepository.findByUsername(username);
        User user = null;
        for(User user1 : lsUsers) {
            if (user1.getUsername().equals(username)){
                user = user1;
                break;
            }
        }

        if (user == null) {
            throw new UsernameNotFoundException(String.format("No user found with username '%s'.", username));
        } else {
            return JwtUserFactory.create(user);
        }
    }

    public boolean validateCredentials(final String username, final String password) {
        for(User user1 : lsUsers) {
            if (user1.getUsername().equals(username) && user1.getPassword().equals(password)){
                return true;
            }
        }

        return false;
    }

    public List<Authority> getAuthorities(final String username){
        for(User user1 : lsUsers) {
            if (user1.getUsername().equals(username)){
                return user1.getAuthorities();
            }
        }

        return null;
    }

    public List<GrantedAuthority> getGrantedAuthorities(final String username){
        final List<Authority> authorities = getAuthorities(username);
        final List<GrantedAuthority> ls = new ArrayList<GrantedAuthority>();
        for(Authority authority: authorities){
            ls.add(new SimpleGrantedAuthority(authority.getName().name()));
        }

        return ls;
    }
}
