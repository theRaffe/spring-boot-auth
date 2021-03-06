	package no.bluebit.demo;

	import org.springframework.beans.factory.annotation.Autowired;
	import org.springframework.context.annotation.Configuration;
	import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
	import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
	import org.springframework.security.config.annotation.web.builders.HttpSecurity;
	import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
	import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
	import no.bluebit.demo.auth.provider.CustomAuthenticationProvider;

	@Configuration
	@EnableWebSecurity
	@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
	public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

		@Autowired
		private CustomAuthenticationProvider customAuthenticationProvider;

		@Autowired
		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth
				.authenticationProvider(this.customAuthenticationProvider);
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
					.antMatchers(                        
                        "/",
                        "/*.html",
                        "/favicon.ico",
                        "/**/*.html",
                        "/**/*.css",
                        "/**/*.js"
                	).permitAll()
					.antMatchers("/auth").permitAll()
					.antMatchers("/api/users/login").permitAll()    // Permit access for all to login REST service
					.antMatchers("/").permitAll()				    // Neccessary to permit access to default document
				.anyRequest().authenticated().and()				    // All other requests require authentication
				.httpBasic().and()
				.logout().and()
				.csrf().disable();
		}
	}